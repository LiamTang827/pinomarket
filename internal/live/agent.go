package live

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// AgentPacket exposes only public envelope metadata. Neither the encrypted body,
// its plaintext nor any key/share is passed to a model or its policy executor.
type AgentPacket struct {
	ID              string `json:"id"`
	Owner           string `json:"owner"`
	Nonce           int    `json:"nonce"`
	Round           int    `json:"round"`
	CiphertextBytes int    `json:"ciphertext_bytes"`
}

type AgentObservation struct {
	Phase       string        `json:"phase"`
	Node        string        `json:"node"`
	Round       int           `json:"round"`
	Height      int64         `json:"height"`
	CloseHeight int64         `json:"close_height"`
	Capacity    int           `json:"capacity"`
	Packet      *AgentPacket  `json:"packet,omitempty"`
	Accepted    []AgentPacket `json:"accepted"`
	LockID      string        `json:"lock_id,omitempty"`
	Service     []AgentPacket `json:"service,omitempty"`
}

type AgentDecision struct {
	Action     string   `json:"action"`
	DelayMS    int      `json:"delay_ms"`
	IncludeIDs []string `json:"include_ids,omitempty"`
	// snapshotIDs are the local promises visible when a seal choice was made.
	// Later promises are included normally, never silently omitted by stale input.
	snapshotIDs []string
}

func (d AgentDecision) validate(phase string) error {
	if d.DelayMS < 0 || d.DelayMS > 1500 || d.Action != "delay" && d.DelayMS != 0 {
		return errors.New("invalid agent delay")
	}
	if d.Action == "select" {
		if d.IncludeIDs == nil || phase != "seal" {
			return errors.New("select requires an explicit include_ids array at seal")
		}
	} else if d.IncludeIDs != nil {
		return errors.New("unexpected include_ids")
	}
	allowed := d.Action == "normal" || phase == "admission" && (d.Action == "refuse" || d.Action == "delay") || phase == "seal" && (d.Action == "omit" || d.Action == "select") || phase == "shares" && d.Action == "withhold"
	if !allowed || phase != "admission" && phase != "seal" && phase != "shares" {
		return errors.New("agent action not allowed for phase")
	}
	return nil
}

type agentResult struct {
	done     chan struct{}
	decision AgentDecision
	err      error
}

type nodeAgent struct {
	client  *http.Client
	mu      sync.Mutex
	results map[string]*agentResult
}

func newNodeAgent(socket string, configuredTimeout ...time.Duration) (*nodeAgent, error) {
	if !filepath.IsAbs(socket) {
		return nil, errors.New("agent socket must be an absolute Unix socket path")
	}
	timeout := 2 * time.Second
	if len(configuredTimeout) > 1 {
		return nil, errors.New("expected at most one agent timeout")
	}
	if len(configuredTimeout) == 1 {
		timeout = configuredTimeout[0]
	}
	if timeout <= 0 || timeout > 55*time.Second {
		return nil, errors.New("agent timeout must be positive and at most 55 seconds")
	}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	return &nodeAgent{client: &http.Client{Transport: transport, Timeout: timeout}, results: map[string]*agentResult{}}, nil
}

// result reserves exactly one request per logical decision. A slow model does
// not hold a protocol-state lock or the result map lock. Same-key retries wait
// for the same result; errors are retained rather than causing another inference.
func (a *nodeAgent) result(key string) (*agentResult, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if result, ok := a.results[key]; ok {
		return result, false
	}
	result := &agentResult{done: make(chan struct{})}
	a.results[key] = result
	return result, true
}

func (a *nodeAgent) decide(ctx context.Context, key string, o AgentObservation) (AgentDecision, error) {
	result, created := a.result(key)
	if created {
		result.decision, result.err = a.request(ctx, o)
		close(result.done)
	}
	select {
	case <-ctx.Done():
		return AgentDecision{}, ctx.Err()
	case <-result.done:
		return result.decision, result.err
	}
}

// prepare starts a live decision before publication closes. This is optional
// harness scheduling, not a change to admission, list validation, or consensus.
func (a *nodeAgent) prepare(ctx context.Context, key string, o AgentObservation) {
	result, created := a.result(key)
	if !created {
		return
	}
	go func() {
		result.decision, result.err = a.request(ctx, o)
		close(result.done)
	}()
}

func (a *nodeAgent) request(ctx context.Context, o AgentObservation) (AgentDecision, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agent/decide", bytes.NewReader(JSON(o)))
	if err != nil {
		return AgentDecision{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := a.client.Do(req)
	if err != nil {
		return AgentDecision{}, fmt.Errorf("node agent unavailable: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return AgentDecision{}, errors.New("node agent rejected decision request")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(raw) > 4096 {
		return AgentDecision{}, errors.New("node agent response too large/unreadable")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields["action"] == nil || fields["delay_ms"] == nil {
		return AgentDecision{}, errors.New("node agent must return action and delay_ms")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var d AgentDecision
	if err = decoder.Decode(&d); err != nil {
		return AgentDecision{}, errors.New("invalid node agent response")
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return AgentDecision{}, errors.New("trailing node agent response data")
	}
	if fields["include_ids"] != nil && d.Action != "select" {
		return AgentDecision{}, errors.New("unexpected phase action parameter")
	}
	if err = d.validate(o.Phase); err != nil {
		return AgentDecision{}, err
	}
	if d.Action == "select" {
		known := map[string]bool{}
		for _, p := range o.Accepted {
			known[p.ID] = true
			d.snapshotIDs = append(d.snapshotIDs, p.ID)
		}
		seen := map[string]bool{}
		for _, id := range d.IncludeIDs {
			if !known[id] || seen[id] {
				return AgentDecision{}, errors.New("include_ids must be distinct own accepted packet IDs")
			}
			seen[id] = true
		}
	}
	return d, nil
}

func publicAgentPacket(p Packet) AgentPacket {
	return AgentPacket{p.ID(), p.Header.Owner, p.Header.Nonce, p.Header.Round, len(p.Body) + len(JSON(p.Wrapped))}
}

// No HTTP/model callback runs while either protocol-state lock is held.
func (n *liveNode) agentObservation(phase string, packet *Packet, s *State) AgentObservation {
	if s == nil {
		s = n.machine.Snapshot()
	}
	o := AgentObservation{Phase: phase, Node: n.peer.ID, Height: s.Height, Accepted: []AgentPacket{}}
	if s.Round != nil {
		o.Round = s.Round.Number
		o.CloseHeight = s.Round.CloseHeight
		o.Capacity = s.Round.Capacity
	}
	if packet != nil {
		o.Round = packet.Header.Round
	}
	n.mu.Lock()
	local := n.journal.Rounds[o.Round]
	if local != nil {
		for _, g := range local.Accepted {
			o.Accepted = append(o.Accepted, publicAgentPacket(g.Packet))
		}
	}
	n.mu.Unlock()
	sort.Slice(o.Accepted, func(i, j int) bool { return o.Accepted[i].ID < o.Accepted[j].ID })
	if packet != nil {
		p := publicAgentPacket(*packet)
		o.Packet = &p
	}
	if s.Active != nil && phase == "shares" {
		o.LockID = s.Active.ID
		for _, id := range s.Active.Items {
			o.Service = append(o.Service, publicAgentPacket(s.Orders[id]))
		}
	}
	return o
}

func (n *liveNode) decideAgent(ctx context.Context, phase string, p *Packet, s *State) (AgentDecision, error) {
	if n.agent == nil {
		return AgentDecision{Action: "normal"}, nil
	}
	o := n.agentObservation(phase, p, s)
	key := fmt.Sprintf("%s:%d", phase, o.Round)
	if p != nil {
		key = phase + ":" + p.ID()
	}
	if phase == "shares" {
		key = phase + ":" + o.LockID
	}
	return n.agent.decide(ctx, key, o)
}
