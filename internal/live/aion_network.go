package live

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type aionChallenge struct {
	Context   string   `json:"context"`
	Round     int      `json:"round"`
	Origin    string   `json:"origin"`
	Verifier  string   `json:"verifier"`
	Nonce     [32]byte `json:"nonce"`
	Signature []byte   `json:"signature,omitempty"`
}

func (c aionChallenge) body() any {
	c.Signature = nil
	return timingBody("challenge", c)
}

type aionReply struct {
	Challenge string `json:"challenge"`
	Time      int64  `json:"unix_nano"`
	Signature []byte `json:"signature,omitempty"`
}

func (r aionReply) body() any {
	r.Signature = nil
	return timingBody("challenge-reply", r)
}

type aionCalibrationRequest struct {
	Context   string `json:"context"`
	Round     int    `json:"round"`
	Origin    string `json:"origin"`
	Signature []byte `json:"signature,omitempty"`
}

func (r aionCalibrationRequest) body() any {
	r.Signature = nil
	return timingBody("calibrate", r)
}

type aionVoteRequest struct {
	Packet Packet    `json:"packet"`
	Claim  TimeClaim `json:"claim"`
}

type aionMeasurement struct {
	ReplyTime int64 `json:"reply_unix_nano"`
	Received  int64 `json:"received_unix_nano"`
}

func (d aionMeasurement) delay() int64 { return d.Received - d.ReplyTime }

type aionDelayJournal struct {
	Context  string                     `json:"context"`
	Verifier string                     `json:"verifier"`
	Round    int                        `json:"round"`
	Delays   map[string]aionMeasurement `json:"delays"`
}

type aionAuthority interface {
	now() int64
	sign(any) []byte
}

// The host owns the key and clock in the software timing model.
type softwareAionAuthority struct{ key ed25519.PrivateKey }

func (a softwareAionAuthority) now() int64           { return time.Now().UnixNano() }
func (a softwareAionAuthority) sign(body any) []byte { return Sign(a.key, body) }

type aionRuntime struct {
	authority aionAuthority
	client    *http.Client
	prove     chan struct{}
	path      string

	mu      sync.Mutex
	loaded  bool
	journal aionDelayJournal
	failed  error
}

func newAionRuntime(key ed25519.PrivateKey, path string) *aionRuntime {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &aionRuntime{
		authority: softwareAionAuthority{key: bytes.Clone(key)}, path: path, prove: make(chan struct{}, 1),
		client: &http.Client{
			Transport: transport,
			Timeout:   2 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (n *liveNode) registerAionHandlers(mux *http.ServeMux) {
	if n.aion == nil {
		return
	}
	mux.HandleFunc("/aion/prove", n.telemetry.wrap("/aion/prove", n.proveTime))
	mux.HandleFunc("/aion/calibrate", n.telemetry.wrap("/aion/calibrate", n.calibrateTime))
	mux.HandleFunc("/aion/challenge", n.telemetry.wrap("/aion/challenge", n.answerTimeChallenge))
	mux.HandleFunc("/aion/vote", n.telemetry.wrap("/aion/vote", n.voteTime))
}

func (n *liveNode) aionRoundOpen(round int) bool {
	n.machine.mu.RLock()
	defer n.machine.mu.RUnlock()
	s := n.machine.state
	return n.cfg.Manifest.Policy.Aion != nil && s.Round != nil &&
		s.Round.Number == round && !s.Round.Registered && s.Height < s.Round.CloseHeight
}

func (a *aionRuntime) loadJournal(m Manifest, verifier string) error {
	if a.loaded {
		return a.failed
	}
	a.loaded = true
	if err := ReadJSON(a.path, &a.journal); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		a.failed = fmt.Errorf("read Aion delay journal: %w", err)
		return a.failed
	}
	if a.journal.Context != m.Context || a.journal.Verifier != verifier ||
		a.journal.Round < 1 || len(a.journal.Delays) > len(m.Peers) {
		a.failed = errors.New("invalid Aion delay journal identity")
		return a.failed
	}
	for origin, value := range a.journal.Delays {
		_, known := m.Peer(origin)
		if !known || value.ReplyTime <= 0 || value.Received <= 0 ||
			!m.Policy.Aion.validDelay(value.delay()) {
			a.failed = errors.New("invalid Aion delay journal measurement")
			return a.failed
		}
	}
	return nil
}

func (a *aionRuntime) measurement(m Manifest, verifier, origin string, round int) (aionMeasurement, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.loadJournal(m, verifier); err != nil {
		return aionMeasurement{}, false, err
	}
	if round < a.journal.Round {
		return aionMeasurement{}, false, errors.New("stale Aion measurement round")
	}
	if round != a.journal.Round {
		return aionMeasurement{}, false, nil
	}
	value, ok := a.journal.Delays[origin]
	return value, ok, nil
}

func (a *aionRuntime) pin(m Manifest, verifier, origin string, round int, value aionMeasurement) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.loadJournal(m, verifier); err != nil {
		return err
	}
	if round < a.journal.Round {
		return errors.New("stale Aion measurement round")
	}
	next := aionDelayJournal{Context: m.Context, Verifier: verifier, Round: round, Delays: map[string]aionMeasurement{}}
	if round == a.journal.Round {
		if _, exists := a.journal.Delays[origin]; exists {
			return nil
		}
		for id, old := range a.journal.Delays {
			next.Delays[id] = old
		}
	}
	next.Delays[origin] = value
	if err := AtomicJSON(a.path, next); err != nil {
		a.failed = fmt.Errorf("persist Aion delay: %w", err)
		return a.failed
	}
	a.journal = next
	return nil
}

func (a *aionRuntime) post(ctx context.Context, peer Peer, path string, payload, reply any) error {
	url := strings.TrimRight(peer.API, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(JSON(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s returned status %d", peer.ID, path, resp.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 16*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(reply); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("expected one Aion response")
	}
	return nil
}

func (n *liveNode) answerTimeChallenge(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	var c aionChallenge
	m := n.cfg.Manifest
	if err := readJSON(w, r, &c); err != nil {
		sendError(w, http.StatusBadRequest, err)
		return
	}
	verifier, ok := m.Peer(c.Verifier)
	if !ok || c.Context != m.Context || c.Origin != n.peer.ID || c.Nonce == ([32]byte{}) ||
		!n.aionRoundOpen(c.Round) || !Verify(verifier.IngressKey, c.body(), c.Signature) {
		sendError(w, http.StatusBadRequest, errors.New("invalid Aion challenge"))
		return
	}
	reply := aionReply{Challenge: Hash(c), Time: n.aion.authority.now()}
	reply.Signature = n.aion.authority.sign(reply.body())
	sendJSON(w, http.StatusOK, reply)
}

func (n *liveNode) calibrateTime(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	var request aionCalibrationRequest
	m := n.cfg.Manifest
	if err := readJSON(w, r, &request); err != nil {
		sendError(w, http.StatusBadRequest, err)
		return
	}
	origin, ok := m.Peer(request.Origin)
	if !ok || request.Context != m.Context || !n.aionRoundOpen(request.Round) ||
		!Verify(origin.IngressKey, request.body(), request.Signature) {
		sendError(w, http.StatusBadRequest, errors.New("invalid Aion calibration request"))
		return
	}
	_, cached, err := n.aion.measurement(m, n.peer.ID, origin.ID, request.Round)
	if err != nil {
		sendError(w, http.StatusConflict, err)
		return
	}
	if !cached {
		challenge := aionChallenge{Context: m.Context, Round: request.Round, Origin: origin.ID, Verifier: n.peer.ID}
		if _, err := rand.Read(challenge.Nonce[:]); err != nil {
			sendError(w, http.StatusInternalServerError, err)
			return
		}
		challenge.Signature = n.aion.authority.sign(challenge.body())
		var reply aionReply
		if err := n.aion.post(r.Context(), origin, "/aion/challenge", challenge, &reply); err != nil {
			sendError(w, http.StatusServiceUnavailable, err)
			return
		}
		measurement := aionMeasurement{ReplyTime: reply.Time, Received: n.aion.authority.now()}
		if reply.Challenge != Hash(challenge) || reply.Time <= 0 || measurement.Received <= 0 ||
			!Verify(origin.IngressKey, reply.body(), reply.Signature) ||
			!m.Policy.Aion.validDelay(measurement.delay()) || !n.aionRoundOpen(request.Round) {
			sendError(w, http.StatusBadRequest, errors.New("invalid Aion challenge response or delay"))
			return
		}
		if err := n.aion.pin(m, n.peer.ID, origin.ID, request.Round, measurement); err != nil {
			sendError(w, http.StatusConflict, err)
			return
		}
	}
	sendJSON(w, http.StatusOK, struct{}{})
}

func (n *liveNode) voteTime(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	var request aionVoteRequest
	m := n.cfg.Manifest
	if err := readJSON(w, r, &request); err != nil {
		sendError(w, http.StatusBadRequest, err)
		return
	}
	received := n.aion.authority.now()
	claim := request.Claim
	if request.Packet.TimeProof != nil || !n.aionRoundOpen(claim.Round) ||
		request.Packet.Validate(m) != nil || claim.validate(m, request.Packet) != nil {
		sendError(w, http.StatusBadRequest, errors.New("invalid Aion vote request"))
		return
	}
	measurement, exists, err := n.aion.measurement(m, n.peer.ID, claim.Origin, claim.Round)
	if err != nil {
		sendError(w, http.StatusConflict, err)
		return
	}
	if !exists || received < measurement.Received || claim.Time < measurement.ReplyTime ||
		!m.Policy.Aion.matches(claim.Time, received, measurement.delay()) || !n.aionRoundOpen(claim.Round) {
		sendError(w, http.StatusConflict, errors.New("Aion time differs from pinned delay or predates calibration"))
		return
	}
	vote := TimeVote{Verifier: n.peer.ID, Received: received, Delay: measurement.delay()}
	vote.Signature = n.aion.authority.sign(vote.body(claim))
	sendJSON(w, http.StatusOK, vote)
}

func (n *liveNode) proveTime(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	var packet Packet
	m := n.cfg.Manifest
	if err := readJSON(w, r, &packet); err != nil {
		sendError(w, http.StatusBadRequest, err)
		return
	}
	if packet.TimeProof != nil || !n.aionRoundOpen(packet.Header.Round) || packet.Validate(m) != nil {
		sendError(w, http.StatusBadRequest, errors.New("Aion proof needs an unproved packet in the active round"))
		return
	}
	select {
	case n.aion.prove <- struct{}{}:
		defer func() { <-n.aion.prove }()
	default:
		sendError(w, http.StatusServiceUnavailable, errors.New("Aion origin is busy"))
		return
	}

	calibration := aionCalibrationRequest{Context: m.Context, Round: packet.Header.Round, Origin: n.peer.ID}
	calibration.Signature = n.aion.authority.sign(calibration.body())
	calibrated := make(chan Peer, len(m.Peers))
	for _, peer := range m.Peers {
		go func(peer Peer) {
			var reply struct{}
			if err := n.aion.post(r.Context(), peer, "/aion/calibrate", calibration, &reply); err != nil {
				peer = Peer{}
			}
			calibrated <- peer
		}(peer)
	}
	ready := make([]Peer, 0, len(m.Peers))
	for range m.Peers {
		if peer := <-calibrated; peer.ID != "" {
			ready = append(ready, peer)
		}
	}
	if len(ready) < m.Policy.Quorum || !n.aionRoundOpen(packet.Header.Round) {
		sendError(w, http.StatusServiceUnavailable, errors.New("Aion calibration quorum unavailable"))
		return
	}

	claim := TimeClaim{Context: m.Context, Round: packet.Header.Round, Origin: n.peer.ID, PacketID: packet.ID()}
	claim.Time = n.aion.authority.now()
	claim.Signature = n.aion.authority.sign(claim.body())
	request := aionVoteRequest{Packet: packet, Claim: claim}
	votes := make(chan TimeVote, len(ready))
	for _, peer := range ready {
		go func(peer Peer) {
			var vote TimeVote
			if err := n.aion.post(r.Context(), peer, "/aion/vote", request, &vote); err != nil ||
				vote.Verifier != peer.ID || vote.validate(m, claim) != nil {
				vote = TimeVote{}
			}
			votes <- vote
		}(peer)
	}
	proof := TimeProof{Claim: claim}
	for range ready {
		if vote := <-votes; vote.Verifier != "" {
			proof.Votes = append(proof.Votes, vote)
			if len(proof.Votes) == m.Policy.Quorum {
				break
			}
		}
	}
	if len(proof.Votes) < m.Policy.Quorum || !n.aionRoundOpen(packet.Header.Round) {
		sendError(w, http.StatusServiceUnavailable, errors.New("Aion time vote quorum unavailable"))
		return
	}
	sort.Slice(proof.Votes, func(i, j int) bool { return proof.Votes[i].Verifier < proof.Votes[j].Verifier })
	if err := proof.Validate(m, packet); err != nil {
		sendError(w, http.StatusConflict, err)
		return
	}
	sendJSON(w, http.StatusOK, proof)
}
