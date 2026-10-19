package live

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/LiamTang827/pinocchio-market/internal/consensus"
	"github.com/LiamTang827/pinocchio-market/threshold"
	rpchttp "github.com/cometbft/cometbft/rpc/client/http"
	cmttypes "github.com/cometbft/cometbft/types"
)

// NodeOptions intentionally injects protocol faults in local experiments.
// A node still possesses only its own signing key and threshold secret share.
type NodeOptions struct {
	Refuse         bool
	OmitList       bool
	WithholdShares bool
	DelayMS        int
}

// Gossip contains public signed receipts; it carries no private key material.
type Gossip struct {
	Packet  Packet  `json:"packet"`
	Promise Promise `json:"promise"`
}

type admissionRound struct {
	Accepted map[string]Gossip `json:"accepted"`
	Sealed   *FinalList        `json:"sealed,omitempty"`
}

type admissionJournal struct {
	Context  string                  `json:"context"`
	Node     string                  `json:"node"`
	Rounds   map[int]*admissionRound `json:"rounds"`
	Receipts map[string]Gossip       `json:"receipts"`
	Lists    map[string]FinalList    `json:"lists"`
}

type liveNode struct {
	cfg         NodeConfig
	options     NodeOptions
	peer        Peer
	private     ed25519.PrivateKey
	machine     *Machine
	rpc         *rpchttp.HTTP
	httpClient  *http.Client
	journalPath string
	mu          sync.Mutex
	journal     admissionJournal
}

// RunNode runs one independent application, HTTP transport and CometBFT process.
// The worker authorizes every decryption share from this node's committed local
// application snapshot, after a service lock has reached consensus finality.
func RunNode(ctx context.Context, cfg NodeConfig, options NodeOptions) error {
	if err := cfg.Manifest.Validate(); err != nil {
		return err
	}
	if cfg.Index < 0 || cfg.Index >= len(cfg.Manifest.Peers) {
		return errors.New("node index outside manifest")
	}
	peer := cfg.Manifest.Peers[cfg.Index]
	if len(cfg.Private) != ed25519.PrivateKeySize {
		return errors.New("invalid local signing key")
	}
	private := ed25519.PrivateKey(cfg.Private)
	if !bytes.Equal(private.Public().(ed25519.PublicKey), peer.Key) {
		return errors.New("local signing key does not match manifest member")
	}
	if cfg.Share.Index != cfg.Index || cfg.Share.ConfigID != cfg.Manifest.Crypto.ID || len(cfg.Share.Value) == 0 || len(cfg.Share.Value) > 32 {
		return errors.New("local threshold share does not match manifest configuration/index")
	}
	if cfg.CometDir == "" {
		return errors.New("missing CometBFT home directory")
	}
	if options.DelayMS < 0 || options.DelayMS > 60000 {
		return errors.New("delay must be between 0 and 60000 milliseconds")
	}
	listenAddress, err := localAddress(peer.API)
	if err != nil {
		return fmt.Errorf("node API: %w", err)
	}
	for _, p := range cfg.Manifest.Peers {
		if _, err := localAddress(p.API); err != nil {
			return fmt.Errorf("peer %s API: %w", p.ID, err)
		}
		if _, err := localAddress(p.RPC); err != nil {
			return fmt.Errorf("peer %s RPC: %w", p.ID, err)
		}
	}
	machine, err := NewMachine(cfg.Manifest, filepath.Join(cfg.CometDir, "app"))
	if err != nil {
		return err
	}
	rpc, err := rpchttp.NewWithTimeout(peer.RPC, "/websocket", 2)
	if err != nil {
		return err
	}
	// Keep retrying consensus transactions bounded; a missing quorum must not
	// prevent the worker or HTTP server from responding to shutdown.
	n := &liveNode{cfg: cfg, options: options, peer: peer, private: private, machine: machine, rpc: rpc, httpClient: &http.Client{Timeout: 2 * time.Second}, journalPath: filepath.Join(cfg.CometDir, "app", "admission.json")}
	if err := n.loadJournal(); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	comet, err := consensus.StartNode(cfg.CometDir, consensus.NewApplication(machine))
	if err != nil {
		return err
	}
	defer func() {
		if comet.IsRunning() {
			_ = comet.Stop()
			comet.Wait()
		}
	}()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	mux := http.NewServeMux()
	mux.HandleFunc("/health", n.health)
	mux.HandleFunc("/state", n.state)
	mux.HandleFunc("/submit", n.submit)
	mux.HandleFunc("/gossip", n.gossip)
	mux.HandleFunc("/open", n.open)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 65 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 * 1024, BaseContext: func(net.Listener) context.Context { return runCtx }}
	errorsC := make(chan error, 2)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errorsC <- err
		}
	}()
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		if err := n.work(runCtx); err != nil {
			errorsC <- err
		}
	}()
	var runErr error
	select {
	case <-ctx.Done():
	case err := <-errorsC:
		runErr = err
	case <-comet.Quit():
		runErr = errors.New("CometBFT stopped unexpectedly")
	}
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
	_ = server.Close()
	<-workerDone
	return runErr
}

func localAddress(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return "", errors.New("expected a plain local HTTP URL")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", errors.New("local demo endpoints must bind to loopback")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("invalid endpoint port")
	}
	return net.JoinHostPort(host, port), nil
}

func (n *liveNode) loadJournal() error {
	n.journal = admissionJournal{Context: n.cfg.Manifest.Context, Node: n.peer.ID, Rounds: map[int]*admissionRound{}, Receipts: map[string]Gossip{}, Lists: map[string]FinalList{}}
	b, err := os.ReadFile(n.journalPath)
	if errors.Is(err, os.ErrNotExist) {
		return AtomicJSON(n.journalPath, n.journal)
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &n.journal); err != nil {
		return err
	}
	if n.journal.Context != n.cfg.Manifest.Context || n.journal.Node != n.peer.ID {
		return errors.New("admission journal belongs to a different network/member")
	}
	if n.journal.Rounds == nil {
		n.journal.Rounds = map[int]*admissionRound{}
	}
	if n.journal.Receipts == nil {
		n.journal.Receipts = map[string]Gossip{}
	}
	if n.journal.Lists == nil {
		n.journal.Lists = map[string]FinalList{}
	}
	for number, round := range n.journal.Rounds {
		if number < 1 || round == nil {
			return errors.New("invalid admission journal round")
		}
		if round.Accepted == nil {
			round.Accepted = map[string]Gossip{}
		}
		refs := map[string]string{}
		for id, g := range round.Accepted {
			if err := n.validateGossip(g); err != nil {
				return err
			}
			if id != g.Packet.ID() || g.Promise.Node != n.peer.ID || g.Promise.Round != number {
				return errors.New("invalid local admission record")
			}
			if previous := refs[g.Packet.Ref()]; previous != "" && previous != id {
				return errors.New("conflicting commands in local admission journal")
			}
			refs[g.Packet.Ref()] = id
		}
		if round.Sealed != nil {
			if err := round.Sealed.Validate(n.cfg.Manifest, n.cfg.Manifest.Policy.QueueCapacity); err != nil {
				return err
			}
			if round.Sealed.Node != n.peer.ID || round.Sealed.Round != number {
				return errors.New("invalid sealed local final list")
			}
		}
	}
	for hash, g := range n.journal.Receipts {
		if err := n.validateGossip(g); err != nil {
			return err
		}
		if hash != Hash(g.Promise) {
			return errors.New("invalid public receipt key")
		}
	}
	for _, list := range n.journal.Lists {
		if err := list.Validate(n.cfg.Manifest, n.cfg.Manifest.Policy.QueueCapacity); err != nil {
			return err
		}
	}
	return nil
}

func (n *liveNode) validateGossip(g Gossip) error {
	if err := g.Packet.Validate(n.cfg.Manifest); err != nil {
		return err
	}
	if err := g.Promise.Validate(n.cfg.Manifest); err != nil {
		return err
	}
	if g.Promise.ID != g.Packet.ID() || g.Promise.Round != g.Packet.Header.Round {
		return errors.New("receipt does not name its packet/round")
	}
	return nil
}

func sendJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func sendError(w http.ResponseWriter, status int, err error) {
	sendJSON(w, status, map[string]string{"error": err.Error()})
}
func method(w http.ResponseWriter, r *http.Request, want string) bool {
	if r.Method != want {
		w.Header().Set("Allow", want)
		sendError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return false
	}
	return true
}
func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("expected one JSON value")
	}
	return nil
}
func (n *liveNode) health(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	s := n.machine.Snapshot()
	sendJSON(w, http.StatusOK, map[string]any{"ok": true, "node": n.peer.ID, "index": n.cfg.Index, "height": s.Height, "context": s.Context})
}
func (n *liveNode) state(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	sendJSON(w, http.StatusOK, n.machine.Snapshot())
}
func (n *liveNode) submit(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	if n.options.Refuse {
		sendError(w, http.StatusServiceUnavailable, errors.New("node refuses admission"))
		return
	}
	if n.options.DelayMS > 0 {
		timer := time.NewTimer(time.Duration(n.options.DelayMS) * time.Millisecond)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
		}
	}
	var packet Packet
	if err := readJSON(w, r, &packet); err != nil {
		sendError(w, http.StatusBadRequest, err)
		return
	}
	if err := packet.Validate(n.cfg.Manifest); err != nil {
		sendError(w, http.StatusBadRequest, err)
		return
	}
	promise, err := n.accept(packet)
	if err != nil {
		sendError(w, http.StatusConflict, err)
		return
	}
	sendJSON(w, http.StatusOK, promise)
	// Receipt retries also run from the durable journal, so a transient peer
	// outage or crash after this response does not erase the public receipt.
}

func (n *liveNode) accept(packet Packet) (Promise, error) {
	// Hold the committed-state read lock through durable admission, preventing
	// a concurrent block commit from crossing the close height mid-promise.
	n.machine.mu.RLock()
	defer n.machine.mu.RUnlock()
	n.mu.Lock()
	defer n.mu.Unlock()
	id := packet.ID()
	local := n.journal.Rounds[packet.Header.Round]
	if local != nil {
		if old, ok := local.Accepted[id]; ok {
			return old.Promise, nil
		}
	}
	s := n.machine.state
	if s.Round == nil || s.Round.Registered || packet.Header.Round != s.Round.Number || s.Height >= s.Round.CloseHeight {
		return Promise{}, errors.New("admission round is not open")
	}
	if local != nil && local.Sealed != nil {
		return Promise{}, errors.New("admission round already sealed")
	}
	if previous := s.Used[packet.Ref()]; previous != "" {
		return Promise{}, errors.New("owner nonce was already registered")
	}
	if local == nil {
		local = &admissionRound{Accepted: map[string]Gossip{}}
		n.journal.Rounds[packet.Header.Round] = local
	}
	for _, old := range local.Accepted {
		if old.Packet.Ref() == packet.Ref() {
			return Promise{}, errors.New("conflicting packet for an accepted owner nonce")
		}
	}
	if len(local.Accepted) >= s.Round.Capacity {
		return Promise{}, errors.New("node admission capacity is exhausted")
	}
	promise := NewPromise(n.cfg.Manifest, n.peer.ID, packet.Header.Round, id, n.private)
	g := Gossip{packet, promise}
	local.Accepted[id] = g
	hash := Hash(promise)
	n.journal.Receipts[hash] = g
	if err := AtomicJSON(n.journalPath, n.journal); err != nil {
		delete(local.Accepted, id)
		delete(n.journal.Receipts, hash)
		return Promise{}, fmt.Errorf("persist admission: %w", err)
	}
	return promise, nil
}

func (n *liveNode) gossip(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	var g Gossip
	if err := readJSON(w, r, &g); err != nil {
		sendError(w, http.StatusBadRequest, err)
		return
	}
	if err := n.validateGossip(g); err != nil {
		sendError(w, http.StatusBadRequest, err)
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	key := Hash(g.Promise)
	if _, ok := n.journal.Receipts[key]; !ok {
		n.journal.Receipts[key] = g
		if err := AtomicJSON(n.journalPath, n.journal); err != nil {
			delete(n.journal.Receipts, key)
			sendError(w, http.StatusInternalServerError, err)
			return
		}
	}
	sendJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (n *liveNode) open(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	s := n.machine.Snapshot()
	round := 1
	if s.Round != nil {
		round = s.Round.Number + 1
	}
	tx := NewTx(n.cfg.Manifest, n.peer.ID, "open", struct {
		Round int `json:"round"`
	}{round}, n.private)
	result, err := n.rpc.BroadcastTxSync(r.Context(), cmttypes.Tx(JSON(tx)))
	if err != nil {
		sendError(w, http.StatusServiceUnavailable, err)
		return
	}
	if result.Code != 0 {
		sendError(w, http.StatusConflict, errors.New(result.Log))
		return
	}
	sendJSON(w, http.StatusAccepted, map[string]any{"hash": fmt.Sprintf("%X", result.Hash), "status": "submitted"})
}

func (n *liveNode) broadcast(ctx context.Context, kind string, payload any) {
	tx := NewTx(n.cfg.Manifest, n.peer.ID, kind, payload, n.private)
	_, _ = n.rpc.BroadcastTxSync(ctx, cmttypes.Tx(JSON(tx)))
}

func (n *liveNode) work(ctx context.Context) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var gossipTick uint64
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		s := n.machine.Snapshot()
		if err := n.recordLists(s); err != nil {
			return err
		}
		if round := s.Round; round != nil && !round.Registered {
			if s.Height > round.CloseHeight && !round.HasList(n.peer.ID) {
				list, err := n.seal(round)
				if err != nil {
					return err
				}
				n.broadcast(ctx, "list", list)
			}
			if len(round.Lists) >= n.cfg.Manifest.Policy.Quorum {
				n.broadcast(ctx, "register", struct {
					Round int `json:"round"`
				}{round.Number})
			}
		}
		if len(s.Queue) > 0 && s.Active == nil {
			n.broadcast(ctx, "lock", struct {
				Number int    `json:"number"`
				Head   string `json:"head"`
			}{len(s.Services) + 1, s.Queue[0]})
		}
		if lock := s.Active; lock != nil && s.Height >= lock.Height {
			if !n.options.WithholdShares {
				batch := ShareBatch{LockID: lock.ID, Shares: map[string]threshold.DecryptionShare{}}
				for _, id := range lock.Items {
					already := false
					for _, share := range lock.Shares[id] {
						if share.Index == n.cfg.Index {
							already = true
							break
						}
					}
					if already {
						continue
					}
					packet, ok := s.Orders[id]
					if !ok {
						return errors.New("committed service references a missing encrypted packet")
					}
					share, err := threshold.CreateDecryptionShare(n.cfg.Manifest.Crypto, n.cfg.Share, packet.Wrapped)
					if err != nil {
						return fmt.Errorf("create authorized decryption share: %w", err)
					}
					batch.Shares[id] = share
				}
				if len(batch.Shares) > 0 {
					n.broadcast(ctx, "shares", batch)
				}
			}
			ready := true
			for _, id := range lock.Items {
				if len(lock.Shares[id]) < n.cfg.Manifest.Policy.Threshold {
					ready = false
					break
				}
			}
			if ready {
				n.broadcast(ctx, "execute", struct {
					LockID string `json:"lock_id"`
				}{lock.ID})
			}
		}
		for _, e := range n.omissions(s) {
			n.broadcast(ctx, "evidence", e)
		}
		// Rotate one of this node's accepted receipts through all peers per
		// tick. Retry bounds keep worker and shutdown latency predictable.
		gossipTick++
		if g, ok := n.receiptForTick(gossipTick); ok {
			n.sendReceipt(ctx, g)
		}
	}
}

func (n *liveNode) seal(round *Round) (FinalList, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	local := n.journal.Rounds[round.Number]
	if local == nil {
		local = &admissionRound{Accepted: map[string]Gossip{}}
		n.journal.Rounds[round.Number] = local
	}
	if local.Sealed != nil {
		return *local.Sealed, nil
	}
	list := FinalList{Context: n.cfg.Manifest.Context, Node: n.peer.ID, Round: round.Number, Packets: []Packet{}, Promises: []Promise{}}
	if !n.options.OmitList {
		ids := make([]string, 0, len(local.Accepted))
		for id := range local.Accepted {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			g := local.Accepted[id]
			list.Packets = append(list.Packets, g.Packet)
			list.Promises = append(list.Promises, g.Promise)
		}
	}
	list.Signature = Sign(n.private, list.body())
	if err := list.Validate(n.cfg.Manifest, round.Capacity); err != nil {
		return FinalList{}, err
	}
	local.Sealed = &list
	if err := AtomicJSON(n.journalPath, n.journal); err != nil {
		local.Sealed = nil
		return FinalList{}, err
	}
	return list, nil
}

func (n *liveNode) recordLists(s *State) error {
	lists := []FinalList{}
	if s.Round != nil {
		lists = append(lists, s.Round.Lists...)
	}
	for _, registration := range s.Registrations {
		lists = append(lists, registration.Lists...)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	added := []string{}
	for _, list := range lists {
		key := Hash(list)
		if _, ok := n.journal.Lists[key]; !ok {
			n.journal.Lists[key] = list
			added = append(added, key)
		}
	}
	if len(added) == 0 {
		return nil
	}
	if err := AtomicJSON(n.journalPath, n.journal); err != nil {
		for _, key := range added {
			delete(n.journal.Lists, key)
		}
		return err
	}
	return nil
}

func (n *liveNode) omissions(s *State) []Evidence {
	n.mu.Lock()
	defer n.mu.Unlock()
	done := map[string]bool{}
	for _, e := range s.Evidence {
		done[Hash(e)] = true
	}
	out := []Evidence{}
	for _, g := range n.journal.Receipts {
		for _, list := range n.journal.Lists {
			if g.Promise.Node != list.Node || g.Promise.Round != list.Round || list.Has(g.Promise.ID) {
				continue
			}
			e := Evidence{Promise: g.Promise, List: list}
			if !done[Hash(e)] {
				done[Hash(e)] = true
				out = append(out, e)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return Hash(out[i]) < Hash(out[j]) })
	return out
}

func (n *liveNode) receiptForTick(tick uint64) (Gossip, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	keys := []string{}
	for key, g := range n.journal.Receipts {
		if g.Promise.Node == n.peer.ID {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return Gossip{}, false
	}
	sort.Strings(keys)
	return n.journal.Receipts[keys[int(tick%uint64(len(keys)))]], true
}

func (n *liveNode) sendReceipt(ctx context.Context, g Gossip) {
	var wg sync.WaitGroup
	for _, peer := range n.cfg.Manifest.Peers {
		if peer.ID == n.peer.ID {
			continue
		}
		wg.Add(1)
		go func(peer Peer) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, peer.API+"/gossip", bytes.NewReader(JSON(g)))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := n.httpClient.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				_ = resp.Body.Close()
			}
		}(peer)
	}
	wg.Wait()
}
