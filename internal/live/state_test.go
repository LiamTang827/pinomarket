package live

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sort"
	"testing"

	"github.com/LiamTang827/pinomarket/protocol"
	"github.com/LiamTang827/pinomarket/threshold"
)

type liveTestFixture struct {
	manifest Manifest
	nodes    []ed25519.PrivateKey
	users    map[string]ed25519.PrivateKey
	secrets  []threshold.SecretShare
}

func newLiveTestFixture(t *testing.T) liveTestFixture {
	t.Helper()
	crypto, shares, err := threshold.RunLocalDKG(901, 4, 3)
	if err != nil {
		t.Fatal(err)
	}
	f := liveTestFixture{manifest: Manifest{
		Version: Domain, Session: "test-session",
		Policy: Policy{Nodes: 4, Faults: 1, Quorum: 3, Threshold: 3, QueueCapacity: 8, ServiceCapacity: 2, WindowBlocks: 3},
		Users:  make(map[string][]byte), Crypto: crypto,
	}, users: make(map[string]ed25519.PrivateKey), secrets: shares}
	for i := 0; i < 4; i++ {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		f.nodes = append(f.nodes, key)
		f.manifest.Peers = append(f.manifest.Peers, Peer{ID: fmt.Sprintf("node-%d", i+1), Index: i, Key: pub, ValidatorKey: bytes.Clone(pub)})
	}
	for _, owner := range []string{"alice", "bob", "carol", "seller"} {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		f.users[owner], f.manifest.Users[owner] = key, pub
	}
	f.manifest.Context = f.manifest.ContextID()
	if err := f.manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f liveTestFixture) packet(t *testing.T, round int, owner string, nonce int) Packet {
	t.Helper()
	order := protocol.Order{Owner: owner, Nonce: nonce, Kind: "buy", Listing: "yes-1", Quantity: 1, Limit: 60}
	p, err := NewPacket(f.manifest, round, order, f.users[owner])
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (f liveTestFixture) list(index, round int, packets ...Packet) FinalList {
	items := append([]Packet{}, packets...)
	sort.Slice(items, func(i, j int) bool { return items[i].ID() < items[j].ID() })
	node := f.manifest.Peers[index].ID
	l := FinalList{Context: f.manifest.Context, Node: node, Round: round, Packets: items, Promises: []Promise{}}
	for _, packet := range items {
		l.Promises = append(l.Promises, NewPromise(f.manifest, node, round, packet.ID(), f.nodes[index]))
	}
	l.Signature = Sign(f.nodes[index], l.body())
	return l
}

func (f liveTestFixture) tx(index int, kind string, payload any) SignedTx {
	return NewTx(f.manifest, f.manifest.Peers[index].ID, kind, payload, f.nodes[index])
}

func (f liveTestFixture) command(s *State, index int, kind string, payload any) SignedTx {
	if payload == nil {
		switch kind {
		case "open":
			round := 1
			if s.Round != nil {
				round = s.Round.Number + 1
			}
			payload = map[string]any{"round": round}
		case "register":
			round := 0
			if s.Round != nil {
				round = s.Round.Number
			}
			payload = map[string]any{"round": round}
		case "lock":
			head := ""
			if len(s.Queue) > 0 {
				head = s.Queue[0]
			}
			payload = map[string]any{"number": len(s.Services) + 1, "head": head}
		case "execute":
			id := ""
			if s.Active != nil {
				id = s.Active.ID
			}
			payload = map[string]any{"lock_id": id}
		}
	}
	return f.tx(index, kind, payload)
}

// Apply the same signature check and candidate cloning as Machine.FinalizeBlock.
func (f liveTestFixture) apply(s *State, tx SignedTx, height int64) (*State, error) {
	parsed, err := ParseTx(f.manifest, JSON(tx))
	if err != nil {
		return s, err
	}
	candidate := s.Clone()
	if err := candidate.Apply(f.manifest, parsed, height); err != nil {
		return s, err
	}
	candidate.Height = height
	return candidate, nil
}

func (f liveTestFixture) mustApply(t *testing.T, s *State, index int, kind string, payload any, height int64) *State {
	t.Helper()
	next, err := f.apply(s, f.command(s, index, kind, payload), height)
	if err != nil {
		t.Fatalf("apply %s at %d: %v", kind, height, err)
	}
	return next
}

func (f liveTestFixture) reject(t *testing.T, s *State, tx SignedTx, height int64) {
	t.Helper()
	before := JSON(s)
	next, err := f.apply(s, tx, height)
	if err == nil {
		t.Fatalf("unexpectedly accepted %s at %d", tx.Type, height)
	}
	if next != s || !bytes.Equal(before, JSON(s)) {
		t.Fatalf("rejected %s changed committed state", tx.Type)
	}
}

func (f liveTestFixture) register(t *testing.T, s *State, round int, height int64, lists ...FinalList) *State {
	t.Helper()
	for _, list := range lists {
		peer, ok := f.manifest.Peer(list.Node)
		if !ok {
			t.Fatal("unknown fixture list member")
		}
		s = f.mustApply(t, s, peer.Index, "list", list, height)
	}
	return f.mustApply(t, s, 0, "register", nil, height+1)
}

func (f liveTestFixture) batch(t *testing.T, s *State, index int) ShareBatch {
	t.Helper()
	if s.Active == nil {
		t.Fatal("fixture requires active service lock")
	}
	batch := ShareBatch{LockID: s.Active.ID, Shares: make(map[string]threshold.DecryptionShare)}
	for _, id := range s.Active.Items {
		share, err := threshold.CreateDecryptionShare(f.manifest.Crypto, f.secrets[index], s.Orders[id].Wrapped)
		if err != nil {
			t.Fatal(err)
		}
		batch.Shares[id] = share
	}
	return batch
}

func (f liveTestFixture) serve(t *testing.T, s *State, height int64) *State {
	t.Helper()
	s = f.mustApply(t, s, 0, "lock", nil, height)
	for index := 0; index < f.manifest.Policy.Threshold; index++ {
		s = f.mustApply(t, s, index, "shares", f.batch(t, s, index), height+1)
	}
	return f.mustApply(t, s, 0, "execute", nil, height+2)
}

func TestLiveStateQuorumToThresholdExecutionAndReleaseGates(t *testing.T) {
	f := newLiveTestFixture(t)
	s := f.mustApply(t, NewState(f.manifest), 0, "open", nil, 1)
	p := f.packet(t, 1, "alice", 0)
	for i := 0; i < 3; i++ {
		promise := NewPromise(f.manifest, f.manifest.Peers[i].ID, 1, p.ID(), f.nodes[i])
		if err := promise.Validate(f.manifest); err != nil {
			t.Fatal(err)
		}
	}
	f.reject(t, s, f.tx(0, "list", f.list(0, 1, p)), s.Round.CloseHeight)
	f.reject(t, s, f.tx(0, "shares", ShareBatch{LockID: "uncommitted", Shares: map[string]threshold.DecryptionShare{p.ID(): {}}}), 2)
	f.reject(t, s, f.command(s, 0, "register", nil), 5)
	for i := 0; i < 2; i++ {
		s = f.mustApply(t, s, i, "list", f.list(i, 1, p), 5)
	}
	f.reject(t, s, f.command(s, 0, "register", nil), 5)
	s = f.mustApply(t, s, 2, "list", f.list(2, 1, p), 5)
	s = f.mustApply(t, s, 0, "register", nil, 6)
	if len(s.Queue) != 1 || s.Queue[0] != p.ID() || len(s.Registrations[0].Lists) != 3 {
		t.Fatal("quorum registration did not deduplicate and retain admitted packet")
	}
	f.reject(t, s, f.tx(3, "list", f.list(3, 1, p)), 7)
	s = f.mustApply(t, s, 0, "lock", nil, 7)
	batch0 := f.batch(t, s, 0)
	f.reject(t, s, f.tx(0, "shares", batch0), 7)
	f.reject(t, s, f.tx(0, "shares", f.batch(t, s, 1)), 8) // Correct proof signed by wrong member.
	wrongLock := batch0
	wrongLock.LockID = "a different service"
	f.reject(t, s, f.tx(0, "shares", wrongLock), 8)
	wrongContext := f.tx(0, "shares", batch0)
	wrongContext.Context = "another network"
	wrongContext.Signature = Sign(f.nodes[0], wrongContext.body())
	f.reject(t, s, wrongContext, 8)
	s = f.mustApply(t, s, 0, "shares", batch0, 8)
	f.reject(t, s, f.tx(0, "shares", batch0), 8)
	s = f.mustApply(t, s, 1, "shares", f.batch(t, s, 1), 8)
	f.reject(t, s, f.command(s, 0, "execute", nil), 9)
	s = f.mustApply(t, s, 2, "shares", f.batch(t, s, 2), 8)
	s = f.mustApply(t, s, 3, "execute", nil, 9)
	if s.Active != nil || len(s.Queue) != 0 || len(s.Services) != 1 || len(s.Openings) != 1 || len(s.Results) != 1 || s.Results[0].Status != "filled" || s.Market.Cash["alice"] != 940 || s.Market.Shares["alice"] != 1 {
		t.Fatalf("unexpected threshold execution result: %s", JSON(s))
	}
	if err := AuditState(f.manifest, s); err != nil {
		t.Fatalf("public audit rejected completed threshold execution: %v", err)
	}
	f.reject(t, s, f.tx(0, "shares", batch0), 10)
}

func TestLiveStateQuorumIntersectionInclusionAndOmissionEvidence(t *testing.T) {
	f := newLiveTestFixture(t)
	s := f.mustApply(t, NewState(f.manifest), 0, "open", nil, 1)
	p := f.packet(t, 1, "bob", 0)
	// An item promised by q=3 parties intersects every selected q=3 lists in
	// at least two parties. Even one selected member omitting its promise leaves
	// an honest includer. This test selects nodes 1, 2 and 4.
	promises := []Promise{}
	for i := 0; i < 3; i++ {
		promises = append(promises, NewPromise(f.manifest, f.manifest.Peers[i].ID, 1, p.ID(), f.nodes[i]))
	}
	omitted := f.list(0, 1)
	s = f.register(t, s, 1, 5, omitted, f.list(1, 1, p), f.list(3, 1))
	if !Contains(s.Queue, p.ID()) {
		t.Fatal("selected quorum failed to include an honestly listed promised item")
	}
	evidence := Evidence{Promise: promises[0], List: omitted}
	if err := evidence.Validate(f.manifest); err != nil {
		t.Fatal(err)
	}
	s = f.mustApply(t, s, 2, "evidence", evidence, 7)
	if len(s.Evidence) != 1 {
		t.Fatal("public omission evidence was not recorded")
	}
	f.reject(t, s, f.tx(2, "evidence", evidence), 8)
	if err := (Evidence{Promise: promises[1], List: f.list(1, 1, p)}).Validate(f.manifest); err == nil {
		t.Fatal("an included promise incorrectly produced omission evidence")
	}
}

func TestLiveStateOwnerEquivocationExceptionExcludesConflictingCommand(t *testing.T) {
	f := newLiveTestFixture(t)
	s := f.mustApply(t, NewState(f.manifest), 0, "open", nil, 1)
	a := f.packet(t, 1, "alice", 0)
	b := f.packet(t, 1, "alice", 0) // Same signed owner/nonce, a different ciphertext ID.
	// Inclusion promises are for a non-equivocating command. An owner signing
	// two packet IDs for the same owner/nonce deliberately invokes the documented
	// equivocation exception; the selected union excludes both alternatives.
	s = f.register(t, s, 1, 5, f.list(0, 1, a), f.list(1, 1, a), f.list(2, 1, a, b))
	if len(s.Queue) != 0 || len(s.Registrations[0].Items) != 0 || s.Used[a.Ref()] != "" {
		t.Fatal("conflicting signed owner/nonce alternatives were executed or consumed")
	}
}

func TestLiveStateQueueReservationAndServiceAcrossRounds(t *testing.T) {
	f := newLiveTestFixture(t)
	s := f.mustApply(t, NewState(f.manifest), 0, "open", nil, 1)
	if s.Round.Capacity != 2 {
		t.Fatal("unexpected first-round reservation")
	}
	a0, a1 := f.packet(t, 1, "alice", 0), f.packet(t, 1, "alice", 1)
	b0, b1 := f.packet(t, 1, "bob", 0), f.packet(t, 1, "bob", 1)
	c0, c1 := f.packet(t, 1, "carol", 0), f.packet(t, 1, "carol", 1)
	s = f.register(t, s, 1, 5, f.list(0, 1, a1, a0), f.list(1, 1, b1, b0), f.list(2, 1, c1, c0))
	if len(s.Queue) != 6 || s.Queue[0] != a0.ID() || s.Queue[1] != a1.ID() {
		t.Fatal("registration failed deterministic owner/nonce ordering")
	}
	s = f.mustApply(t, s, 0, "open", nil, 7)
	if s.Round.Capacity != 0 {
		t.Fatal("reserved more than available queue slots divided among nodes")
	}
	f.reject(t, s, f.tx(0, "list", f.list(0, 2, f.packet(t, 2, "alice", 2))), 11)
	s = f.register(t, s, 2, 11, f.list(0, 2), f.list(1, 2), f.list(2, 2))
	s = f.serve(t, s, 13)
	if len(s.Queue) != 4 || len(s.Services[0].Items) != 2 || s.Services[0].Items[0] != a0.ID() || s.Services[0].Items[1] != a1.ID() {
		t.Fatal("service failed to drain only the oldest bounded queue prefix")
	}
	s = f.mustApply(t, s, 0, "open", nil, 16)
	if s.Round.Capacity != 1 {
		t.Fatal("serviced slots were not available to a later round")
	}
	a2, b2, c2 := f.packet(t, 3, "alice", 2), f.packet(t, 3, "bob", 2), f.packet(t, 3, "carol", 2)
	s = f.register(t, s, 3, 20, f.list(0, 3, a2), f.list(1, 3, b2), f.list(2, 3, c2))
	if len(s.Queue) != 7 || s.Queue[0] != b0.ID() || s.Queue[4] != a2.ID() || len(s.Queue) > f.manifest.Policy.QueueCapacity {
		t.Fatal("later registration jumped older work or exceeded the reserved queue bound")
	}
}

func TestLiveStateMalformedEncryptedPayloadFailsDeterministically(t *testing.T) {
	f := newLiveTestFixture(t)
	p := f.packet(t, 1, "carol", 0)
	// A syntactically valid threshold encryption does not prove that the hidden
	// payload is a 32-byte AES key. A malicious authenticated owner can submit it;
	// every validator must emit the same failure and consume the service slot.
	var err error
	p.Wrapped, err = threshold.Encrypt(f.manifest.Crypto, p.label(), []byte("wrong key length"))
	if err != nil {
		t.Fatal(err)
	}
	p.Signature = Sign(f.users["carol"], p.core())
	if err := p.Validate(f.manifest); err != nil {
		t.Fatal(err)
	}
	s := f.mustApply(t, NewState(f.manifest), 0, "open", nil, 1)
	s = f.register(t, s, 1, 5, f.list(0, 1, p), f.list(1, 1, p), f.list(2, 1, p))
	before := s.Clone()
	s = f.serve(t, s, 7)
	other := f.serve(t, before, 7)
	if !bytes.Equal(JSON(s), JSON(other)) || len(s.Results) != 1 || s.Results[0].Status != "invalid_encrypted_payload" || len(s.Openings) != 0 || len(s.Queue) != 0 || s.Market.Cash["carol"] != 1000 {
		t.Fatal("malformed encrypted input did not produce the same bounded failure")
	}
	if err := AuditState(f.manifest, s); err != nil {
		t.Fatalf("public audit rejected deterministic malformed-payload failure: %v", err)
	}
	changed := f.packet(t, 1, "alice", 5)
	changed.Body[0] ^= 1
	changed.Signature = Sign(f.users["alice"], changed.core())
	if err := changed.Validate(f.manifest); err == nil {
		t.Fatal("AES body tampering accepted without rebinding its threshold identity label")
	}
}

func TestLiveMachineCommitRestartAndDurableNonceReplayFiltering(t *testing.T) {
	f := newLiveTestFixture(t)
	dir := t.TempDir()
	machine, err := NewMachine(f.manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	block := func(height int64, txs ...SignedTx) {
		t.Helper()
		raw := make([][]byte, len(txs))
		for i, tx := range txs {
			raw[i] = JSON(tx)
		}
		results, expectedHash, err := machine.FinalizeBlock(height, raw)
		if err != nil {
			t.Fatal(err)
		}
		for i, result := range results {
			if result.Code != 0 {
				t.Fatalf("height %d tx %d: %s", height, i, result.Log)
			}
		}
		if got, _ := machine.Info(); got == height {
			t.Fatal("FinalizeBlock exposed uncommitted state")
		}
		if err := machine.Commit(); err != nil {
			t.Fatal(err)
		}
		gotHeight, gotHash := machine.Info()
		if gotHeight != height || !bytes.Equal(gotHash, expectedHash) {
			t.Fatal("committed app hash differs from finalized state")
		}
	}
	restart := func() {
		t.Helper()
		height, hash := machine.Info()
		before := JSON(machine.Snapshot())
		recovered, err := NewMachine(f.manifest, dir)
		if err != nil {
			t.Fatal(err)
		}
		h2, hash2 := recovered.Info()
		if height != h2 || !bytes.Equal(hash, hash2) || !bytes.Equal(before, JSON(recovered.Snapshot())) {
			t.Fatal("restart changed committed state, height or app hash")
		}
		machine = recovered
	}
	p := f.packet(t, 1, "alice", 0)
	block(1, f.tx(0, "open", map[string]any{"round": 1}))
	restart()
	for h := int64(2); h <= 4; h++ {
		block(h)
	}
	block(5, f.tx(0, "list", f.list(0, 1, p)), f.tx(1, "list", f.list(1, 1, p)), f.tx(2, "list", f.list(2, 1, p)))
	block(6, f.command(machine.Snapshot(), 0, "register", nil))
	block(7, f.command(machine.Snapshot(), 0, "lock", nil))
	restart()
	s := machine.Snapshot()
	block(8, f.tx(0, "shares", f.batch(t, s, 0)), f.tx(1, "shares", f.batch(t, s, 1)), f.tx(2, "shares", f.batch(t, s, 2)))
	restart()
	block(9, f.command(machine.Snapshot(), 0, "execute", nil))
	restart()
	if machine.Snapshot().Used[p.Ref()] != p.ID() || machine.Snapshot().Market.Shares["alice"] != 1 {
		t.Fatal("restart lost command use or market balances")
	}
	// A newly signed packet in another round and with fresh encryption still
	// cannot execute the same durable owner/nonce a second time.
	replayed := f.packet(t, 2, "alice", 0)
	block(10, f.command(machine.Snapshot(), 0, "open", nil))
	for h := int64(11); h <= 13; h++ {
		block(h)
	}
	block(14, f.tx(0, "list", f.list(0, 2, replayed)), f.tx(1, "list", f.list(1, 2, replayed)), f.tx(2, "list", f.list(2, 2, replayed)))
	block(15, f.command(machine.Snapshot(), 0, "register", nil))
	restart()
	s = machine.Snapshot()
	if len(s.Queue) != 0 || len(s.Results) != 1 || len(s.Registrations) != 2 || len(s.Registrations[1].Items) != 0 || s.Market.Shares["alice"] != 1 {
		t.Fatal("persisted replay filter permitted a second execution")
	}
}

func TestLiveStateSignedCommandReplayBindings(t *testing.T) {
	f := newLiveTestFixture(t)
	f.manifest.Policy.ServiceCapacity = 1
	f.manifest.Context = f.manifest.ContextID()
	s := NewState(f.manifest)
	oldOpen := f.tx(0, "open", map[string]any{"round": 1})
	var err error
	s, err = f.apply(s, oldOpen, 1)
	if err != nil {
		t.Fatal(err)
	}
	a, b := f.packet(t, 1, "alice", 0), f.packet(t, 1, "bob", 0)
	for i := 0; i < 3; i++ {
		s = f.mustApply(t, s, i, "list", f.list(i, 1, a, b), 5)
	}
	oldRegister := f.command(s, 0, "register", nil)
	s, err = f.apply(s, oldRegister, 6)
	if err != nil {
		t.Fatal(err)
	}
	// The exact old signed bytes must fail under application rules, even when
	// CometBFT's transaction cache is bypassed or absent.
	f.reject(t, s, oldOpen, 7)
	f.reject(t, s, f.tx(0, "lock", map[string]any{"number": 1, "head": b.ID()}), 7)
	f.reject(t, s, f.tx(0, "lock", map[string]any{"number": 2, "head": a.ID()}), 7)
	oldLock := f.command(s, 0, "lock", nil)
	s, err = f.apply(s, oldLock, 7)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		s = f.mustApply(t, s, i, "shares", f.batch(t, s, i), 8)
	}
	oldExecute := f.command(s, 0, "execute", nil)
	f.reject(t, s, f.tx(0, "execute", map[string]any{"lock_id": "another lock"}), 9)
	s, err = f.apply(s, oldExecute, 9)
	if err != nil {
		t.Fatal(err)
	}
	f.reject(t, s, oldLock, 10)
	s = f.mustApply(t, s, 0, "lock", nil, 10)
	for i := 0; i < 3; i++ {
		s = f.mustApply(t, s, i, "shares", f.batch(t, s, i), 11)
	}
	f.reject(t, s, oldExecute, 12) // A later lock is ready; only the ID is wrong.
	s = f.mustApply(t, s, 0, "execute", nil, 12)
	s = f.mustApply(t, s, 0, "open", nil, 13)
	for i := 0; i < 3; i++ {
		s = f.mustApply(t, s, i, "list", f.list(i, 2), 17)
	}
	f.reject(t, s, oldRegister, 18) // A later round has a quorum; only the round is wrong.
	s = f.mustApply(t, s, 0, "register", nil, 18)
	if len(s.Services) != 2 || len(s.Results) != 2 || s.Round.Number != 2 || !s.Round.Registered {
		t.Fatal("fresh commands failed after signed replay attempts")
	}
}
