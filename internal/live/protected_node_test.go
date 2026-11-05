package live

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
)

func softwareIngressNode(t *testing.T, f liveTestFixture, keys []ed25519.PrivateKey, index int, s *State, path string) *liveNode {
	t.Helper()
	n := &liveNode{
		cfg:  NodeConfig{Manifest: f.manifest, Index: index, Private: f.nodes[index], IngressPrivate: keys[index]},
		peer: f.manifest.Peers[index], private: f.nodes[index], machine: &Machine{state: s}, journalPath: path,
	}
	if err := n.loadJournal(); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSoftwareIngressNodeRestartAndCompleteSeal(t *testing.T) {
	f, keys := softwareIngressFixture(t)
	s := f.mustApply(t, NewState(f.manifest), 0, "open", nil, 1)
	path := filepath.Join(t.TempDir(), "journal.json")
	n := softwareIngressNode(t, f, keys, 0, s, path)
	bob := f.packet(t, 1, "bob", 0)
	alice := f.packet(t, 1, "alice", 0)
	first, err := n.accept(bob)
	if err != nil || first.Ingress == nil || first.Ingress.Sequence != 1 {
		t.Fatal("first protected admission", err)
	}
	// Restart with only the durable journal, not a copied in-memory sequence.
	n = softwareIngressNode(t, f, keys, 0, s, path)
	second, err := n.accept(alice)
	if err != nil || second.Ingress.Sequence != 2 || second.Ingress.Previous != Hash(*first.Ingress) {
		t.Fatal("restart did not extend original record chain", err)
	}
	retry, err := n.accept(bob)
	if err != nil || Hash(retry) != Hash(first) || len(n.journal.Rounds[1].Accepted) != 2 {
		t.Fatal("duplicate changed recorded admission", err)
	}
	// The protected sealer derives its list from all accepted records.
	n.options.OmitList = true
	list, err := n.seal(s.Round)
	if err != nil || !list.Has(alice.ID()) || !list.Has(bob.ID()) || list.IngressSeal == nil || list.IngressSeal.Count != 2 {
		t.Fatal("protected seal omitted admitted input", err)
	}
	if err := list.Validate(f.manifest, s.Round.Capacity); err != nil {
		t.Fatal(err)
	}
	if _, err := n.accept(f.packet(t, 1, "carol", 0)); err == nil {
		t.Fatal("accepted input after sealing")
	}
	restored := softwareIngressNode(t, f, keys, 0, s, path)
	again, err := restored.seal(s.Round)
	if err != nil || Hash(again) != Hash(list) {
		t.Fatal("restart changed sealed snapshot", err)
	}

	// Even a newly signed valid prefix seal must not replace the full local
	// accepted set on restore. Whole-file rollback remains outside this mock.
	partial := softwareIngressList(t, f, keys[0], 0, 1, []Packet{bob})
	n.journal.Rounds[1].Sealed = &partial
	if err := AtomicJSON(path, n.journal); err != nil {
		t.Fatal(err)
	}
	if err := restored.loadJournal(); err == nil {
		t.Fatal("restored sealed prefix inconsistent with accepted journal")
	}
}

func TestSoftwareIngressPersistenceFailureStopsSigning(t *testing.T) {
	f, keys := softwareIngressFixture(t)
	s := f.mustApply(t, NewState(f.manifest), 0, "open", nil, 1)
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.json")
	n := softwareIngressNode(t, f, keys, 0, s, path)
	bob := f.packet(t, 1, "bob", 0)
	alice := f.packet(t, 1, "alice", 0)
	if _, err := n.accept(bob); err != nil {
		t.Fatal(err)
	}
	// Renaming a journal file over an existing directory must fail.
	n.journalPath = dir
	if _, err := n.accept(alice); err == nil || n.ingressFailure == nil {
		t.Fatal("persistence error did not fail closed")
	}
	n.journalPath = path
	if _, err := n.accept(alice); err == nil {
		t.Fatal("continued issuing records after uncertain persistence")
	}
	if _, err := n.seal(s.Round); err == nil {
		t.Fatal("sealed after uncertain persistence")
	}
	restarted := softwareIngressNode(t, f, keys, 0, s, path)
	accepted, err := restarted.accept(alice)
	if err != nil || accepted.Ingress.Sequence != 2 {
		t.Fatal("restart failed to recover durable prefix", err)
	}
}

func TestSoftwareIngressRecoveryRejectsLocallyContradictoryPrefix(t *testing.T) {
	f, keys := softwareIngressFixture(t)
	s := f.mustApply(t, NewState(f.manifest), 0, "open", nil, 1)
	path := filepath.Join(t.TempDir(), "journal.json")
	n := softwareIngressNode(t, f, keys, 0, s, path)
	if _, err := n.accept(f.packet(t, 1, "bob", 0)); err != nil {
		t.Fatal(err)
	}
	a := f.packet(t, 1, "alice", 0)
	if _, err := n.accept(a); err != nil {
		t.Fatal(err)
	}
	// A valid accepted prefix alone cannot establish freshness. However, an
	// extra locally signed receipt in the same journal exposes this deletion.
	delete(n.journal.Rounds[1].Accepted, a.ID())
	if err := AtomicJSON(path, n.journal); err != nil {
		t.Fatal(err)
	}
	if err := n.loadJournal(); err == nil {
		t.Fatal("accepted truncated prefix despite contradictory local receipt")
	}
}

func TestSoftwareIngressConsensusAndThresholdPipeline(t *testing.T) {
	f, keys := softwareIngressFixture(t)
	s := f.mustApply(t, NewState(f.manifest), 0, "open", nil, 1)
	a := f.packet(t, 1, "alice", 0)
	b := f.packet(t, 1, "bob", 0)
	// Real local observation orders can differ. This version authenticates
	// them without treating timestamps as a new global fairness policy.
	lists := []FinalList{
		softwareIngressList(t, f, keys[0], 0, 1, []Packet{b, a}),
		softwareIngressList(t, f, keys[1], 1, 1, []Packet{a, b}),
		softwareIngressList(t, f, keys[2], 2, 1, []Packet{a, b}),
	}
	s = f.register(t, s, 1, 5, lists...)
	if len(s.Queue) != 2 || s.Queue[0] != a.ID() || len(s.Openings) != 0 {
		t.Fatal("protected records changed baseline ordering or opened too early")
	}
	s = f.serve(t, s, 7)
	if len(s.Results) != 2 || len(s.Queue) != 0 || len(s.Openings) != 2 {
		t.Fatal("protected mode did not complete threshold processing")
	}
	if err := AuditState(f.manifest, s); err != nil {
		t.Fatal("protected public audit", err)
	}
}

func TestSoftwareIngressRejectsWrongNodeKeyBeforeStartup(t *testing.T) {
	f, keys := softwareIngressFixture(t)
	cfg := NodeConfig{Manifest: f.manifest, Index: 0, Private: f.nodes[0], IngressPrivate: keys[1], Share: f.secrets[0]}
	if err := RunNode(context.Background(), cfg, NodeOptions{}); err == nil || errors.Is(err, context.Canceled) {
		t.Fatal("wrong software ingress key accepted")
	}
}

func TestSoftwareIngressManifestRejectsCrossRoleKeyReuse(t *testing.T) {
	f, _ := softwareIngressFixture(t)
	f.manifest.Peers[1].IngressKey = append([]byte(nil), f.manifest.Peers[0].Key...)
	f.manifest.Context = f.manifest.ContextID()
	if err := f.manifest.Validate(); err == nil {
		t.Fatal("ingress key reused another member's ordinary signing key")
	}
}
