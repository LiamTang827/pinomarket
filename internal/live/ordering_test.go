package live

import "testing"

func TestBaseRegistrationDoesNotGateOrRankByObservationCount(t *testing.T) {
	f := newLiveTestFixture(t)
	a := f.packet(t, 1, "alice", 0)
	b := f.packet(t, 1, "bob", 0)
	// Alice appears in just one selected list; Bob appears in all three. List
	// frequency is not an eligibility gate or ordering input in the base protocol.
	s := f.mustApply(t, NewState(f.manifest), 0, "open", nil, 1)
	s = f.register(t, s, 1, 5,
		f.list(0, 1, a, b), f.list(1, 1, b), f.list(2, 1, b))
	if len(s.Queue) != 2 || s.Queue[0] != a.ID() || s.Queue[1] != b.ID() {
		t.Fatalf("base deterministic placeholder unexpectedly changed: %v", s.Queue)
	}
	if err := AuditState(f.manifest, s); err != nil {
		t.Fatal(err)
	}
	bad := s.Clone()
	bad.Registrations[0].Items[0], bad.Registrations[0].Items[1] = b.ID(), a.ID()
	if err := auditRegistrationOrder(f.manifest, bad.Registrations[0], map[string]bool{}); err == nil {
		t.Fatal("auditor accepted a different order")
	}
}

func TestBaseProtocolRejectsRemovedOrderingConfiguration(t *testing.T) {
	f := newLiveTestFixture(t)
	f.manifest.Policy.Ordering = "median-receipts"
	f.manifest.Context = f.manifest.ContextID()
	if err := f.manifest.Validate(); err == nil {
		t.Fatal("withdrawn experiment manifest accepted by base protocol")
	}
	if _, err := InitNetwork(t.TempDir(), InitOptions{Ordering: "median-receipts"}); err == nil {
		t.Fatal("withdrawn experiment configuration accepted")
	}
}
