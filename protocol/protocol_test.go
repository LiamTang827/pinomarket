package protocol

import (
	"crypto/ed25519"
	"testing"
)

func run(t *testing.T, name string) *Report {
	t.Helper()
	c, e := DefaultConfig(name)
	if e != nil {
		t.Fatal(e)
	}
	r, e := Run(c)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestScenarioOutcomes(t *testing.T) {
	cases := []struct {
		name               string
		evidence, executed int
		firstStatus        string
	}{
		{"normal", 0, 3, "filled"}, {"delay", 0, 3, "filled"}, {"omission", 3, 3, "filled"}, {"refusal", 0, 3, "filled"}, {"equivocation", 2, 3, "filled"}, {"late", 0, 2, "filled"}, {"capacity", 0, 2, "filled"}, {"funds", 0, 3, "insufficient_funds"}, {"cancel", 0, 4, "filled"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := run(t, c.name)
			if len(r.Audit.Evidence) != c.evidence || len(r.Results) != c.executed || r.Results[0].Status != c.firstStatus {
				t.Fatalf("unexpected results: evidence=%d results=%+v", len(r.Audit.Evidence), r.Results)
			}
		})
	}
}
func TestNoCrossRoundOvertakeAndNoEarlyReveal(t *testing.T) {
	r := run(t, "normal")
	if r.Results[0].Order != "alice:0" || r.Results[1].Order != "bob:0" || r.Results[2].Order != "carol:0" {
		t.Fatal(r.Results)
	}
	locked := map[string]bool{}
	registered := map[string]bool{}
	for _, e := range r.Events {
		switch e.Kind {
		case "registered":
			registered[e.Order] = true
		case "service_locked":
			if !registered[e.Order] {
				t.Fatal("lock before registration")
			}
			locked[e.Order] = true
		case "decrypted":
			if !locked[e.Order] {
				t.Fatal("decryption before lock")
			}
		}
	}
}
func TestEvidenceTamperAndContext(t *testing.T) {
	r := run(t, "omission")
	e := r.Audit.Evidence[0]
	if !e.Verify(r.Audit.Members, r.Context) {
		t.Fatal("valid evidence rejected")
	}
	if e.Verify(r.Audit.Members, "other-context") {
		t.Fatal("cross-context replay accepted")
	}
	e.First.Items = []string{"fabricated"}
	if e.Verify(r.Audit.Members, r.Context) {
		t.Fatal("tampered evidence accepted")
	}
}
func TestDuplicateSignerNotQuorum(t *testing.T) {
	r := run(t, "normal")
	c := r.Admissions[0]
	c.Votes = []Statement{c.Votes[0], c.Votes[0], c.Votes[0], c.Votes[0]}
	if c.Verify(r.Audit.Members, 4) {
		t.Fatal("duplicate signer counted")
	}
}
func TestSemanticReproducibility(t *testing.T) {
	a, b := run(t, "delay"), run(t, "delay")
	if a.SemanticDigest != b.SemanticDigest {
		t.Fatal("semantic trace differs")
	}
	if a.Envelopes[0].ID() == b.Envelopes[0].ID() {
		t.Fatal("unexpected reused crypto randomness")
	}
}
func TestFundsAndAssetConservation(t *testing.T) {
	for _, name := range []string{"normal", "funds", "cancel"} {
		r := run(t, name)
		var cash, shares int64
		for _, v := range r.Market.Cash {
			if v < 0 {
				t.Fatal("negative cash")
			}
			cash += v
		}
		for _, v := range r.Market.Shares {
			if v < 0 {
				t.Fatal("negative shares")
			}
			shares += v
		}
		expected := int64(3000)
		if name == "funds" {
			expected = 2100
		}
		if cash != expected || shares+r.Market.Inventory != 10 {
			t.Fatalf("conservation failed: %s", name)
		}
	}
}
func TestInvalidConfiguration(t *testing.T) {
	c, _ := DefaultConfig("normal")
	c.Admission = 2
	if c.Validate() == nil {
		t.Fatal("unsafe quorum accepted")
	}
	c, _ = DefaultConfig("normal")
	c.Release = 1
	if c.Validate() == nil {
		t.Fatal("unsafe release accepted")
	}
}
func TestVaultRequiresLockAndDistinctApprovals(t *testing.T) {
	users := map[string][]byte{}
	pub, priv, _ := newIdentity()
	users["alice"] = pub
	keys := map[string][]byte{}
	private := map[string]ed25519.PrivateKey{}
	for _, id := range []string{"a", "b", "c", "d"} {
		p, k, _ := newIdentity()
		keys[id] = p
		private[id] = k
	}
	v := NewIdealVault(3)
	h := Header{Domain: Domain, Context: "ctx", Round: 1, Owner: "alice"}
	o := Order{Owner: "alice", Kind: "buy", Listing: "yes-1", Quantity: 1, Limit: 60}
	e, err := v.Seal(h, o, priv)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{e.ID()}
	lock := Certificate{Context: "ctx", Round: 1, Item: digest(ids)}
	approvals := []Statement{}
	for _, id := range []string{"a", "b", "c", "d"} {
		lock.Votes = append(lock.Votes, statement(private[id], "ctx", "service", id, 1, []string{lock.Item}))
		approvals = append(approvals, statement(private[id], "ctx", "release", id, 1, []string{lock.Item}))
	}
	if _, err = v.Open(e, lock, approvals, keys, users, 3); err == nil {
		t.Fatal("opened without finalized lock")
	}
	if err = v.lock(lock, ids, keys, 4); err != nil {
		t.Fatal(err)
	}
	if _, err = v.Open(e, lock, approvals[:2], keys, users, 3); err == nil {
		t.Fatal("opened below release threshold")
	}
	if _, err = v.Open(e, lock, approvals[:1], keys, users, 1); err == nil {
		t.Fatal("caller lowered configured threshold")
	}
	duplicates := []Statement{approvals[0], approvals[0], approvals[0]}
	if _, err = v.Open(e, lock, duplicates, keys, users, 3); err == nil {
		t.Fatal("duplicate approvals accepted")
	}
	modified := e
	modified.Header.Round = 2
	if _, err = v.Open(modified, lock, approvals, keys, users, 3); err == nil {
		t.Fatal("modified header accepted")
	}
	if _, err = v.Open(e, lock, approvals, keys, users, 3); err != nil {
		t.Fatal(err)
	}
	if _, err = v.Open(e, lock, approvals, keys, users, 3); err == nil {
		t.Fatal("duplicate decrypt accepted")
	}
}
