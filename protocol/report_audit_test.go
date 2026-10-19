package protocol

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func TestAuditAllScenarios(t *testing.T) {
	for _, name := range []string{"normal", "delay", "omission", "refusal", "equivocation", "late", "capacity", "funds", "cancel", "duplicate", "corrupt", "drop"} {
		t.Run(name, func(t *testing.T) {
			r := run(t, name)
			if err := AuditReport(*r); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func cloneReport(r *Report) Report {
	b, _ := json.Marshal(r)
	var out Report
	_ = json.Unmarshal(b, &out)
	return out
}
func TestAuditRejectsTamperedArtifacts(t *testing.T) {
	base := run(t, "omission")
	cases := []struct {
		name   string
		change func(*Report)
	}{
		{"balance", func(r *Report) { r.Market.Cash["alice"]++ }},
		{"cost", func(r *Report) { r.Results[0].Cost++ }},
		{"signature", func(r *Report) { r.Promises[0].Signature[0] ^= 1 }},
		{"ciphertext", func(r *Report) { r.Envelopes[0].Ciphertext[0] ^= 1 }},
		{"opening_key", func(r *Report) { r.Openings[0].Key[0] ^= 1 }},
		{"missing_admission", func(r *Report) { r.Admissions = r.Admissions[1:] }},
		{"missing_evidence", func(r *Report) { r.Audit.Evidence = r.Audit.Evidence[1:] }},
		{"wrong_service_item", func(r *Report) { r.ServiceRecords[0].Items[0] = r.ServiceRecords[1].Items[0] }},
		{"duplicate_release", func(r *Report) { r.Releases[1] = r.Releases[0] }},
		{"registration", func(r *Report) { r.Registrations[0].Items = []string{} }},
		{"early_open_event", func(r *Report) { r.Events[0].Kind = "decrypted" }},
		{"negative_time", func(r *Report) { r.Events[0].Time = -1 }},
		{"metrics", func(r *Report) { r.Metrics.Executed++ }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := cloneReport(base)
			c.change(&r)
			r.SemanticDigest = r.Semantic()
			if err := AuditReport(r); err == nil {
				t.Fatal("tampered artifact accepted")
			}
		})
	}
}
func TestDuplicateCorruptDrop(t *testing.T) {
	normal := run(t, "normal")
	for _, name := range []string{"duplicate", "corrupt", "drop"} {
		r := run(t, name)
		if digest(r.Results) != digest(normal.Results) || digest(r.Market) != digest(normal.Market) {
			t.Fatalf("%s changed market", name)
		}
		if len(r.Audit.Evidence) != 0 {
			t.Fatal("transport anomaly falsely blamed on node")
		}
		switch name {
		case "duplicate":
			if r.Metrics.Duplicates != 30 || len(r.Promises) != 15 {
				t.Fatal(r.Metrics)
			}
		case "corrupt":
			if r.Metrics.Invalid != 3 {
				t.Fatal(r.Metrics)
			}
		case "drop":
			if r.Metrics.Dropped != 3 {
				t.Fatal(r.Metrics)
			}
		}
	}
}
func TestPublicContextDoesNotCommitSecretOrders(t *testing.T) {
	c, _ := DefaultConfig("normal")
	a := ContextFor(c, "fixed-session")
	c.Orders[0].Order.Quantity = 999
	c.Omit = "node-1"
	if ContextFor(c, "fixed-session") != a {
		t.Fatal("secret workload or attack flags leaked into context")
	}
	c.Service++
	if ContextFor(c, "fixed-session") == a {
		t.Fatal("public policy not bound")
	}
}
func TestRejectVirtualTimeOverflow(t *testing.T) {
	c, _ := DefaultConfig("normal")
	c.Window = int(^uint(0) >> 1)
	if c.Validate() == nil {
		t.Fatal("huge window accepted")
	}
	c, _ = DefaultConfig("normal")
	c.Orders[0].Delays = []int{int(^uint(0) >> 1), 1, 1, 1, 1}
	if c.Validate() == nil {
		t.Fatal("overflowing delay accepted")
	}
}
func TestSealRejectsInvalidInputs(t *testing.T) {
	_, key, _ := newIdentity()
	o := Order{Owner: "alice", Nonce: 0}
	h := Header{Domain: Domain, Context: "ctx", Round: 1, Owner: "alice"}
	v := NewIdealVault(3)
	if _, err := v.Seal(h, o, []byte{1}); err == nil {
		t.Fatal("short key accepted")
	}
	h.Owner = "mallory"
	if _, err := v.Seal(h, o, key); err == nil {
		t.Fatal("owner mismatch accepted")
	}
}
func TestPinnedVaultMembers(t *testing.T) {
	pub, user, _ := newIdentity()
	users := map[string][]byte{"alice": pub}
	members := map[string][]byte{}
	private := map[string]ed25519.PrivateKey{}
	for _, id := range []string{"a", "b", "c", "d"} {
		p, k, _ := newIdentity()
		members[id] = p
		private[id] = k
	}
	v := NewIdealVault(3)
	e, err := v.Seal(Header{Domain: Domain, Context: "ctx", Round: 1, Owner: "alice"}, Order{Owner: "alice"}, user)
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
	if err = v.lock(lock, ids, members, 4); err != nil {
		t.Fatal(err)
	}
	replacement := map[string][]byte{}
	fake := []Statement{}
	for _, id := range []string{"a", "b", "c", "d"} {
		p, k, _ := newIdentity()
		replacement[id] = p
		fake = append(fake, statement(k, "ctx", "release", id, 1, []string{lock.Item}))
	}
	if _, err = v.Open(e, lock, fake, replacement, users, 3); err == nil {
		t.Fatal("replaced member keys accepted")
	}
	original := cloneKeys(members)
	members["a"][0] ^= 1
	if _, err = v.Open(e, lock, approvals, members, users, 3); err == nil {
		t.Fatal("mutable anchor alias accepted")
	}
	if _, err = v.Open(e, lock, approvals, original, users, 3); err != nil {
		t.Fatal(err)
	}
}

func TestAuditRejectsExecutionBeforeOpening(t *testing.T) {
	r := cloneReport(run(t, "normal"))
	execute, lock := -1, -1
	for i, e := range r.Events {
		if e.Order == "alice:0" && e.Kind == "service_locked" {
			lock = i
		}
		if e.Order == "alice:0" && e.Kind == "executed" {
			execute = i
		}
	}
	moved := r.Events[execute]
	r.Events = append(r.Events[:execute], r.Events[execute+1:]...)
	r.Events = append(r.Events[:lock], append([]Event{moved}, r.Events[lock:]...)...)
	r.SemanticDigest = r.Semantic()
	if AuditReport(r) == nil {
		t.Fatal("execution before opening accepted")
	}
}
