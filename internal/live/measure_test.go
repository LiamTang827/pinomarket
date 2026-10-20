package live

import (
	"testing"

	"github.com/LiamTang827/pinocchio-market/protocol"
	"github.com/LiamTang827/pinocchio-market/threshold"
)

func TestMeasurementRetainsIncompleteAndFailedBusinessOrders(t *testing.T) {
	m := Measurement{Policy: Policy{Threshold: 3}, DurationMS: 1000, Orders: []MeasuredOrder{{ID: "a", Ref: "alice:0", SubmitMS: 10, Quorum: true}, {ID: "b", Ref: "bob:0", SubmitMS: 20}, {ID: "c", Ref: "carol:0", SubmitMS: 30}}}
	s := &State{Orders: map[string]Packet{"a": {}, "b": {}}, Services: []Lock{{Items: []string{"a", "b"}, Shares: map[string][]threshold.DecryptionShare{"a": {{}, {}, {}}, "b": {{}, {}, {}}}}}, Results: []protocol.Result{{Order: "alice:0", Status: "filled", Filled: 1}, {Order: "bob:0", Status: "no_inventory"}}}
	m.observe(s, 110)
	m.observe(s, 210)
	m.summarize()
	if m.Submitted != 3 || m.Admitted != 1 || m.Registered != 2 || m.Processed != 2 || m.Filled != 1 || m.Incomplete != 1 {
		t.Fatalf("wrong denominator: %+v", m)
	}
	if *m.Orders[0].RegisteredMS != 110 || *m.Orders[0].ProcessedMS != 110 || m.Orders[2].ProcessedMS != nil {
		t.Fatal("overwrote first observation or invented completion")
	}
	if m.CompletionMS["p50"] != 90 || m.CompletionMS["p95"] != 100 || m.ProcessedTPS != 2 {
		t.Fatalf("wrong quantiles: %+v", m)
	}
}

func TestMeasurementEmptyCompletionsDoesNotInventPercentiles(t *testing.T) {
	m := Measurement{Orders: []MeasuredOrder{{ID: "pending", Ref: "alice:0"}}}
	m.summarize()
	if m.Incomplete != 1 || len(m.CompletionMS) != 0 || m.ProcessedTPS != 0 {
		t.Fatalf("invented measured samples: %+v", m)
	}
}

func TestMeasurementDoesNotCountAnOldResultForAConflictingPacket(t *testing.T) {
	m := Measurement{Orders: []MeasuredOrder{{ID: "new-ciphertext", Ref: "alice:0"}}}
	m.observe(&State{Orders: map[string]Packet{"old-ciphertext": {}}, Results: []protocol.Result{{Order: "alice:0", Status: "filled", Filled: 1}}}, 10)
	m.summarize()
	if m.Processed != 0 || m.Filled != 0 || m.Orders[0].Result != nil {
		t.Fatal("counted old owner/nonce result as new completion")
	}
}
