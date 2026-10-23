package live

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestAgentGranularChoiceBounds(t *testing.T) {
	tests := []struct {
		phase, body string
		valid       bool
	}{
		{"admission", `{"action":"sequence","delay_ms":0,"sequence":2}`, false},
		{"admission", `{"action":"normal","delay_ms":0,"sequence":0}`, false},
		{"seal", `{"action":"select","delay_ms":0,"include_ids":["own"]}`, true},
		{"seal", `{"action":"select","delay_ms":0,"include_ids":[]}`, true},
		{"seal", `{"action":"select","delay_ms":0,"include_ids":null}`, false},
		{"seal", `{"action":"select","delay_ms":0}`, false},
		{"seal", `{"action":"select","delay_ms":0,"include_ids":["unknown"]}`, false},
		{"seal", `{"action":"select","delay_ms":0,"include_ids":["own","own"]}`, false},
		{"shares", `{"action":"select","delay_ms":0,"include_ids":[]}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			a, err := newNodeAgent(agentTestServer(t, tt.body, nil), 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			o := AgentObservation{Phase: tt.phase, Node: "node-1", Capacity: 4, Accepted: []AgentPacket{{ID: "own"}}}
			_, err = a.decide(context.Background(), "once", o)
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v error=%v", tt.valid, err)
			}
		})
	}
	for _, timeout := range []time.Duration{0, -time.Second, 56 * time.Second} {
		if _, err := newNodeAgent("/tmp/unused.sock", timeout); err == nil {
			t.Fatalf("invalid timeout %v accepted", timeout)
		}
	}
}

func TestAgentPreparedSealIncludesLaterAdmissions(t *testing.T) {
	f := newLiveTestFixture(t)
	s := NewState(f.manifest)
	s.Round = &Round{Number: 1, OpenHeight: 1, CloseHeight: 10, Capacity: 2}
	s.Height = 2
	var calls atomic.Int32
	a, err := newNodeAgent(agentTestServer(t, `{"action":"select","delay_ms":0,"include_ids":[]}`, &calls))
	if err != nil {
		t.Fatal(err)
	}
	n := &liveNode{cfg: NodeConfig{Manifest: f.manifest, Index: 0}, peer: f.manifest.Peers[0], private: f.nodes[0], machine: &Machine{state: s}, agent: a, journalPath: filepath.Join(t.TempDir(), "journal.json"), journal: admissionJournal{Context: f.manifest.Context, Node: f.manifest.Peers[0].ID, Rounds: map[int]*admissionRound{}, Receipts: map[string]Gossip{}, Lists: map[string]FinalList{}}}
	alice := f.packet(t, 1, "alice", 0)
	bob := f.packet(t, 1, "bob", 0)
	alicePromise, err := n.accept(alice)
	if err != nil {
		t.Fatal(err)
	}
	a.prepare(context.Background(), "seal:1", n.agentObservation("seal", nil, s))
	// Same-key request joins the prepared decision, without a second model call.
	if _, err = n.decideAgent(context.Background(), "seal", nil, s); err != nil {
		t.Fatal(err)
	}
	if _, err = n.accept(bob); err != nil {
		t.Fatal(err)
	}
	list, err := n.seal(s.Round)
	if err != nil {
		t.Fatal(err)
	}
	if list.Has(alice.ID()) || !list.Has(bob.ID()) || len(list.Packets) != 1 {
		t.Fatal("stale prepared list omitted a later admission or retained omitted snapshot item")
	}
	if err = (Evidence{Promise: alicePromise, List: list}).Validate(f.manifest); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("prepared decision called model %d times", calls.Load())
	}
	if err = n.loadJournal(); err != nil {
		t.Fatal("promises did not survive restart", err)
	}
}
