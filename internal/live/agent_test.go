package live

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAgentDecisionPhaseValidation(t *testing.T) {
	tests := []struct {
		phase, action string
		delay         int
		ok            bool
	}{
		{"admission", "normal", 0, true}, {"admission", "refuse", 0, true}, {"admission", "delay", 1500, true}, {"admission", "reverse_sequence", 0, false},
		{"seal", "omit", 0, true}, {"shares", "withhold", 0, true}, {"seal", "normal", 0, true}, {"shares", "normal", 0, true},
		{"admission", "omit", 0, false}, {"seal", "withhold", 0, false}, {"shares", "reverse_sequence", 0, false}, {"admission", "delay", 1501, false}, {"admission", "refuse", 1, false}, {"unknown", "normal", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.phase+"/"+tt.action, func(t *testing.T) {
			if got := (AgentDecision{Action: tt.action, DelayMS: tt.delay}.validate(tt.phase) == nil); got != tt.ok {
				t.Fatalf("valid=%v want%v", got, tt.ok)
			}
		})
	}
}

func agentTestServer(t *testing.T, body string, calls *atomic.Int32) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "pma-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "a.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/decide" || r.Method != "POST" {
			t.Error("wrong endpoint")
		}
		if calls != nil {
			calls.Add(1)
		}
		io.WriteString(w, body)
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return socket
}

func TestAgentStrictResponseAndCache(t *testing.T) {
	for _, body := range []string{`{"action":"normal","delay_ms":0}`, `{"action":"normal"}`, `{"action":"normal","delay_ms":0,"key":"bad"}`, `{"action":"omit","delay_ms":0}`, `{"action":"normal","delay_ms":0} {}`, strings.Repeat("x", 4097)} {
		t.Run(body[:min(len(body), 50)], func(t *testing.T) {
			var calls atomic.Int32
			socket := agentTestServer(t, body, &calls)
			a, err := newNodeAgent(socket)
			if err != nil {
				t.Fatal(err)
			}
			o := AgentObservation{Phase: "admission", Node: "node-1"}
			_, err = a.decide(context.Background(), "same", o)
			good := body == `{"action":"normal","delay_ms":0}`
			if (err == nil) != good {
				t.Fatalf("error=%v valid=%v", err, good)
			}
			if good {
				if _, err = a.decide(context.Background(), "same", o); err != nil {
					t.Fatal(err)
				}
				if calls.Load() != 1 {
					t.Fatal("retry invoked agent twice")
				}
			}
		})
	}
	if _, err := newNodeAgent("relative.sock"); err == nil {
		t.Fatal("relative socket accepted")
	}
}

func TestAgentPublicObservationAndDurableAdmission(t *testing.T) {
	f := newLiveTestFixture(t)
	s := NewState(f.manifest)
	s.Round = &Round{Number: 1, OpenHeight: 1, CloseHeight: 10, Capacity: 2}
	s.Height = 2
	n := &liveNode{cfg: NodeConfig{Manifest: f.manifest, Index: 0}, peer: f.manifest.Peers[0], private: f.nodes[0], machine: &Machine{state: s}, journalPath: filepath.Join(t.TempDir(), "journal.json"), journal: admissionJournal{Context: f.manifest.Context, Node: f.manifest.Peers[0].ID, Rounds: map[int]*admissionRound{}, Receipts: map[string]Gossip{}, Lists: map[string]FinalList{}}}
	alice := f.packet(t, 1, "alice", 0)
	bob := f.packet(t, 1, "bob", 0)
	p1, err := n.accept(alice)
	if err != nil {
		t.Fatal(err)
	}
	_, err = n.accept(bob)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := n.accept(alice)
	if err != nil || Hash(retry) != Hash(p1) {
		t.Fatal("retry changed promise", err)
	}
	observation := n.agentObservation("admission", &alice, nil)
	raw := string(JSON(observation))
	for _, secret := range []string{"signature", "wrapped", "private", "quantity", "limit", "shares", "body"} {
		if strings.Contains(raw, `"`+secret+`"`) {
			t.Fatalf("secret field %s", secret)
		}
	}
	var fields map[string]any
	if err = json.Unmarshal([]byte(raw), &fields); err != nil {
		t.Fatal(err)
	}
	if len(observation.Accepted) != 2 || observation.Packet.Owner != "alice" || observation.Packet.CiphertextBytes <= 0 {
		t.Fatal("missing public observation")
	}
	list, err := n.seal(s.Round)
	if err != nil {
		t.Fatal(err)
	}
	if err = list.Validate(f.manifest, 2); err != nil {
		t.Fatal(err)
	}
	if err = n.loadJournal(); err != nil {
		t.Fatalf("valid promises failed durable restart: %v", err)
	}
}

func TestVerifyReceiptAuthenticatesPartialAndRejectsConflicts(t *testing.T) {
	f := newLiveTestFixture(t)
	packet := f.packet(t, 1, "alice", 0)
	promises := []Promise{}
	for i := 0; i < 3; i++ {
		promises = append(promises, NewPromise(f.manifest, f.manifest.Peers[i].ID, 1, packet.ID(), f.nodes[i]))
	}
	for _, count := range []int{0, 1, 3} {
		got, err := VerifyReceipt(f.manifest, SubmissionReceipt{Packet: packet, Promises: promises[:count]})
		if err != nil || got != count {
			t.Fatalf("partial/quorum count%d got%d error%v", count, got, err)
		}
	}
	duplicate := append(append([]Promise{}, promises...), promises[0])
	if _, err := VerifyReceipt(f.manifest, SubmissionReceipt{Packet: packet, Promises: duplicate}); err == nil {
		t.Fatal("duplicate member accepted")
	}
	wrongID := NewPromise(f.manifest, f.manifest.Peers[0].ID, 1, "other-packet", f.nodes[0])
	wrongRound := NewPromise(f.manifest, f.manifest.Peers[0].ID, 2, packet.ID(), f.nodes[0])
	badSignature := promises[0]
	badSignature.Signature = append([]byte{}, badSignature.Signature...)
	badSignature.Signature[0] ^= 1
	for _, promise := range []Promise{wrongID, wrongRound, badSignature} {
		if _, err := VerifyReceipt(f.manifest, SubmissionReceipt{Packet: packet, Promises: []Promise{promise}}); err == nil {
			t.Fatal("invalid promise accepted")
		}
	}
	packet.Signature = append([]byte{}, packet.Signature...)
	packet.Signature[0] ^= 1
	if _, err := VerifyReceipt(f.manifest, SubmissionReceipt{Packet: packet}); err == nil {
		t.Fatal("invalid packet accepted")
	}
}
