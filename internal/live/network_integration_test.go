package live

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/LiamTang827/pinocchio-market/protocol"
)

const liveHelperConfigEnv = "PINOCCHIO_LIVE_HELPER_CONFIG"
const liveHelperOptionsEnv = "PINOCCHIO_LIVE_HELPER_OPTIONS"

// TestLiveNodeHelper is selected only in a child copy of the Go test binary.
// Each child owns one independent CometBFT home, admission journal, signing key
// and threshold share. No parent-side coordinator orders protocol transactions.
func TestLiveNodeHelper(t *testing.T) {
	path := os.Getenv(liveHelperConfigEnv)
	if path == "" {
		t.Skip("node helper is run only as a child process")
	}
	var cfg NodeConfig
	if err := ReadJSON(path, &cfg); err != nil {
		t.Fatal(err)
	}
	var options NodeOptions
	if err := json.Unmarshal([]byte(os.Getenv(liveHelperOptionsEnv)), &options); err != nil {
		t.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := RunNode(ctx, cfg, options); err != nil {
		t.Fatal(err)
	}
}

type liveChild struct {
	cmd     *exec.Cmd
	done    chan struct{}
	err     error // Written before closing done; read only after done is closed.
	logPath string
}

func startLiveChild(t *testing.T, dir string, index, generation int, options NodeOptions) *liveChild {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, fmt.Sprintf("node%d-process%d.log", index, generation))
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestLiveNodeHelper$", "-test.timeout=150s", "-test.v")
	cmd.Env = append(os.Environ(), liveHelperConfigEnv+"="+filepath.Join(dir, fmt.Sprintf("node%d.json", index)), liveHelperOptionsEnv+"="+string(JSON(options)))
	cmd.Stdout, cmd.Stderr = log, log
	child := &liveChild{cmd: cmd, done: make(chan struct{}), logPath: logPath}
	if err := cmd.Start(); err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	go func() {
		child.err = cmd.Wait()
		_ = log.Close()
		close(child.done)
	}()
	return child
}

func stopLiveChild(t *testing.T, child *liveChild) {
	t.Helper()
	select {
	case <-child.done:
		if child.err != nil {
			t.Fatalf("node process already failed: %v (log %s)", child.err, child.logPath)
		}
		return
	default:
	}
	if err := child.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal node process: %v", err)
	}
	select {
	case <-child.done:
		if child.err != nil {
			t.Fatalf("node process did not shut down cleanly: %v (log %s)", child.err, child.logPath)
		}
	case <-time.After(8 * time.Second):
		_ = child.cmd.Process.Kill()
		<-child.done
		t.Fatalf("node process ignored SIGTERM (log %s)", child.logPath)
	}
}

func liveEventually(t *testing.T, ctx context.Context, description string, condition func() bool) {
	t.Helper()
	for {
		if condition() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for %s: %v", description, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func peerState(ctx context.Context, peer Peer) (*State, error) {
	requestCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var s State
	if err := RequestJSON(requestCtx, "GET", peer.API+"/state", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Run explicitly with localhost listen permissions:
// PINOCCHIO_LIVE_INTEGRATION=1 go test ./internal/live -run '^TestLiveNetworkProcessesRestartAndOmission$' -count=1 -timeout=150s -v
func TestLiveNetworkProcessesRestartAndOmission(t *testing.T) {
	if os.Getenv("PINOCCHIO_LIVE_INTEGRATION") != "1" {
		t.Skip("set PINOCCHIO_LIVE_INTEGRATION=1 to run five real OS validator processes")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	dir := t.TempDir()
	manifest, err := InitNetwork(dir, InitOptions{Nodes: 5, Threshold: 3, QueueCapacity: 30, ServiceCapacity: 2, BasePort: 34656, APIPort: 35600, WindowBlocks: 20, BlockInterval: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	children := []*liveChild{}
	// Signal only the child processes created by this test. Signal all first,
	// then wait, so cleanup cannot strand a still-running validator network.
	t.Cleanup(func() {
		for _, child := range children {
			select {
			case <-child.done:
			default:
				_ = child.cmd.Process.Signal(syscall.SIGTERM)
			}
		}
		for _, child := range children {
			select {
			case <-child.done:
			case <-time.After(8 * time.Second):
				_ = child.cmd.Process.Kill()
				<-child.done
			}
			if t.Failed() {
				log, _ := os.ReadFile(child.logPath)
				if len(log) > 16000 {
					log = log[len(log)-16000:]
				}
				t.Logf("child log %s:\n%s", child.logPath, log)
			}
		}
	})
	nodes := make([]*liveChild, 5)
	generation := make([]int, 5)
	start := func(index int, options NodeOptions) {
		nodes[index] = startLiveChild(t, dir, index, generation[index], options)
		generation[index]++
		children = append(children, nodes[index])
	}
	waitHealth := func(index int, minHeight int64) {
		t.Helper()
		liveEventually(t, ctx, fmt.Sprintf("node%d health at height %d", index, minHeight), func() bool {
			select {
			case <-nodes[index].done:
				t.Fatalf("node%d exited: %v (log %s)", index, nodes[index].err, nodes[index].logPath)
			default:
			}
			requestCtx, requestCancel := context.WithTimeout(ctx, time.Second)
			defer requestCancel()
			var health struct {
				OK     bool  `json:"ok"`
				Height int64 `json:"height"`
			}
			err := RequestJSON(requestCtx, "GET", manifest.Peers[index].API+"/health", nil, &health)
			return err == nil && health.OK && health.Height >= minHeight
		})
	}
	for index := range nodes {
		start(index, NodeOptions{})
	}
	for index := range nodes {
		waitHealth(index, 2)
	}
	stopLiveChild(t, nodes[4])

	openRound := func() *Round {
		t.Helper()
		round, err := OpenRound(ctx, manifest)
		if err != nil {
			t.Fatal(err)
		}
		for index := 0; index < 4; index++ {
			liveEventually(t, ctx, fmt.Sprintf("node%d committed admission round %d", index, round.Number), func() bool {
				s, e := peerState(ctx, manifest.Peers[index])
				return e == nil && s.Round != nil && s.Round.Number == round.Number && !s.Round.Registered && s.Height < s.Round.CloseHeight
			})
		}
		return round
	}
	packet := func(round int, owner string, nonce int, quantity int64) Packet {
		t.Helper()
		var rawKey []byte
		if err := ReadJSON(filepath.Join(dir, "wallets", owner+".json"), &rawKey); err != nil {
			t.Fatal(err)
		}
		p, err := NewPacket(manifest, round, protocol.Order{Owner: owner, Nonce: nonce, Kind: "buy", Listing: "yes-1", Quantity: quantity, Limit: 60}, ed25519.PrivateKey(rawKey))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	submit := func(p Packet) SubmissionReceipt {
		t.Helper()
		receipt, err := SubmitPacket(ctx, manifest, p)
		if err != nil {
			t.Fatal(err)
		}
		if !receipt.Quorum || len(receipt.Promises) != 4 {
			t.Fatalf("expected four independent signed promises, got %d (errors %v)", len(receipt.Promises), receipt.Errors)
		}
		return receipt
	}
	round := openRound()
	packets := []Packet{packet(round.Number, "alice", 0, 4), packet(round.Number, "bob", 0, 3), packet(round.Number, "carol", 0, 3)}
	receipts := make([]SubmissionReceipt, 0, len(packets))
	for _, p := range packets {
		receipts = append(receipts, submit(p))
	}

	// Restart a receipt signer after it replied but before it has finalized its
	// round list. The identical signed promise must survive its process death.
	beforeRestart, err := peerState(ctx, manifest.Peers[1])
	if err != nil || beforeRestart.Round == nil || beforeRestart.Height >= beforeRestart.Round.CloseHeight || beforeRestart.Round.HasList(manifest.Peers[1].ID) {
		t.Fatalf("receipt-signing restart missed the admission window: state=%v error=%v", beforeRestart, err)
	}
	stopLiveChild(t, nodes[1])
	start(1, NodeOptions{})
	waitHealth(1, beforeRestart.Height)
	var repeated Promise
	if err := RequestJSON(ctx, "POST", manifest.Peers[1].API+"/submit", packets[0], &repeated); err != nil {
		t.Fatalf("replay durable promise after restart: %v", err)
	}
	var original *Promise
	for i := range receipts[0].Promises {
		if receipts[0].Promises[i].Node == manifest.Peers[1].ID {
			original = &receipts[0].Promises[i]
		}
	}
	if original == nil || !bytes.Equal(JSON(original), JSON(repeated)) {
		t.Fatal("receipt signer lost or changed its durable signed promise")
	}

	var completed *State
	liveEventually(t, ctx, "three FIFO results with one validator offline", func() bool {
		s, e := peerState(ctx, manifest.Peers[0])
		if e == nil {
			completed = s
		}
		return e == nil && len(s.Results) == 3 && s.Active == nil && len(s.Queue) == 0
	})
	if len(completed.Services) != 2 || len(completed.Openings) != 3 || completed.Market.Inventory != 0 || completed.Market.Cash["seller"] != 600 {
		t.Fatalf("unexpected completed FIFO/accounting state: %s", JSON(completed))
	}
	for _, result := range completed.Results {
		if result.Status != "filled" || result.Filled == 0 {
			t.Fatalf("expected all initial orders filled: %+v", result)
		}
	}
	for owner, want := range map[string]int64{"alice": 4, "bob": 3, "carol": 3} {
		if completed.Market.Shares[owner] != want || completed.Market.Cash[owner] != 1000-want*60 {
			t.Fatalf("wrong %s balance after deterministic execution", owner)
		}
	}
	audit, err := AuditNetwork(ctx, manifest)
	if err != nil {
		t.Fatalf("public consensus/replay/threshold/accounting audit: %v", err)
	}
	if signers, ok := audit["commit_signatures"].(int); !ok || signers < 4 {
		t.Fatalf("missing four real commit signatures: %v", audit)
	}
	t.Logf("one validator offline: %s", JSON(audit))

	// The fifth process resumes its original block DB, WAL and signing state,
	// then catches up by replay. No result or market transfer may execute twice.
	start(4, NodeOptions{})
	waitHealth(4, completed.Height)
	liveEventually(t, ctx, "restarted offline validator catches up without duplicate execution", func() bool {
		s, e := peerState(ctx, manifest.Peers[4])
		return e == nil && s.Height >= completed.Height && len(s.Results) == 3 && s.Active == nil && len(s.Queue) == 0 && Hash(s.Market) == Hash(completed.Market) && Hash(s.Results) == Hash(completed.Results) && Hash(s.Services) == Hash(completed.Services)
	})
	stableHeight := completed.Height + 2
	waitHealth(4, stableHeight)
	restarted, err := peerState(ctx, manifest.Peers[4])
	if err != nil || len(restarted.Results) != 3 || Hash(restarted.Market) != Hash(completed.Market) {
		t.Fatal("offline restart duplicated a result or market transfer")
	}

	// Force the omitting node's final list into the required four-node quorum.
	// It still returns an admission promise, which contradicts its empty list.
	stopLiveChild(t, nodes[0])
	start(0, NodeOptions{OmitList: true})
	waitHealth(0, restarted.Height)
	stopLiveChild(t, nodes[4])
	round = openRound()
	if round.Number != 2 {
		t.Fatalf("expected second live admission round, got %d", round.Number)
	}
	submit(packet(round.Number, "alice", 1, 1))
	var withEvidence *State
	liveEventually(t, ctx, "signed omission contradiction and second-round execution", func() bool {
		s, e := peerState(ctx, manifest.Peers[1])
		if e == nil {
			withEvidence = s
		}
		return e == nil && len(s.Results) == 4 && len(s.Evidence) > 0 && s.Active == nil && len(s.Queue) == 0
	})
	if withEvidence.Results[3].Order != "alice:1" || withEvidence.Results[3].Status != "no_inventory" || Hash(withEvidence.Market) != Hash(completed.Market) {
		t.Fatal("second-round no-inventory order changed market balances")
	}
	found := false
	for _, evidence := range withEvidence.Evidence {
		if err := evidence.Validate(manifest); err != nil {
			t.Fatalf("invalid public omission evidence: %v", err)
		}
		if evidence.Promise.Node == manifest.Peers[0].ID && evidence.Promise.Round == 2 {
			found = true
		}
	}
	if !found {
		t.Fatal("no signed contradiction for the deliberately omitting node")
	}
	audit, err = AuditNetwork(ctx, manifest)
	if err != nil {
		t.Fatalf("public audit after omission and second-round execution: %v", err)
	}
	if signers, ok := audit["commit_signatures"].(int); !ok || signers < 4 {
		t.Fatalf("second-round finality lacks four signatures: %v", audit)
	}
	if processed, ok := audit["processed"].(int); !ok || processed != 4 {
		t.Fatalf("audit did not authenticate exactly four results: %v", audit)
	}
	t.Logf("process restarts, two admission rounds and signed omission evidence: %s", JSON(audit))
	if ctx.Err() != nil {
		t.Fatal(ctx.Err())
	}
	// Assert helpers did not quietly exit while the test merely read old files.
	for _, index := range []int{0, 1, 2, 3} {
		select {
		case <-nodes[index].done:
			t.Fatalf("active node%d exited: %v", index, nodes[index].err)
		default:
		}
	}
}
