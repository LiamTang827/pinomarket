package consensus

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cometbft/cometbft/node"
	rpchttp "github.com/cometbft/cometbft/rpc/client/http"
	"github.com/cometbft/cometbft/types"
)

// Run explicitly when localhost networking is available:
// PINOCCHIO_CONSENSUS_INTEGRATION=1 go test ./internal/consensus -run TestFiveNodeConsensus -count=1 -timeout=60s
func TestFiveNodeConsensus(t *testing.T) {
	if os.Getenv("PINOCCHIO_CONSENSUS_INTEGRATION") != "1" {
		t.Skip("set PINOCCHIO_CONSENSUS_INTEGRATION=1 to run real localhost nodes")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	infos, err := InitWithOptions(filepath.Join(t.TempDir(), "network"), Options{Validators: 5, BasePort: 31656, BlockInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	nodes := make([]*node.Node, 5)
	defer func() {
		for _, n := range nodes {
			if n != nil && n.IsRunning() {
				_ = n.Stop()
				n.Wait()
			}
		}
	}()
	clients := make([]*rpchttp.HTTP, 5)
	for i, info := range infos {
		nodes[i], err = StartNode(info.Dir, NewApplication(&testMachine{}))
		if err != nil {
			t.Fatal(err)
		}
		clients[i], err = rpchttp.New(info.RPCAddress, "/websocket")
		if err != nil {
			t.Fatal(err)
		}
	}
	waitHeight := func(client *rpchttp.HTTP, want int64) {
		t.Helper()
		for {
			status, e := client.Status(ctx)
			if e == nil && status.SyncInfo.LatestBlockHeight >= want {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatalf("did not reach height %d: %v", want, ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	for _, client := range clients {
		waitHeight(client, 2)
	}
	if err := nodes[4].Stop(); err != nil {
		t.Fatal(err)
	}
	nodes[4].Wait()
	result, err := clients[0].BroadcastTxCommit(ctx, types.Tx("valid-after-one-stop"))
	if err != nil {
		t.Fatal(err)
	}
	if result.CheckTx.Code != 0 || result.TxResult.Code != 0 {
		t.Fatalf("transaction rejected: %+v", result)
	}
	commit, err := clients[0].Commit(ctx, &result.Height)
	if err != nil {
		t.Fatal(err)
	}
	var signed int
	for _, sig := range commit.Commit.Signatures {
		if sig.BlockIDFlag == types.BlockIDFlagCommit {
			signed++
		}
	}
	if signed < 4 {
		t.Fatalf("only %d commit signatures", signed)
	}
	for _, client := range clients[:4] {
		waitHeight(client, result.Height+2)
	}
	t.Logf("five real CometBFT validators finalized height %d with %d signatures after one node stopped", result.Height, signed)
}
