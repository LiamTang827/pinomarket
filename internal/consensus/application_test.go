package consensus

import (
	"context"
	"errors"
	"testing"

	abci "github.com/cometbft/cometbft/abci/types"
)

type testMachine struct {
	committed, pending int64
	proposalErr        error
	commitErr          error
}

func (m *testMachine) Info() (int64, []byte) { return m.committed, []byte{byte(m.committed)} }
func (m *testMachine) CheckTx(tx []byte) error {
	if string(tx) == "invalid" {
		return errors.New("invalid command")
	}
	return nil
}
func (m *testMachine) FinalizeBlock(h int64, txs [][]byte) ([]*abci.ExecTxResult, []byte, error) {
	m.pending = h
	results := make([]*abci.ExecTxResult, len(txs))
	for i, tx := range txs {
		results[i] = &abci.ExecTxResult{}
		if m.CheckTx(tx) != nil {
			results[i].Code = 1
		}
	}
	return results, []byte{byte(h)}, nil
}
func (m *testMachine) Commit() error {
	if m.commitErr != nil {
		return m.commitErr
	}
	m.committed = m.pending
	return nil
}
func (m *testMachine) ValidateProposal(int64, [][]byte) error { return m.proposalErr }

func TestAdapterCommitBoundaryAndInvalidResult(t *testing.T) {
	ctx := context.Background()
	m := &testMachine{}
	app := NewApplication(m)
	check, err := app.CheckTx(ctx, &abci.RequestCheckTx{Tx: []byte("invalid")})
	if err != nil || check.Code == 0 {
		t.Fatalf("invalid mempool admission: %+v, %v", check, err)
	}
	result, err := app.FinalizeBlock(ctx, &abci.RequestFinalizeBlock{Height: 1, Txs: [][]byte{[]byte("valid"), []byte("invalid")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.TxResults) != 2 || result.TxResults[0].Code != 0 || result.TxResults[1].Code != 1 {
		t.Fatalf("wrong execution results: %+v", result.TxResults)
	}
	info, err := app.Info(ctx, &abci.RequestInfo{})
	if err != nil || info.LastBlockHeight != 0 {
		t.Fatal("staged state was reported as committed")
	}
	if _, err := app.Commit(ctx, &abci.RequestCommit{}); err != nil {
		t.Fatal(err)
	}
	info, err = app.Info(ctx, &abci.RequestInfo{})
	if err != nil || info.LastBlockHeight != 1 {
		t.Fatal("committed state was not reported")
	}
	m.proposalErr = errors.New("bad signature")
	proposal, err := app.ProcessProposal(ctx, &abci.RequestProcessProposal{Height: 2})
	if err != nil || proposal.Status != abci.ResponseProcessProposal_REJECT {
		t.Fatal("invalid proposal accepted")
	}
	m.commitErr = errors.New("disk full")
	if _, err := app.Commit(ctx, &abci.RequestCommit{}); err == nil {
		t.Fatal("commit persistence failure was swallowed")
	}
}
