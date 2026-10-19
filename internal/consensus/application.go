// Package consensus connects a deterministic application to CometBFT's actual
// Byzantine consensus engine. It never decides or fabricates consensus itself.
package consensus

import (
	"context"
	"fmt"
	"sync"

	abci "github.com/cometbft/cometbft/abci/types"
)

// Machine supplies deterministic application logic. FinalizeBlock stages the
// next state and computes its hash; Commit durably persists that staged state.
// Info must describe only the last durably committed state, so CometBFT can
// replay a decided block after a crash between consensus and application commit.
// Methods must not depend on wall clocks, random numbers, or local node identity.
type Machine interface {
	Info() (height int64, appHash []byte)
	CheckTx(tx []byte) error
	FinalizeBlock(height int64, txs [][]byte) (results []*abci.ExecTxResult, appHash []byte, err error)
	Commit() error
}

// ProposalValidator optionally checks an entire proposed transaction sequence
// against a disposable state copy, without mutating the committed or staged state.
// Invalid application commands may alternatively be finalized as failed txs.
type ProposalValidator interface {
	ValidateProposal(height int64, txs [][]byte) error
}

// Querier optionally exposes application state using CometBFT's ABCI query RPC.
type Querier interface {
	Query(path string, data []byte) ([]byte, error)
}

// Application implements ABCI++. CometBFT owns proposer selection, signatures,
// voting rounds, block locks, WAL, peer networking, commit and block storage.
type Application struct {
	abci.BaseApplication
	mu      sync.Mutex
	machine Machine
}

var _ abci.Application = (*Application)(nil)

func NewApplication(machine Machine) *Application {
	return &Application{machine: machine}
}

func (a *Application) Info(context.Context, *abci.RequestInfo) (*abci.ResponseInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	height, hash := a.machine.Info()
	return &abci.ResponseInfo{Data: "pinocchio-market", Version: "0.3.0", AppVersion: 3, LastBlockHeight: height, LastBlockAppHash: append([]byte(nil), hash...)}, nil
}

// InitChain binds the genesis application hash to the deterministic initial
// state. The genesis validator set is retained by returning no validator updates.
func (a *Application) InitChain(context.Context, *abci.RequestInitChain) (*abci.ResponseInitChain, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, hash := a.machine.Info()
	return &abci.ResponseInitChain{AppHash: append([]byte(nil), hash...)}, nil
}

func (a *Application) CheckTx(_ context.Context, req *abci.RequestCheckTx) (*abci.ResponseCheckTx, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.machine.CheckTx(req.Tx); err != nil {
		return &abci.ResponseCheckTx{Code: 1, Log: err.Error(), Codespace: "pinocchio"}, nil
	}
	return &abci.ResponseCheckTx{Code: abci.CodeTypeOK}, nil
}

func (a *Application) ProcessProposal(_ context.Context, req *abci.RequestProcessProposal) (*abci.ResponseProcessProposal, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if validator, ok := a.machine.(ProposalValidator); ok {
		if err := validator.ValidateProposal(req.Height, req.Txs); err != nil {
			return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_REJECT}, nil
		}
	}
	return &abci.ResponseProcessProposal{Status: abci.ResponseProcessProposal_ACCEPT}, nil
}

func (a *Application) FinalizeBlock(_ context.Context, req *abci.RequestFinalizeBlock) (*abci.ResponseFinalizeBlock, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	results, hash, err := a.machine.FinalizeBlock(req.Height, req.Txs)
	if err != nil {
		return nil, err
	}
	if len(results) != len(req.Txs) {
		return nil, fmt.Errorf("machine returned %d transaction results for %d transactions", len(results), len(req.Txs))
	}
	for i, result := range results {
		if result == nil {
			return nil, fmt.Errorf("machine returned nil transaction result %d", i)
		}
	}
	return &abci.ResponseFinalizeBlock{TxResults: results, AppHash: append([]byte(nil), hash...)}, nil
}

func (a *Application) Commit(context.Context, *abci.RequestCommit) (*abci.ResponseCommit, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.machine.Commit(); err != nil {
		return nil, err
	}
	return &abci.ResponseCommit{}, nil
}

func (a *Application) Query(_ context.Context, req *abci.RequestQuery) (*abci.ResponseQuery, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	height, _ := a.machine.Info()
	querier, ok := a.machine.(Querier)
	if !ok {
		return &abci.ResponseQuery{Code: 1, Log: "application queries are unavailable", Height: height}, nil
	}
	value, err := querier.Query(req.Path, req.Data)
	if err != nil {
		return &abci.ResponseQuery{Code: 1, Log: err.Error(), Height: height}, nil
	}
	return &abci.ResponseQuery{Code: abci.CodeTypeOK, Value: value, Height: height}, nil
}
