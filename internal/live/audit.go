package live

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/LiamTang827/pinomarket/threshold"
	"sort"
	"time"

	"github.com/LiamTang827/pinomarket/protocol"
	cmed "github.com/cometbft/cometbft/crypto/ed25519"
	rpchttp "github.com/cometbft/cometbft/rpc/client/http"
	cmtypes "github.com/cometbft/cometbft/types"
)

// AuditState independently verifies completed services and accounting, without
// any private keys. Comet commit verification is performed separately below.
func AuditState(m Manifest, s *State) error {
	if s == nil || s.Context != m.Context {
		return errors.New("state/context mismatch")
	}
	if err := m.Validate(); err != nil {
		return err
	}
	expectedQueue := []string{}
	lastHeight := int64(0)
	registered := map[string]bool{}
	refs := map[string]bool{}
	for _, r := range s.Registrations {
		if r.Height < lastHeight || len(r.Lists) != m.Policy.Quorum {
			return errors.New("invalid registration record")
		}
		lastHeight = r.Height
		nodes := map[string]bool{}
		for _, list := range r.Lists {
			if list.Round != r.Round || nodes[list.Node] {
				return errors.New("invalid selected list membership")
			}
			nodes[list.Node] = true
			if err := list.Validate(m, m.Policy.QueueCapacity); err != nil {
				return err
			}
		}
		if err := auditRegistrationOrder(m, r, refs); err != nil {
			return err
		}
		for _, id := range r.Items {
			p, ok := s.Orders[id]
			if !ok || p.ID() != id || p.Header.Round != r.Round || registered[id] || refs[p.Ref()] {
				return errors.New("invalid registered order")
			}
			if err := p.Validate(m); err != nil {
				return err
			}
			registered[id] = true
			refs[p.Ref()] = true
			expectedQueue = append(expectedQueue, id)
		}
	}
	resultIndex := 0
	openingIndex := 0
	orders := []protocol.Order{}
	results := []protocol.Result{}
	for i, lock := range s.Services {
		if lock.Number != i+1 || len(lock.Items) == 0 || len(lock.Items) > m.Policy.ServiceCapacity || len(lock.Items) > len(expectedQueue) {
			return errors.New("invalid completed service")
		}
		expectedID := Hash(struct {
			Context string
			Number  int
			Items   []string
		}{m.Context, lock.Number, lock.Items})
		if lock.ID != expectedID {
			return errors.New("service ID mismatch")
		}
		for j, id := range lock.Items {
			if expectedQueue[j] != id || resultIndex >= len(s.Results) {
				return errors.New("service FIFO/result mismatch")
			}
			p := s.Orders[id]
			if len(lock.Shares[id]) < m.Policy.Threshold {
				return errors.New("missing threshold shares")
			}
			// Decrypt verifies share pairing and distinct indices, ciphertext integrity,
			// AES authentication and the client's inner authorization.
			shares := appendSharesSorted(lock.Shares[id])
			opened, err := OpenPacket(m, p, shares)
			result := s.Results[resultIndex]
			resultIndex++
			if err != nil {
				if result.Order != p.Ref() || result.Status != "invalid_encrypted_payload" || result.Filled != 0 || result.Cost != 0 {
					return errors.New("bad encrypted payload not recorded deterministically")
				}
				continue
			}
			if openingIndex >= len(s.Openings) || Hash(opened) != Hash(s.Openings[openingIndex]) {
				return errors.New("published opening mismatch")
			}
			openingIndex++
			orders = append(orders, opened.Order)
			results = append(results, result)
		}
		expectedQueue = expectedQueue[len(lock.Items):]
	}
	if resultIndex != len(s.Results) || openingIndex != len(s.Openings) || !equalStrings(expectedQueue, s.Queue) {
		return errors.New("extra results/openings or queue mismatch")
	}
	if err := protocol.AuditMarket(orders, results, nil, s.Market); err != nil {
		return err
	}
	for _, e := range s.Evidence {
		if err := e.Validate(m); err != nil {
			return err
		}
	}
	return nil
}
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// AuditNetwork replays the real committed block log, then checks a signed
// CometBFT header that binds the resulting application hash. Genesis validator
// keys and the network manifest remain the externally supplied trust anchors.
func AuditNetwork(ctx context.Context, m Manifest) (map[string]any, error) {
	var client *rpchttp.HTTP
	var snapshot *State
	var last error
	for _, p := range m.Peers {
		c, e := rpchttp.New(p.RPC, "/websocket")
		if e != nil {
			last = e
			continue
		}
		query, e := c.ABCIQuery(ctx, "/state", nil)
		if e != nil {
			last = e
			continue
		}
		var state State
		if e = json.Unmarshal(query.Response.Value, &state); e != nil {
			last = e
			continue
		}
		// A restarted first peer may be healthy but still behind another peer.
		// Select the freshest responsive committed snapshot, then authenticate it
		// by replay and validator signatures below; height alone is not trusted.
		if snapshot == nil || state.Height > snapshot.Height {
			client = c
			snapshot = &state
		}
	}
	if client == nil {
		return nil, fmt.Errorf("no responsive validator RPC: %v", last)
	}
	if err := AuditState(m, snapshot); err != nil {
		return nil, err
	}
	replay := NewState(m)
	for height := int64(1); height <= snapshot.Height; height++ {
		block, err := client.Block(ctx, &height)
		if err != nil {
			return nil, err
		}
		for _, raw := range block.Block.Txs {
			tx, e := ParseTx(m, raw)
			next := replay.Clone()
			if e == nil {
				e = next.Apply(m, tx, height)
			}
			if e == nil {
				replay = next
			}
		}
		replay.Height = height
	}
	if Hash(replay) != Hash(snapshot) {
		return nil, errors.New("committed block replay disagrees with state")
	}
	// Header H+1 contains the finalized application hash produced at height H.
	nextHeight := snapshot.Height + 1
	var proof *cmtypes.SignedHeader
	for {
		commit, e := client.Commit(ctx, &nextHeight)
		if e == nil {
			proof = &commit.SignedHeader
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	validators := []*cmtypes.Validator{}
	for _, p := range m.Peers {
		validators = append(validators, cmtypes.NewValidator(cmed.PubKey(p.ValidatorKey), 1))
	}
	set := cmtypes.NewValidatorSet(validators)
	if proof.Header.ChainID != m.Session || proof.Header.Height != nextHeight || !bytes.Equal(proof.Commit.BlockID.Hash, proof.Header.Hash()) {
		return nil, errors.New("invalid finality header binding")
	}
	if err := set.VerifyCommitLight(m.Session, proof.Commit.BlockID, nextHeight, proof.Commit); err != nil {
		return nil, err
	}
	appHash, err := hex.DecodeString(Hash(snapshot))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(proof.Header.AppHash, appHash) {
		return nil, errors.New("finalized app hash does not authenticate snapshot")
	}
	signers := 0
	for _, sig := range proof.Commit.Signatures {
		if sig.BlockIDFlag == cmtypes.BlockIDFlagCommit {
			signers++
		}
	}
	return map[string]any{"height": snapshot.Height, "app_hash": Hash(snapshot), "commit_height": nextHeight, "commit_signatures": signers, "registered": len(snapshot.Used), "processed": len(snapshot.Results), "services": len(snapshot.Services), "evidence": len(snapshot.Evidence), "market": snapshot.Market, "status": "real commit, block replay, threshold openings and independent accounting verified"}, nil
}

func appendSharesSorted(in []threshold.DecryptionShare) []threshold.DecryptionShare {
	out := append([]threshold.DecryptionShare{}, in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}
