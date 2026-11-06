package live

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// The executor verifies committee signatures over this ABI, not CometBFT
// proofs. The chain, contract, finalized lock and exact ordered calls are bound.
const batchABI = `[
	{"type":"function","name":"executeBatch","inputs":[
		{"type":"uint256","name":"number"},{"type":"bytes32","name":"lockId"},
		{"type":"tuple[]","name":"orders","components":[
			{"type":"address","name":"trader"},{"type":"bool","name":"buy"},
			{"type":"uint256","name":"amountIn"},{"type":"uint256","name":"minOut"},
			{"type":"uint256","name":"nonce"}]},
		{"type":"bytes[]","name":"signatures"}],"outputs":[]}
]`

var executorABI = func() abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(batchABI))
	if err != nil {
		panic(err)
	}
	return parsed
}()

type EVMOrder struct {
	Trader   common.Address `json:"trader"`
	Buy      bool           `json:"buy"`
	AmountIn *big.Int       `json:"amount_in"`
	MinOut   *big.Int       `json:"min_out"`
	Nonce    *big.Int       `json:"nonce"`
}

type EVMBatch struct {
	ChainID  int64          `json:"chain_id"`
	Contract common.Address `json:"contract"`
	Number   int            `json:"number"`
	LockID   common.Hash    `json:"lock_id"`
	Orders   []EVMOrder     `json:"orders"`
}

func (b EVMBatch) digest() (common.Hash, error) {
	method := executorABI.Methods["executeBatch"]
	orders, err := (abi.Arguments{method.Inputs[2]}).Pack(b.Orders)
	if err != nil {
		return common.Hash{}, err
	}
	digestArgs := abi.Arguments{
		method.Inputs[0],
		{Type: abi.Type{T: abi.AddressTy, Size: common.AddressLength}},
		method.Inputs[0],
		method.Inputs[1],
		method.Inputs[1],
	}
	encoded, err := digestArgs.Pack(big.NewInt(b.ChainID), b.Contract, big.NewInt(int64(b.Number)), b.LockID, crypto.Keccak256Hash(orders))
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(encoded), nil
}

func evmListing(listing string) (int64, common.Address, error) {
	parts := strings.Split(listing, ":")
	if len(parts) == 3 && parts[0] == "evm" && common.IsHexAddress(parts[2]) {
		chain, err := strconv.ParseInt(parts[1], 10, 64)
		contract := common.HexToAddress(parts[2])
		if err == nil && chain > 0 && contract != (common.Address{}) {
			return chain, contract, nil
		}
	}
	return 0, common.Address{}, errors.New("expected evm:<positive chain id>:<contract address>")
}

func evmTrader(m Manifest, owner string) common.Address {
	return common.BytesToAddress(crypto.Keccak256(m.Users[owner]))
}

func evmConfig(m Manifest) any {
	traders := make(map[string]common.Address, len(m.Users))
	for owner := range m.Users {
		traders[owner] = evmTrader(m, owner)
	}
	signers := make([]common.Address, 0, len(m.Peers))
	for _, peer := range m.Peers {
		signers = append(signers, common.HexToAddress(peer.EVMAddress))
	}
	return map[string]any{"signers": signers, "traders": traders, "quorum": m.Policy.Quorum}
}

type evmVote struct {
	Batch     EVMBatch      `json:"batch"`
	Signature hexutil.Bytes `json:"signature"`
	OpenMS    float64       `json:"open_ms"`
	SignMS    float64       `json:"sign_ms"`
}

func (n *liveNode) signEVMBatch(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	number, err := strconv.Atoi(r.URL.Query().Get("number"))
	if err != nil || number <= 0 {
		sendError(w, http.StatusBadRequest, errors.New("invalid batch number"))
		return
	}
	s := n.machine.Snapshot()
	if number > len(s.Services) {
		sendError(w, http.StatusConflict, errors.New("batch has not completed locally"))
		return
	}
	vote, err := deriveEVMVote(n.cfg.Manifest, s, number, n.evmKey)
	if err != nil {
		sendError(w, http.StatusUnprocessableEntity, err)
		return
	}
	sendJSON(w, http.StatusOK, vote)
}

func deriveEVMVote(m Manifest, s *State, number int, key *ecdsa.PrivateKey) (evmVote, error) {
	lock := s.Services[number-1]
	b := EVMBatch{Number: number, LockID: common.HexToHash(lock.ID)}
	started := time.Now()
	for _, id := range lock.Items {
		p := s.Orders[id]
		opened, err := OpenPacket(m, p, appendSharesSorted(lock.Shares[id]))
		if err != nil {
			return evmVote{}, fmt.Errorf("locked packet %s: %w", id, err)
		}
		o := opened.Order
		chain, contract, err := evmListing(o.Listing)
		if err != nil || o.Quantity <= 0 || o.Limit < 0 || (o.Kind != "buy" && o.Kind != "sell") {
			return evmVote{}, fmt.Errorf("order %s has invalid EVM fields", o.Ref())
		}
		if b.ChainID != 0 && (b.ChainID != chain || b.Contract != contract) {
			return evmVote{}, errors.New("a service batch must target a single EVM chain and contract")
		}
		b.ChainID, b.Contract = chain, contract
		b.Orders = append(b.Orders, EVMOrder{evmTrader(m, o.Owner), o.Kind == "buy", big.NewInt(o.Quantity), big.NewInt(o.Limit), big.NewInt(int64(o.Nonce))})
	}
	vote := evmVote{Batch: b, OpenMS: elapsedMS(started)}
	started = time.Now()
	digest, err := b.digest()
	if err != nil {
		return evmVote{}, err
	}
	vote.Signature, err = crypto.Sign(digest[:], key)
	if err != nil {
		return evmVote{}, err
	}
	vote.Signature[64] += 27
	vote.SignMS = elapsedMS(started)
	return vote, nil
}

func elapsedMS(start time.Time) float64 {
	return float64(time.Since(start)) / float64(time.Millisecond)
}

func (b EVMBatch) validate(number, capacity int) error {
	if b.Number != number || b.ChainID <= 0 || b.Contract == (common.Address{}) ||
		b.LockID == (common.Hash{}) || len(b.Orders) == 0 || len(b.Orders) > capacity {
		return errors.New("invalid batch envelope")
	}
	for _, order := range b.Orders {
		if order.Trader == (common.Address{}) || order.AmountIn == nil || order.MinOut == nil || order.Nonce == nil ||
			!order.AmountIn.IsInt64() || !order.MinOut.IsInt64() || !order.Nonce.IsInt64() ||
			order.AmountIn.Sign() <= 0 || order.MinOut.Sign() < 0 || order.Nonce.Sign() < 0 {
			return errors.New("invalid batch order")
		}
	}
	return nil
}

func fetchEVMBatch(ctx context.Context, m Manifest, number int) (any, error) {
	type response struct {
		peer Peer
		vote evmVote
		err  error
	}
	responses := make(chan response, len(m.Peers))
	for _, peer := range m.Peers {
		go func(peer Peer) {
			var vote evmVote
			err := RequestJSON(ctx, http.MethodGet, peer.API+"/evm/sign-batch?number="+strconv.Itoa(number), nil, &vote)
			responses <- response{peer, vote, err}
		}(peer)
	}
	type certificate struct {
		batch      EVMBatch
		signers    []string
		signatures []hexutil.Bytes
		timings    map[string]map[string]float64
	}
	groups := make(map[common.Hash]*certificate)
	failures := make(map[string]string)
	for range m.Peers {
		result := <-responses
		if result.err != nil {
			failures[result.peer.ID] = result.err.Error()
			continue
		}
		v := result.vote
		if v.Batch.validate(number, m.Policy.ServiceCapacity) != nil || len(v.Signature) != crypto.SignatureLength || (v.Signature[64] != 27 && v.Signature[64] != 28) {
			failures[result.peer.ID] = "invalid batch response"
			continue
		}
		digest, err := v.Batch.digest()
		if err != nil {
			failures[result.peer.ID] = err.Error()
			continue
		}
		raw := append([]byte(nil), v.Signature...)
		raw[64] -= 27
		pub, err := crypto.SigToPub(digest[:], raw)
		if err != nil || crypto.PubkeyToAddress(*pub) != common.HexToAddress(result.peer.EVMAddress) {
			failures[result.peer.ID] = "signature does not match member"
			continue
		}
		cert := groups[digest]
		if cert == nil {
			cert = &certificate{batch: v.Batch, timings: map[string]map[string]float64{}}
			groups[digest] = cert
		}
		cert.signers = append(cert.signers, result.peer.EVMAddress)
		cert.signatures = append(cert.signatures, v.Signature)
		cert.timings[result.peer.ID] = map[string]float64{"open_ms": v.OpenMS, "sign_ms": v.SignMS}
	}
	for digest, cert := range groups {
		if len(cert.signatures) < m.Policy.Quorum {
			continue
		}
		sigs := cert.signatures[:m.Policy.Quorum]
		b := cert.batch
		signatureBytes := make([][]byte, len(sigs))
		for i, sig := range sigs {
			signatureBytes[i] = sig
		}
		calldata, err := executorABI.Pack("executeBatch", big.NewInt(int64(b.Number)), b.LockID, b.Orders, signatureBytes)
		if err != nil {
			return nil, err
		}
		return struct {
			EVMBatch
			Digest     common.Hash                   `json:"digest"`
			Signatures []hexutil.Bytes               `json:"signatures"`
			Signers    []string                      `json:"signers"`
			Calldata   hexutil.Bytes                 `json:"calldata"`
			GoTimings  map[string]map[string]float64 `json:"go_timings"`
		}{b, digest, sigs, cert.signers[:m.Policy.Quorum], calldata, cert.timings}, nil
	}
	return nil, fmt.Errorf("no matching EVM signature quorum for batch %d (%v)", number, failures)
}
