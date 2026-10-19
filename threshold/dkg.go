package threshold

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/shutter-network/shutter/shlib/puredkg"
	"github.com/shutter-network/shutter/shlib/shcrypto"
)

const (
	Commitment = "commitment"
	Evaluation = "evaluation"
	Accusation = "accusation"
	Apology    = "apology"
)

// DKGMessage is a JSON-safe protocol message. Commitment, Accusation and Apology
// require authenticated consistent broadcast. Evaluation contains private key
// material and MUST use an authenticated confidential point-to-point channel to
// Receiver. Sender must be checked against the authenticated network identity.
// The eon must uniquely identify a ceremony with the agreed membership and
// threshold. A phase advances only after the agreed round barrier or deadline.
type DKGMessage struct {
	Kind     string `json:"kind"`
	Eon      uint64 `json:"eon"`
	Sender   int    `json:"sender"`
	Receiver int    `json:"receiver"`
	Accuser  int    `json:"accuser"`
	Data     []byte `json:"data,omitempty"`
}

// DKGParty holds ONLY one participant's DKG state. Instantiate one per process
// in a deployment. It is a sequential round machine, not safe for concurrent use.
// Finalize discards the protocol state after extracting this party's key share.
type DKGParty struct {
	pure *puredkg.PureDKG
}

func NewDKGParty(eon uint64, n, threshold, index int) (*DKGParty, error) {
	if err := parameters(n, threshold); err != nil {
		return nil, err
	}
	if index < 0 || index >= n {
		return nil, errors.New("invalid DKG participant index")
	}
	pure := puredkg.NewPureDKG(eon, uint64(n), uint64(threshold), uint64(index))
	return &DKGParty{pure: &pure}, nil
}

func (d *DKGParty) require(phase puredkg.Phase) error {
	if d == nil || d.pure == nil {
		return errors.New("DKG party is finalized or absent")
	}
	if d.pure.Phase != phase {
		return fmt.Errorf("wrong DKG phase: got %s, expected %s", d.pure.Phase, phase)
	}
	return nil
}

// StartDealing returns one broadcast and confidential messages for every other
// participant. The caller also broadcasts the commitment to itself via Handle.
func (d *DKGParty) StartDealing() (DKGMessage, []DKGMessage, error) {
	if err := d.require(puredkg.Off); err != nil {
		return DKGMessage{}, nil, err
	}
	commit, evals, err := d.pure.StartPhase1Dealing()
	if err != nil {
		return DKGMessage{}, nil, err
	}
	broadcast := DKGMessage{Kind: Commitment, Eon: commit.Eon, Sender: int(commit.Sender), Receiver: -1, Accuser: -1, Data: commit.Gammas.Marshal()}
	private := make([]DKGMessage, 0, len(evals))
	for _, eval := range evals {
		private = append(private, DKGMessage{Kind: Evaluation, Eon: eval.Eon, Sender: int(eval.Sender), Receiver: int(eval.Receiver), Accuser: -1, Data: eval.Eval.Bytes()})
	}
	return broadcast, private, nil
}

// StartAccusing closes dealing and emits broadcast complaints for missing or
// inconsistent private evaluations. Broadcast these to every party, including
// their senders, before advancing to the apology round.
func (d *DKGParty) StartAccusing() ([]DKGMessage, error) {
	if err := d.require(puredkg.Dealing); err != nil {
		return nil, err
	}
	msgs := d.pure.StartPhase2Accusing()
	result := make([]DKGMessage, 0, len(msgs))
	for _, msg := range msgs {
		result = append(result, DKGMessage{Kind: Accusation, Eon: msg.Eon, Sender: int(msg.Accuser), Receiver: int(msg.Accused), Accuser: int(msg.Accuser)})
	}
	return result, nil
}

// StartApologizing closes the complaint round and emits library-generated
// public responses. Broadcast these to every party before Finalize.
func (d *DKGParty) StartApologizing() ([]DKGMessage, error) {
	if err := d.require(puredkg.Accusing); err != nil {
		return nil, err
	}
	msgs := d.pure.StartPhase3Apologizing()
	result := make([]DKGMessage, 0, len(msgs))
	for _, msg := range msgs {
		result = append(result, DKGMessage{Kind: Apology, Eon: msg.Eon, Sender: int(msg.Accused), Receiver: -1, Accuser: int(msg.Accuser), Data: msg.Eval.Bytes()})
	}
	return result, nil
}

func (d *DKGParty) scalar(data []byte) (*big.Int, error) {
	if len(data) > 32 || (len(data) > 0 && data[0] == 0) {
		return nil, errors.New("invalid or noncanonical DKG scalar encoding")
	}
	value := new(big.Int).SetBytes(data)
	if !shcrypto.ValidEval(value) {
		return nil, errors.New("invalid DKG scalar")
	}
	return value, nil
}

// Handle validates a decoded message and feeds it to this party. It does not
// authenticate the network sender or supply reliable broadcast; the transport
// must do both. Malformed participant indices are rejected before shlib access.
func (d *DKGParty) Handle(msg DKGMessage) error {
	if d == nil || d.pure == nil {
		return errors.New("DKG party is finalized or absent")
	}
	if msg.Eon != d.pure.Eon || msg.Sender < 0 || msg.Sender >= int(d.pure.NumKeypers) {
		return errors.New("wrong DKG eon or sender")
	}
	switch msg.Kind {
	case Commitment:
		if err := d.require(puredkg.Dealing); err != nil {
			return err
		}
		if msg.Receiver != -1 || msg.Accuser != -1 || len(msg.Data) != int(d.pure.Threshold)*96 {
			return errors.New("invalid commitment envelope or length")
		}
		gammas := new(shcrypto.Gammas)
		if err := gammas.Unmarshal(msg.Data); err != nil {
			return err
		}
		if !bytes.Equal(gammas.Marshal(), msg.Data) {
			return errors.New("noncanonical DKG commitments")
		}
		return d.pure.HandlePolyCommitmentMsg(puredkg.PolyCommitmentMsg{Eon: msg.Eon, Sender: uint64(msg.Sender), Gammas: gammas})
	case Evaluation:
		if err := d.require(puredkg.Dealing); err != nil {
			return err
		}
		if msg.Receiver != int(d.pure.Keyper) || msg.Accuser != -1 {
			return errors.New("wrong DKG private evaluation receiver")
		}
		value, err := d.scalar(msg.Data)
		if err != nil {
			return err
		}
		return d.pure.HandlePolyEvalMsg(puredkg.PolyEvalMsg{Eon: msg.Eon, Sender: uint64(msg.Sender), Receiver: uint64(msg.Receiver), Eval: value})
	case Accusation:
		if err := d.require(puredkg.Accusing); err != nil {
			return err
		}
		if msg.Receiver < 0 || msg.Receiver >= int(d.pure.NumKeypers) || msg.Sender != msg.Accuser || msg.Sender == msg.Receiver || len(msg.Data) != 0 {
			return errors.New("invalid DKG accusation envelope")
		}
		return d.pure.HandleAccusationMsg(puredkg.AccusationMsg{Eon: msg.Eon, Accuser: uint64(msg.Sender), Accused: uint64(msg.Receiver)})
	case Apology:
		if err := d.require(puredkg.Apologizing); err != nil {
			return err
		}
		if msg.Receiver != -1 || msg.Accuser < 0 || msg.Accuser >= int(d.pure.NumKeypers) || msg.Sender == msg.Accuser {
			return errors.New("invalid DKG apology envelope")
		}
		value, err := d.scalar(msg.Data)
		if err != nil {
			return err
		}
		return d.pure.HandleApologyMsg(puredkg.ApologyMsg{Eon: msg.Eon, Accuser: uint64(msg.Accuser), Accused: uint64(msg.Sender), Eval: value})
	default:
		return errors.New("unknown DKG message kind")
	}
}

// Finalize emits the common public config and this participant's private share.
// The application must confirm all participating parties agree on Config.ID.
// DKG protocol state is discarded; Go does not guarantee memory zeroization.
func (d *DKGParty) Finalize() (PublicConfig, SecretShare, error) {
	if err := d.require(puredkg.Apologizing); err != nil {
		return PublicConfig{}, SecretShare{}, err
	}
	d.pure.Finalize()
	result, err := d.pure.ComputeResult()
	d.pure = nil
	if err != nil {
		return PublicConfig{}, SecretShare{}, err
	}
	config := PublicConfig{Version: Version, Eon: result.Eon, N: int(result.NumKeypers), Threshold: int(result.Threshold), PublicKey: result.PublicKey.Marshal()}
	for _, key := range result.PublicKeyShares {
		config.VerificationKeys = append(config.VerificationKeys, key.Marshal())
	}
	config.ID = config.computedID()
	if err := config.Validate(); err != nil {
		return PublicConfig{}, SecretShare{}, err
	}
	secret := SecretShare{ConfigID: config.ID, Index: int(result.Keyper), Value: result.SecretKeyShare.Marshal()}
	return config, secret, nil
}

// RunLocalDKG drives independent DKGParty states through all protocol rounds.
// It is an in-process test/development harness, NOT a deployed distributed
// ceremony: this process temporarily has access to every party's secret state.
// Production callers run DKGParty in separate nodes with the required channels.
func RunLocalDKG(eon uint64, n, threshold int) (PublicConfig, []SecretShare, error) {
	if err := parameters(n, threshold); err != nil {
		return PublicConfig{}, nil, err
	}
	parties := make([]*DKGParty, n)
	for i := range parties {
		party, err := NewDKGParty(eon, n, threshold, i)
		if err != nil {
			return PublicConfig{}, nil, err
		}
		parties[i] = party
	}
	var commitments, evaluations []DKGMessage
	for _, party := range parties {
		commit, evals, err := party.StartDealing()
		if err != nil {
			return PublicConfig{}, nil, err
		}
		commitments = append(commitments, commit)
		evaluations = append(evaluations, evals...)
	}
	broadcast := func(messages []DKGMessage) error {
		for _, msg := range messages {
			for _, party := range parties {
				if err := party.Handle(msg); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := broadcast(commitments); err != nil {
		return PublicConfig{}, nil, err
	}
	for _, msg := range evaluations {
		if err := parties[msg.Receiver].Handle(msg); err != nil {
			return PublicConfig{}, nil, err
		}
	}
	var accusations []DKGMessage
	for _, party := range parties {
		msgs, err := party.StartAccusing()
		if err != nil {
			return PublicConfig{}, nil, err
		}
		accusations = append(accusations, msgs...)
	}
	if err := broadcast(accusations); err != nil {
		return PublicConfig{}, nil, err
	}
	var apologies []DKGMessage
	for _, party := range parties {
		msgs, err := party.StartApologizing()
		if err != nil {
			return PublicConfig{}, nil, err
		}
		apologies = append(apologies, msgs...)
	}
	if err := broadcast(apologies); err != nil {
		return PublicConfig{}, nil, err
	}
	var common PublicConfig
	secrets := make([]SecretShare, n)
	for i, party := range parties {
		config, secret, err := party.Finalize()
		if err != nil {
			return PublicConfig{}, nil, err
		}
		if i > 0 && config.ID != common.ID {
			return PublicConfig{}, nil, errors.New("DKG public configuration disagreement")
		}
		common, secrets[i] = config, secret
	}
	return common, secrets, nil
}
