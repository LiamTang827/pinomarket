package live

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

// IngressSoftware is an opt-in protocol simulator, not a hardware attestation.
// Its key and state remain accessible to the host. Signatures therefore test
// binding and verification paths, not resistance to a malicious host or rollback.
const IngressSoftware = "software"

const ingressRecordDomain = "pinocchio/ingress-record/v0.1"
const ingressSealDomain = "pinocchio/ingress-seal/v0.1"

// IngressRecord records successful admission at the simulated protected adapter.
// ReceivedUnixNano is a host clock observation, not a trustworthy wall clock,
// network arrival time, or global transaction-ordering key.
type IngressRecord struct {
	Mode             string `json:"mode"`
	Context          string `json:"context"`
	Node             string `json:"node"`
	Round            int    `json:"round"`
	ID               string `json:"id"`
	Sequence         uint64 `json:"sequence"`
	ReceivedUnixNano int64  `json:"received_unix_nano"`
	Previous         string `json:"previous"`
	Signature        []byte `json:"signature"`
}

func (r IngressRecord) body() any {
	r.Signature = nil
	return struct {
		Domain string        `json:"domain"`
		Record IngressRecord `json:"record"`
	}{ingressRecordDomain, r}
}

// NewIngressRecord signs an admission observation. Callers validate the private
// key during configuration and persist the record together with the promise.
func NewIngressRecord(m Manifest, node string, round int, id string, sequence uint64, received int64, previous string, key ed25519.PrivateKey) IngressRecord {
	r := IngressRecord{Mode: IngressSoftware, Context: m.Context, Node: node, Round: round, ID: id, Sequence: sequence, ReceivedUnixNano: received, Previous: previous}
	r.Signature = Sign(key, r.body())
	return r
}

func (r IngressRecord) Validate(m Manifest) error {
	peer, ok := m.Peer(r.Node)
	if m.Policy.Ingress != IngressSoftware || r.Mode != IngressSoftware || !ok || r.Context != m.Context || r.Round < 1 || r.ID == "" || r.Sequence == 0 || r.ReceivedUnixNano <= 0 || !Verify(peer.IngressKey, r.body(), r.Signature) {
		return errors.New("invalid software ingress record")
	}
	if r.Sequence == 1 {
		if r.Previous != "" {
			return errors.New("first ingress record has a predecessor")
		}
	} else {
		previous, err := hex.DecodeString(r.Previous)
		if err != nil || len(previous) != 32 || len(r.Previous) != 64 {
			return errors.New("invalid ingress predecessor digest")
		}
	}
	return nil
}

// IngressSeal authenticates the complete accepted-record chain for one member
// and one round. It does not establish delivery to peers or common registration.
type IngressSeal struct {
	Mode      string `json:"mode"`
	Context   string `json:"context"`
	Node      string `json:"node"`
	Round     int    `json:"round"`
	Count     int    `json:"count"`
	Head      string `json:"head"`
	Signature []byte `json:"signature"`
}

func (s IngressSeal) body() any {
	s.Signature = nil
	return struct {
		Domain string      `json:"domain"`
		Seal   IngressSeal `json:"seal"`
	}{ingressSealDomain, s}
}

// ingressChainHead verifies a complete contiguous chain without changing the
// caller's slice. FinalList packets remain sorted by ID; admission order is
// reconstructed separately from the signed sequence numbers.
func ingressChainHead(m Manifest, node string, round int, records []IngressRecord) (string, error) {
	if _, ok := m.Peer(node); !ok || round < 1 || m.Policy.Ingress != IngressSoftware {
		return "", errors.New("invalid ingress chain context")
	}
	ordered := append([]IngressRecord(nil), records...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Sequence < ordered[j].Sequence })
	seen := make(map[string]bool, len(ordered))
	head := ""
	var previousTime int64
	for i, record := range ordered {
		if err := record.Validate(m); err != nil {
			return "", err
		}
		if record.Node != node || record.Round != round || record.Sequence != uint64(i+1) || record.Previous != head || record.ReceivedUnixNano < previousTime || seen[record.ID] {
			return "", errors.New("incomplete or inconsistent ingress chain")
		}
		seen[record.ID] = true
		previousTime = record.ReceivedUnixNano
		head = Hash(record)
	}
	return head, nil
}

// ValidateIngressRecords validates persisted accepted records without issuing a
// new seal, and returns the final digest (empty for an empty accepted round).
func ValidateIngressRecords(m Manifest, node string, round int, records []IngressRecord) (string, error) {
	return ingressChainHead(m, node, round, records)
}

func NewIngressSeal(m Manifest, node string, round int, records []IngressRecord, key ed25519.PrivateKey) (IngressSeal, error) {
	peer, ok := m.Peer(node)
	if !ok || len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), peer.IngressKey) {
		return IngressSeal{}, errors.New("ingress seal key does not match member")
	}
	head, err := ingressChainHead(m, node, round, records)
	if err != nil {
		return IngressSeal{}, err
	}
	seal := IngressSeal{Mode: IngressSoftware, Context: m.Context, Node: node, Round: round, Count: len(records), Head: head}
	seal.Signature = Sign(key, seal.body())
	return seal, nil
}

// ValidateIngressPromise checks the additional evidence required by a manifest.
// The normal member signature is checked by Promise.Validate, independently.
func ValidateIngressPromise(m Manifest, p Promise) error {
	switch m.Policy.Ingress {
	case "":
		if p.Ingress != nil {
			return errors.New("unexpected ingress record in baseline network")
		}
		return nil
	case IngressSoftware:
		if p.Ingress == nil {
			return errors.New("missing software ingress record")
		}
		if err := p.Ingress.Validate(m); err != nil {
			return err
		}
		if p.Context != p.Ingress.Context || p.Node != p.Ingress.Node || p.Round != p.Ingress.Round || p.ID != p.Ingress.ID {
			return errors.New("ingress record does not match promise")
		}
		return nil
	default:
		return errors.New("unsupported ingress mode")
	}
}

// ValidateIngressList rejects an omitted, duplicated, replaced, or modified
// record relative to the signed seal. A compromised software signer can still
// invent or replace both records and seals; this function is not hardware proof.
func ValidateIngressList(m Manifest, l FinalList) error {
	if m.Policy.Ingress == "" {
		if l.IngressSeal != nil {
			return errors.New("unexpected ingress seal in baseline network")
		}
		for _, p := range l.Promises {
			if err := ValidateIngressPromise(m, p); err != nil {
				return err
			}
		}
		return nil
	}
	if m.Policy.Ingress != IngressSoftware || l.IngressSeal == nil {
		return errors.New("missing or unsupported ingress seal")
	}
	seal := l.IngressSeal
	peer, ok := m.Peer(l.Node)
	if !ok || seal.Mode != IngressSoftware || seal.Context != m.Context || l.Context != m.Context || seal.Node != l.Node || seal.Round != l.Round || seal.Round < 1 || seal.Count < 0 || seal.Count != len(l.Promises) || len(l.Packets) != len(l.Promises) || !Verify(peer.IngressKey, seal.body(), seal.Signature) {
		return errors.New("invalid software ingress seal")
	}
	records := make([]IngressRecord, 0, len(l.Promises))
	for i, p := range l.Promises {
		if err := ValidateIngressPromise(m, p); err != nil {
			return err
		}
		if p.Node != l.Node || p.Round != l.Round || p.ID != l.Packets[i].ID() {
			return errors.New("ingress list item binding mismatch")
		}
		records = append(records, *p.Ingress)
	}
	head, err := ingressChainHead(m, l.Node, l.Round, records)
	if err != nil {
		return err
	}
	if seal.Head != head {
		return fmt.Errorf("ingress seal head mismatch: expected %s", head)
	}
	return nil
}
