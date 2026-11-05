// Package live implements a local multi-process protocol over CometBFT.
package live

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/LiamTang827/pinomarket/protocol"
	"github.com/LiamTang827/pinomarket/threshold"
)

const Domain = "pinocchio/live/v0.3"

type Policy struct {
	Nodes           int         `json:"nodes"`
	Faults          int         `json:"faults"`
	Quorum          int         `json:"quorum"`
	Threshold       int         `json:"threshold"`
	QueueCapacity   int         `json:"queue_capacity"`
	ServiceCapacity int         `json:"service_capacity"`
	WindowBlocks    int64       `json:"window_blocks"`
	Ordering        string      `json:"ordering,omitempty"`
	Ingress         string      `json:"ingress,omitempty"`
	Aion            *AionPolicy `json:"aion,omitempty"`
}

func (p Policy) validateOrdering() error {
	switch p.Ordering {
	case "", OrderingIdentity:
		if p.Aion == nil {
			return nil
		}
	case OrderingAion:
		if p.Ingress != IngressSoftware || p.Aion == nil {
			return errors.New("aion ordering requires software ingress and timing policy")
		}
		return p.Aion.Validate()
	}
	return errors.New("invalid within-round ordering policy")
}

type Peer struct {
	ID           string `json:"id"`
	Index        int    `json:"index"`
	API          string `json:"api"`
	RPC          string `json:"rpc"`
	Key          []byte `json:"public_key"`
	ValidatorKey []byte `json:"validator_public_key"`
	IngressKey   []byte `json:"ingress_public_key,omitempty"`
}
type Manifest struct {
	Version string                 `json:"version"`
	Session string                 `json:"session"`
	Context string                 `json:"context"`
	Policy  Policy                 `json:"policy"`
	Peers   []Peer                 `json:"peers"`
	Users   map[string][]byte      `json:"users"`
	Crypto  threshold.PublicConfig `json:"crypto"`
}

func (m Manifest) ContextID() string { m.Context = ""; return Hash(m) }
func (m Manifest) Validate() error {
	p := m.Policy
	if err := p.validateOrdering(); err != nil {
		return err
	}
	if p.Ingress != "" && p.Ingress != IngressSoftware {
		return errors.New("unknown ingress backend: only software simulation is available")
	}
	if m.Version != Domain || m.Context != m.ContextID() || p.Nodes < 4 || p.Nodes > 10 || p.Faults != (p.Nodes-1)/3 || p.Quorum != p.Nodes-p.Faults || p.Threshold <= p.Faults || p.Threshold > p.Quorum || p.QueueCapacity < p.Nodes || p.QueueCapacity > p.Nodes*8 || p.ServiceCapacity < 1 || p.ServiceCapacity > p.QueueCapacity || p.WindowBlocks < 3 || p.WindowBlocks > 10000 {
		return errors.New("invalid live manifest policy/context")
	}
	if len(m.Peers) != p.Nodes || m.Crypto.N != p.Nodes || m.Crypto.Threshold != p.Threshold {
		return errors.New("member/crypto policy mismatch")
	}
	if err := m.Crypto.Validate(); err != nil {
		return err
	}
	seen := map[string]bool{}
	keySeen := map[string]bool{}
	for i, n := range m.Peers {
		if n.Index != i || n.ID == "" || seen[n.ID] || len(n.Key) != ed25519.PublicKeySize || len(n.ValidatorKey) != ed25519.PublicKeySize || keySeen[string(n.Key)] {
			return errors.New("invalid member keys")
		}
		seen[n.ID] = true
		keySeen[string(n.Key)] = true
		if p.Ingress == IngressSoftware {
			if len(n.IngressKey) != ed25519.PublicKeySize || bytes.Equal(n.IngressKey, n.Key) || keySeen["ingress:"+string(n.IngressKey)] {
				return errors.New("invalid or reused software ingress key")
			}
			keySeen["ingress:"+string(n.IngressKey)] = true
		} else if len(n.IngressKey) != 0 {
			return errors.New("ingress key present without ingress policy")
		}
	}
	if p.Ingress == IngressSoftware {
		for _, n := range m.Peers {
			if keySeen[string(n.IngressKey)] {
				return errors.New("software ingress key reuses a member signing key")
			}
		}
	}
	for _, name := range []string{"alice", "bob", "carol", "seller"} {
		if len(m.Users[name]) != ed25519.PublicKeySize {
			return errors.New("missing wallet public key")
		}
	}
	return nil
}
func (m Manifest) Peer(id string) (Peer, bool) {
	for _, p := range m.Peers {
		if p.ID == id {
			return p, true
		}
	}
	return Peer{}, false
}

type NodeConfig struct {
	Manifest       Manifest              `json:"manifest"`
	Index          int                   `json:"index"`
	CometDir       string                `json:"comet_dir"`
	Private        []byte                `json:"private_signing_key"`
	Share          threshold.SecretShare `json:"threshold_secret_share"`
	IngressPrivate []byte                `json:"software_ingress_private_key,omitempty"`
}
type Header struct {
	Domain  string `json:"domain"`
	Context string `json:"context"`
	Round   int    `json:"round"`
	Owner   string `json:"owner"`
	Nonce   int    `json:"nonce"`
}
type Packet struct {
	Header    Header               `json:"header"`
	Nonce     []byte               `json:"nonce"`
	Body      []byte               `json:"body"`
	Wrapped   threshold.Ciphertext `json:"wrapped_key"`
	Signature []byte               `json:"signature"`
	TimeProof *TimeProof           `json:"time_proof,omitempty"`
}

func (p Packet) Ref() string { return fmt.Sprintf("%s:%d", p.Header.Owner, p.Header.Nonce) }
func (p Packet) core() Packet {
	p.Signature = nil
	p.TimeProof = nil
	return p
}
func (p Packet) ID() string { return Hash(p.core()) }
func (p Packet) label() []byte {
	return []byte(Hash(struct {
		Header      Header
		Nonce, Body []byte
	}{p.Header, p.Nonce, p.Body}))
}

type Body struct {
	Order     protocol.Order `json:"order"`
	Signature []byte         `json:"signature"`
}

func orderAuth(h Header, o protocol.Order) any {
	return struct {
		Header Header
		Order  protocol.Order
	}{h, o}
}
func NewPacket(m Manifest, round int, o protocol.Order, key ed25519.PrivateKey) (Packet, error) {
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), m.Users[o.Owner]) || round < 1 || o.Nonce < 0 {
		return Packet{}, errors.New("invalid wallet or round")
	}
	p := Packet{Header: Header{Domain, m.Context, round, o.Owner, o.Nonce}}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return p, err
	}
	block, _ := aes.NewCipher(k)
	gcm, _ := cipher.NewGCM(block)
	p.Nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(p.Nonce); err != nil {
		return p, err
	}
	body := Body{o, Sign(key, orderAuth(p.Header, o))}
	p.Body = gcm.Seal(nil, p.Nonce, JSON(body), JSON(p.Header))
	var err error
	p.Wrapped, err = threshold.Encrypt(m.Crypto, p.label(), k)
	if err != nil {
		return Packet{}, err
	}
	p.Signature = Sign(key, p.core())
	return p, nil
}
func (p Packet) Validate(m Manifest) error {
	if p.Header.Domain != Domain || p.Header.Context != m.Context || p.Header.Round < 1 || p.Header.Nonce < 0 || len(p.Nonce) != 12 || len(p.Body) < 16 || len(JSON(p)) > 65536 || !Verify(m.Users[p.Header.Owner], p.core(), p.Signature) || !bytes.Equal(p.Wrapped.Label, p.label()) {
		return errors.New("invalid packet authorization or binding")
	}
	return threshold.ValidateCiphertext(m.Crypto, p.Wrapped)
}

// ValidateAdmission checks the envelope and any evidence required to register it.
func (p Packet) ValidateAdmission(m Manifest) error {
	if err := p.Validate(m); err != nil {
		return err
	}
	if m.Policy.Ordering == OrderingAion {
		if p.TimeProof == nil {
			return errors.New("missing Aion time proof")
		}
		return p.TimeProof.Validate(m, p)
	}
	if p.TimeProof != nil {
		return errors.New("unexpected Aion time proof")
	}
	return nil
}

func (p Packet) timeProofID() string {
	if p.TimeProof == nil {
		return ""
	}
	return Hash(p.TimeProof)
}

func OpenPacket(m Manifest, p Packet, shares []threshold.DecryptionShare) (Opened, error) {
	k, err := threshold.Decrypt(m.Crypto, p.Wrapped, shares)
	if err != nil {
		return Opened{}, err
	}
	if len(k) != 32 {
		return Opened{}, errors.New("invalid recovered AES key")
	}
	block, _ := aes.NewCipher(k)
	gcm, _ := cipher.NewGCM(block)
	raw, err := gcm.Open(nil, p.Nonce, p.Body, JSON(p.Header))
	if err != nil {
		return Opened{}, err
	}
	var body Body
	if err = json.Unmarshal(raw, &body); err != nil {
		return Opened{}, err
	}
	if body.Order.Owner != p.Header.Owner || body.Order.Nonce != p.Header.Nonce || !Verify(m.Users[body.Order.Owner], orderAuth(p.Header, body.Order), body.Signature) {
		return Opened{}, errors.New("invalid inner authorization")
	}
	return Opened{p.ID(), k, body.Order, body.Signature}, nil
}

type Opened struct {
	ID        string         `json:"id"`
	Key       []byte         `json:"key"`
	Order     protocol.Order `json:"order"`
	Signature []byte         `json:"inner_signature"`
}
type Promise struct {
	Context     string         `json:"context"`
	Node        string         `json:"node"`
	Round       int            `json:"round"`
	ID          string         `json:"id"`
	Signature   []byte         `json:"signature"`
	Ingress     *IngressRecord `json:"ingress,omitempty"`
	TimeProofID string         `json:"time_proof_id,omitempty"`
}

func (p Promise) body() Promise { p.Signature = nil; return p }
func NewPromise(m Manifest, node string, round int, id string, key ed25519.PrivateKey) Promise {
	p := Promise{Context: m.Context, Node: node, Round: round, ID: id}
	p.Signature = Sign(key, p.body())
	return p
}

func (p Promise) Validate(m Manifest) error {
	n, ok := m.Peer(p.Node)
	if !ok || p.Context != m.Context || p.Round < 1 || p.ID == "" || !Verify(n.Key, p.body(), p.Signature) {
		return errors.New("invalid admission promise")
	}
	if (p.TimeProofID != "") != (m.Policy.Ordering == OrderingAion) {
		return errors.New("admission promise has wrong timing mode")
	}
	return ValidateIngressPromise(m, p)
}

type FinalList struct {
	Context     string       `json:"context"`
	Node        string       `json:"node"`
	Round       int          `json:"round"`
	Packets     []Packet     `json:"packets"`
	Promises    []Promise    `json:"promises"`
	Signature   []byte       `json:"signature"`
	IngressSeal *IngressSeal `json:"ingress_seal,omitempty"`
}

func (p Promise) matches(packet Packet) bool {
	return p.ID == packet.ID() && p.Round == packet.Header.Round && p.TimeProofID == packet.timeProofID()
}

func (l FinalList) body() FinalList { l.Signature = nil; return l }
func (l FinalList) Has(id string) bool {
	for _, p := range l.Packets {
		if p.ID() == id {
			return true
		}
	}
	return false
}
func (l FinalList) Validate(m Manifest, capacity int) error {
	n, ok := m.Peer(l.Node)
	if !ok || l.Context != m.Context || !Verify(n.Key, l.body(), l.Signature) || len(l.Packets) != len(l.Promises) || len(l.Packets) > capacity {
		return errors.New("invalid final list signature/capacity")
	}
	prev := ""
	for i, p := range l.Packets {
		if err := p.ValidateAdmission(m); err != nil {
			return err
		}
		pr := l.Promises[i]
		if err := pr.Validate(m); err != nil {
			return err
		}
		if p.Header.Round != l.Round || pr.Node != l.Node || !pr.matches(p) || p.ID() <= prev {
			return errors.New("invalid final list item")
		}
		prev = p.ID()
	}
	return ValidateIngressList(m, l)
}

type SignedTx struct {
	Type      string          `json:"type"`
	Context   string          `json:"context"`
	Node      string          `json:"node"`
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"signature"`
}

func (t SignedTx) body() SignedTx { t.Signature = nil; return t }
func NewTx(m Manifest, node, kind string, payload any, key ed25519.PrivateKey) SignedTx {
	t := SignedTx{Type: kind, Context: m.Context, Node: node, Payload: JSON(payload)}
	t.Signature = Sign(key, t.body())
	return t
}
func ParseTx(m Manifest, raw []byte) (SignedTx, error) {
	var t SignedTx
	if len(raw) > 1024*1024 {
		return t, errors.New("transaction too large")
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return t, err
	}
	n, ok := m.Peer(t.Node)
	if !ok || t.Context != m.Context || !Verify(n.Key, t.body(), t.Signature) {
		return t, errors.New("invalid member transaction signature")
	}
	return t, nil
}
func JSON(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}
func Hash(v any) string                       { h := sha256.Sum256(JSON(v)); return hex.EncodeToString(h[:]) }
func Sign(k ed25519.PrivateKey, v any) []byte { return ed25519.Sign(k, JSON(v)) }
func Verify(k []byte, v any, s []byte) bool {
	return len(k) == ed25519.PublicKeySize && ed25519.Verify(k, JSON(v), s)
}
