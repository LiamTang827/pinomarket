package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
)

type signedOrder struct {
	Order     Order  `json:"order"`
	Signature []byte `json:"signature"`
}

func orderMessage(h Header, o Order) any {
	return struct {
		Header Header
		Order  Order
	}{h, o}
}

// IdealVault holds entire AES keys centrally. It models threshold-triggered release;
// it is NOT threshold encryption, DKG, distributed shares, or collusion resistance.
// Only this component sees keys before lock. Never use it with real funds.
type lockedService struct {
	certificate Certificate
	ids         []string
}
type IdealVault struct {
	releaseThreshold int
	members          map[string][]byte
	openings         map[string]Opening
	keys             map[string][]byte
	locks            map[string]lockedService
	opened           map[string]bool
}

func NewIdealVault(threshold int) *IdealVault {
	return &IdealVault{releaseThreshold: threshold, openings: map[string]Opening{}, keys: map[string][]byte{}, locks: map[string]lockedService{}, opened: map[string]bool{}}
}

func (v *IdealVault) Seal(h Header, o Order, key ed25519.PrivateKey) (Envelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("invalid signing private key")
	}
	if h.Domain != Domain || h.Context == "" || h.Round < 1 || h.Owner != o.Owner || h.Nonce != o.Nonce {
		return Envelope{}, errors.New("header/order context mismatch")
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return Envelope{}, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return Envelope{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return Envelope{}, err
	}
	body := signedOrder{o, sign(key, orderMessage(h, o))}
	e := Envelope{Header: h, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, bytesOf(body), bytesOf(h))}
	e.Signature = sign(key, e.core())
	v.keys[e.ID()] = k
	return e, nil
}

// lock is called by the ideal finality coordinator ONLY for a finalized queue prefix.
func (v *IdealVault) lock(c Certificate, ids []string, keys map[string][]byte, q int) error {
	if v.members != nil && !sameKeys(v.members, keys) {
		return errors.New("member trust anchors changed")
	}
	if c.Item != digest(ids) || !verifyService(c, keys, q) {
		return errors.New("invalid service certificate")
	}
	if _, exists := v.locks[c.Item]; exists {
		return errors.New("duplicate lock")
	}
	if v.members == nil {
		v.members = cloneKeys(keys)
	}
	v.locks[c.Item] = lockedService{c, append([]string{}, ids...)}
	return nil
}
func verifyService(c Certificate, keys map[string][]byte, q int) bool {
	if q < 1 || q > len(keys) {
		return false
	}
	seen := map[string]bool{}
	for _, s := range c.Votes {
		if s.Kind != "service" || s.Round != c.Round || len(s.Items) != 1 || s.Items[0] != c.Item || !s.Verify(keys, c.Context) || seen[s.Node] {
			return false
		}
		seen[s.Node] = true
	}
	return len(seen) >= q
}
func (v *IdealVault) Open(e Envelope, lock Certificate, approvals []Statement, members, users map[string][]byte, t int) (Order, error) {
	if !sameKeys(v.members, members) {
		return Order{}, errors.New("member trust anchors changed")
	}
	if t != v.releaseThreshold || t < 1 || t > len(members) {
		return Order{}, errors.New("invalid release threshold")
	}
	stored, ok := v.locks[lock.Item]
	if !ok || !contains(stored.ids, e.ID()) || lock.Context != e.Header.Context || stored.certificate.Context != lock.Context || stored.certificate.Round != lock.Round {
		return Order{}, errors.New("order has no finalized service lock")
	}
	seen := map[string]bool{}
	for _, s := range approvals {
		if s.Kind != "release" || s.Round != lock.Round || len(s.Items) != 1 || s.Items[0] != lock.Item || !s.Verify(members, lock.Context) || seen[s.Node] {
			return Order{}, errors.New("invalid release approval")
		}
		seen[s.Node] = true
	}
	if len(seen) < t {
		return Order{}, errors.New("insufficient distinct release approvals")
	}
	if !e.Verify(users, lock.Context) {
		return Order{}, errors.New("invalid envelope")
	}
	if v.opened[e.ID()] {
		return Order{}, errors.New("already decrypted")
	}
	k, ok := v.keys[e.ID()]
	if !ok {
		return Order{}, errors.New("key unavailable")
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return Order{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Order{}, err
	}
	if len(e.Nonce) != aead.NonceSize() {
		return Order{}, errors.New("invalid nonce")
	}
	raw, err := aead.Open(nil, e.Nonce, e.Ciphertext, bytesOf(e.Header))
	if err != nil {
		return Order{}, err
	}
	var body signedOrder
	if err = json.Unmarshal(raw, &body); err != nil {
		return Order{}, err
	}
	o := body.Order
	if o.Owner != e.Header.Owner || o.Nonce != e.Header.Nonce || !valid(users[o.Owner], orderMessage(e.Header, o), body.Signature) {
		return Order{}, errors.New("invalid order authorization")
	}
	v.opened[e.ID()] = true
	v.openings[e.ID()] = Opening{ID: e.ID(), Key: append([]byte{}, k...), Order: o, Signature: append([]byte{}, body.Signature...)}
	return o, nil
}

// Opening publishes only a serviced order's key, enabling independent AEAD checks.
// Waiting orders' keys and all signing private keys remain absent from reports.
type Opening struct {
	ID        string `json:"id"`
	Key       []byte `json:"released_aes_key"`
	Order     Order  `json:"order"`
	Signature []byte `json:"inner_signature"`
}

func cloneKeys(keys map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for id, k := range keys {
		out[id] = append([]byte{}, k...)
	}
	return out
}
func sameKeys(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for id, k := range a {
		if !bytes.Equal(k, b[id]) {
			return false
		}
	}
	return true
}
func verifyOpening(e Envelope, o Opening, users map[string][]byte) bool {
	if o.ID != e.ID() || len(o.Key) != 32 {
		return false
	}
	block, err := aes.NewCipher(o.Key)
	if err != nil {
		return false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(e.Nonce) != gcm.NonceSize() {
		return false
	}
	raw, err := gcm.Open(nil, e.Nonce, e.Ciphertext, bytesOf(e.Header))
	if err != nil {
		return false
	}
	var body signedOrder
	if json.Unmarshal(raw, &body) != nil {
		return false
	}
	return body.Order == o.Order && bytes.Equal(body.Signature, o.Signature) && o.Order.Owner == e.Header.Owner && o.Order.Nonce == e.Header.Nonce && valid(users[o.Order.Owner], orderMessage(e.Header, o.Order), o.Signature)
}
