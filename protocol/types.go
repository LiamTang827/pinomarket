// Package protocol implements a single-process research model, not a BFT network.
package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

const Domain = "pinocchio/research/v0.1"

type Order struct {
	Owner    string `json:"owner"`
	Nonce    int    `json:"nonce"`
	Kind     string `json:"kind"`
	Listing  string `json:"listing"`
	Quantity int64  `json:"quantity"`
	Limit    int64  `json:"limit_cents"`
}

func (o Order) Ref() string { return fmt.Sprintf("%s:%d", o.Owner, o.Nonce) }

type Submission struct {
	Round  int   `json:"round"`
	Order  Order `json:"order"`
	Delays []int `json:"delays_ms,omitempty"`
}
type Config struct {
	Name            string           `json:"name"`
	Seed            int64            `json:"seed"`
	Nodes           int              `json:"nodes"`
	Faults          int              `json:"fault_bound"`
	Admission       int              `json:"admission_signatures"`
	Release         int              `json:"release_approvals"`
	PerNode         int              `json:"per_node_round_capacity"`
	Service         int              `json:"service_capacity"`
	Window          int              `json:"window_ms"`
	Omit            string           `json:"omit_node,omitempty"`
	Refuse          string           `json:"refuse_node,omitempty"`
	Equivocate      string           `json:"equivocate_node,omitempty"`
	DuplicateCopies int              `json:"duplicate_copies,omitempty"`
	CorruptTo       string           `json:"corrupt_to_node,omitempty"`
	DropTo          string           `json:"drop_to_node,omitempty"`
	InitialCash     map[string]int64 `json:"initial_cash_cents,omitempty"`
	Orders          []Submission     `json:"orders"`
}

func (c Config) Validate() error {
	if c.Nodes < 1 || c.Nodes > 32 || c.Faults < 0 || c.Faults > c.Nodes || c.Nodes < 3*c.Faults+1 {
		return errors.New("require 1..32 nodes and n >= 3f+1")
	}
	if c.Admission <= c.Faults || c.Admission > c.Nodes-c.Faults || 2*c.Admission <= c.Nodes+c.Faults {
		return errors.New("require q>f, q<=n-f, 2q>n+f for this model")
	}
	if c.Release <= c.Faults || c.Release > c.Nodes-c.Faults {
		return errors.New("require f<t<=n-f")
	}
	if c.PerNode < 1 || c.PerNode > 10000 || c.Service < 1 || c.Service > 10000 || c.Window < 1 || c.Window > 100000 || len(c.Orders) > 10000 || c.DuplicateCopies < 0 || c.DuplicateCopies > 3 {
		return errors.New("invalid capacity, window, or workload")
	}
	for _, id := range []string{c.CorruptTo, c.DropTo} {
		if id != "" {
			found := false
			for i := 0; i < c.Nodes; i++ {
				if id == NodeID(i) {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("unknown transport destination %s", id)
			}
		}
	}
	bad := map[string]bool{}
	for _, id := range []string{c.Omit, c.Refuse, c.Equivocate} {
		if id != "" {
			found := false
			for i := 0; i < c.Nodes; i++ {
				if id == NodeID(i) {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("unknown faulty member %s", id)
			}
			bad[id] = true
		}
	}
	if len(bad) > c.Faults {
		return errors.New("scenario exceeds fault bound")
	}
	for owner, cash := range c.InitialCash {
		if (owner != "alice" && owner != "bob" && owner != "carol" && owner != "seller") || cash < 0 || cash > 1000000000 {
			return errors.New("invalid initial account cash")
		}
	}
	seen := map[string]bool{}
	for _, s := range c.Orders {
		if s.Round < 1 || s.Round > 1000 || s.Order.Owner == "" || s.Order.Nonce < 0 {
			return errors.New("invalid submission")
		}
		if seen[s.Order.Ref()] {
			return errors.New("duplicate owner/nonce in scenario")
		}
		seen[s.Order.Ref()] = true
		if len(s.Delays) != 0 && len(s.Delays) != c.Nodes {
			return errors.New("delays must specify every member")
		}
		for _, d := range s.Delays {
			if d < 0 || d > 1000000000 {
				return errors.New("delivery delay outside 0..1000000000 ms")
			}
		}
	}
	return nil
}
func NodeID(i int) string { return fmt.Sprintf("node-%d", i+1) }
func bytesOf(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}
func digest(v any) string                       { h := sha256.Sum256(bytesOf(v)); return hex.EncodeToString(h[:]) }
func sign(key ed25519.PrivateKey, v any) []byte { return ed25519.Sign(key, bytesOf(v)) }
func valid(key []byte, v any, sig []byte) bool {
	return len(key) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(key), bytesOf(v), sig)
}
func newIdentity() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

type Header struct {
	Domain  string `json:"domain"`
	Context string `json:"context"`
	Round   int    `json:"round"`
	Owner   string `json:"owner"`
	Nonce   int    `json:"nonce"`
}
type Envelope struct {
	Header     Header `json:"header"`
	Nonce      []byte `json:"aead_nonce"`
	Ciphertext []byte `json:"ciphertext"`
	Signature  []byte `json:"outer_signature"`
}

func (e Envelope) core() any {
	return struct {
		Header            Header
		Nonce, Ciphertext []byte
	}{e.Header, e.Nonce, e.Ciphertext}
}
func (e Envelope) ID() string { return digest(e.core()) }
func (e Envelope) Verify(keys map[string][]byte, ctx string) bool {
	return e.Header.Domain == Domain && e.Header.Context == ctx && valid(keys[e.Header.Owner], e.core(), e.Signature)
}

type Statement struct {
	Domain    string   `json:"domain"`
	Context   string   `json:"context"`
	Kind      string   `json:"kind"`
	Node      string   `json:"node"`
	Round     int      `json:"round"`
	Items     []string `json:"items"`
	Signature []byte   `json:"signature"`
}

func (s Statement) body() Statement { s.Signature = nil; return s }
func (s Statement) Verify(keys map[string][]byte, ctx string) bool {
	return s.Domain == Domain && s.Context == ctx && valid(keys[s.Node], s.body(), s.Signature)
}
func statement(key ed25519.PrivateKey, ctx, kind, node string, round int, items []string) Statement {
	s := Statement{Domain: Domain, Context: ctx, Kind: kind, Node: node, Round: round, Items: append([]string{}, items...)}
	s.Signature = sign(key, s.body())
	return s
}

type Certificate struct {
	Context string      `json:"context"`
	Round   int         `json:"round"`
	Item    string      `json:"item"`
	Votes   []Statement `json:"votes"`
}

func (c Certificate) Verify(keys map[string][]byte, q int) bool {
	if q < 1 || q > len(keys) {
		return false
	}
	seen := map[string]bool{}
	for _, v := range c.Votes {
		if v.Kind != "admit" || v.Round != c.Round || len(v.Items) != 1 || v.Items[0] != c.Item || !v.Verify(keys, c.Context) || seen[v.Node] {
			return false
		}
		seen[v.Node] = true
	}
	return len(seen) >= q
}

type Evidence struct {
	Kind   string    `json:"kind"`
	First  Statement `json:"first"`
	Second Statement `json:"second"`
}

// Verify uses only signed public statements. It never consults the simulator's clock.
func (e Evidence) Verify(keys map[string][]byte, ctx string) bool {
	a, b := e.First, e.Second
	if !a.Verify(keys, ctx) || !b.Verify(keys, ctx) || a.Node != b.Node || a.Round != b.Round {
		return false
	}
	for _, s := range []Statement{a, b} {
		if s.Kind == "final_list" {
			if s.Items == nil || !sort.StringsAreSorted(s.Items) {
				return false
			}
			for i := 1; i < len(s.Items); i++ {
				if s.Items[i] == s.Items[i-1] {
					return false
				}
			}
		}
	}
	if e.Kind == "omitted_promise" {
		return a.Kind == "admit" && len(a.Items) == 1 && b.Kind == "final_list" && !contains(b.Items, a.Items[0])
	}
	if e.Kind == "conflicting_lists" {
		return a.Kind == "final_list" && b.Kind == "final_list" && digest(a.Items) != digest(b.Items)
	}
	return false
}
func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

type AuditBundle struct {
	Context  string            `json:"context"`
	Members  map[string][]byte `json:"member_public_keys"`
	Evidence []Evidence        `json:"evidence"`
}
