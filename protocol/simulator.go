package protocol

import (
	"container/heap"
	"crypto/ed25519"
	"errors"
	"fmt"
	mathrand "math/rand"
	"sort"
)

type Event struct {
	Time   int    `json:"virtual_ms"`
	Kind   string `json:"kind"`
	Node   string `json:"node,omitempty"`
	Order  string `json:"order,omitempty"`
	Detail string `json:"detail,omitempty"`
}
type Report struct {
	Config         Config        `json:"config"`
	Context        string        `json:"context"`
	Assumptions    []string      `json:"assumptions"`
	Events         []Event       `json:"events"`
	Results        []Result      `json:"results"`
	Market         *Market       `json:"market"`
	Audit          AuditBundle   `json:"audit"`
	Envelopes      []Envelope    `json:"encrypted_orders"`
	Promises       []Statement   `json:"promises"`
	FinalLists     []Statement   `json:"final_lists"`
	Admissions     []Certificate `json:"admission_certificates"`
	Registrations  []Statement   `json:"ideal_registrations"`
	Services       []Certificate `json:"service_certificates"`
	Releases       []Statement   `json:"release_approvals"`
	SemanticDigest string        `json:"semantic_digest"`
}

func (r Report) Semantic() string {
	return digest(struct {
		Events  []Event
		Results []Result
		Market  *Market
	}{r.Events, r.Results, r.Market})
}

type delivery struct {
	at, sequence, node int
	envelope           Envelope
}
type deliveries []delivery

func (d deliveries) Len() int { return len(d) }
func (d deliveries) Less(i, j int) bool {
	if d[i].at == d[j].at {
		return d[i].sequence < d[j].sequence
	}
	return d[i].at < d[j].at
}
func (d deliveries) Swap(i, j int) { d[i], d[j] = d[j], d[i] }
func (d *deliveries) Push(x any)   { *d = append(*d, x.(delivery)) }
func (d *deliveries) Pop() any     { old := *d; n := len(old); x := old[n-1]; *d = old[:n-1]; return x }

type member struct {
	id      string
	private ed25519.PrivateKey
}

func DefaultConfig(name string) (Config, error) {
	c := Config{Name: name, Seed: 7, Nodes: 5, Faults: 1, Admission: 4, Release: 3, PerNode: 8, Service: 1, Window: 100}
	buy := func(owner string, q int64) Order {
		return Order{Owner: owner, Kind: "buy", Listing: "yes-1", Quantity: q, Limit: 60}
	}
	c.Orders = []Submission{{Round: 1, Order: buy("alice", 4)}, {Round: 1, Order: buy("bob", 3)}, {Round: 2, Order: buy("carol", 3)}}
	switch name {
	case "normal":
	case "delay":
		c.Orders[0].Delays = []int{90, 10, 70, 30, 50}
		c.Orders[1].Delays = []int{5, 80, 20, 60, 40}
	case "omission":
		c.Omit = "node-1"
	case "refusal":
		c.Refuse = "node-1"
	case "equivocation":
		c.Equivocate = "node-1"
	case "late":
		c.Orders[0].Delays = []int{100, 100, 100, 100, 100}
	case "capacity":
		c.PerNode = 1
		for i := range c.Orders {
			c.Orders[i].Delays = []int{10 + i, 10 + i, 10 + i, 10 + i, 10 + i}
		}
	case "funds":
		c.InitialCash = map[string]int64{"alice": 100}
	case "cancel":
		c.Orders = append(c.Orders, Submission{Round: 1, Order: Order{Owner: "seller", Kind: "cancel", Listing: "yes-1"}})
	default:
		return Config{}, fmt.Errorf("unknown scenario %q", name)
	}
	return c, nil
}

// Run is a deterministic event model with real signatures and AEAD, but ideal
// common registration/finality and a centralized IdealVault. No wall-clock claims.
func Run(c Config) (*Report, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	ctx := digest(struct {
		Domain string
		Config Config
	}{Domain, c})
	r := &Report{Config: c, Context: ctx, Market: NewMarket(), Results: []Result{}, Events: []Event{}, Audit: AuditBundle{Context: ctx, Members: map[string][]byte{}, Evidence: []Evidence{}}, Assumptions: []string{
		"Single process, virtual time; node views are separate state, not isolated machines.",
		"Common registration/finality is an ideal coordinator, not implemented BFT consensus.",
		"All members publish a final list in each round; crashes/unavailable lists are not modeled.",
		"IdealVault centrally stores AES keys. Release approvals are NOT threshold decryption shares.",
		"Public member keys are scenario trust anchors, not authenticated real-world identities.",
		"No fees, bonds, chain settlement, refunds, deadlines, or slashing implementation.",
		"Within-round order uses public (owner,nonce,digest); no arrival-order fairness claim.",
		"No total queue cap; only local admission and per-service capacity are bounded.",
	}}
	for owner, cash := range c.InitialCash {
		r.Market.Cash[owner] = cash
	}
	members := make([]member, c.Nodes)
	for i := range members {
		pub, priv, err := newIdentity()
		if err != nil {
			return nil, err
		}
		members[i] = member{NodeID(i), priv}
		r.Audit.Members[members[i].id] = pub
	}
	users := map[string][]byte{}
	userPrivate := map[string]ed25519.PrivateKey{}
	for _, s := range c.Orders {
		if _, ok := users[s.Order.Owner]; !ok {
			pub, priv, err := newIdentity()
			if err != nil {
				return nil, err
			}
			users[s.Order.Owner] = pub
			userPrivate[s.Order.Owner] = priv
		}
	}
	vault := NewIdealVault(c.Release)
	rng := mathrand.New(mathrand.NewSource(c.Seed))
	record := func(time int, kind, node, order, detail string) {
		r.Events = append(r.Events, Event{time, kind, node, order, detail})
	}
	all := map[string]Envelope{}
	queue := []Envelope{}
	registered := map[string]bool{}
	serviceRound := 0
	maxRound := 0
	for _, s := range c.Orders {
		maxRound = max(maxRound, s.Round)
	}
	serve := func(now int) error {
		if len(queue) == 0 {
			return nil
		}
		serviceRound++
		count := min(c.Service, len(queue))
		prefix := append([]Envelope{}, queue[:count]...)
		ids := make([]string, count)
		for i, e := range prefix {
			ids[i] = e.ID()
		}
		lock := Certificate{Context: ctx, Round: serviceRound, Item: digest(ids)}
		// Ideal finality signs one exact queue prefix. Nodes do not vote on hidden truth.
		for _, m := range members {
			lock.Votes = append(lock.Votes, statement(m.private, ctx, "service", m.id, serviceRound, []string{lock.Item}))
		}
		if err := vault.lock(lock, ids, r.Audit.Members, c.Admission); err != nil {
			return err
		}
		r.Services = append(r.Services, lock)
		for _, e := range prefix {
			record(now, "service_locked", "", e.Header.Owner+fmt.Sprintf(":%d", e.Header.Nonce), fmt.Sprintf("service=%d", serviceRound))
		}
		approvals := []Statement{}
		for i := 0; i < c.Release; i++ {
			m := members[i]
			approvals = append(approvals, statement(m.private, ctx, "release", m.id, serviceRound, []string{lock.Item}))
		}
		r.Releases = append(r.Releases, approvals...)
		for _, e := range prefix {
			o, err := vault.Open(e, lock, approvals, r.Audit.Members, users, c.Release)
			if err != nil {
				return err
			}
			record(now, "decrypted", "", o.Ref(), "ideal threshold authorization; real AES-GCM open")
			result := r.Market.Execute(o)
			r.Results = append(r.Results, result)
			record(now, "executed", "", o.Ref(), result.Status)
		}
		queue = queue[count:]
		return nil
	}
	for round := 1; round <= maxRound; round++ {
		base := (round - 1) * c.Window
		closeAt := round * c.Window
		inbox := make([][]string, c.Nodes)
		promises := map[string][]Statement{}
		pending := &deliveries{}
		heap.Init(pending)
		seq := 0
		for _, s := range c.Orders {
			if s.Round != round {
				continue
			}
			h := Header{Domain: Domain, Context: ctx, Round: round, Owner: s.Order.Owner, Nonce: s.Order.Nonce}
			e, err := vault.Seal(h, s.Order, userPrivate[s.Order.Owner])
			if err != nil {
				return nil, err
			}
			all[e.ID()] = e
			r.Envelopes = append(r.Envelopes, e)
			record(base, "submitted", "", s.Order.Ref(), "signed encrypted envelope")
			for i := range members {
				delay := 1 + rng.Intn(max(1, c.Window-1))
				if len(s.Delays) > 0 {
					delay = s.Delays[i]
				}
				heap.Push(pending, delivery{base + delay, seq, i, e})
				seq++
			}
		}
		for pending.Len() > 0 {
			d := heap.Pop(pending).(delivery)
			m := members[d.node]
			e := d.envelope
			ref := fmt.Sprintf("%s:%d", e.Header.Owner, e.Header.Nonce)
			if d.at >= closeAt {
				record(closeAt, "not_admitted", m.id, ref, "delivery outside round window; no retry in v0.1")
				continue
			}
			record(d.at, "received", m.id, ref, "")
			if !e.Verify(users, ctx) {
				return nil, errors.New("invalid incoming envelope")
			}
			if m.id == c.Refuse {
				record(d.at, "refused", m.id, ref, "no signed receipt; not proof of misconduct")
				continue
			}
			if contains(inbox[d.node], e.ID()) {
				continue
			}
			if len(inbox[d.node]) >= c.PerNode {
				record(d.at, "capacity_rejected", m.id, ref, "")
				continue
			}
			inbox[d.node] = append(inbox[d.node], e.ID())
			p := statement(m.private, ctx, "admit", m.id, round, []string{e.ID()})
			promises[e.ID()] = append(promises[e.ID()], p)
			r.Promises = append(r.Promises, p)
			record(d.at, "promised", m.id, ref, "")
			if len(promises[e.ID()]) == c.Admission {
				record(d.at, "admission_certificate", "", ref, "eligibility, not a global queue position")
			}
		}
		lists := make([]Statement, c.Nodes)
		for i, m := range members {
			items := append([]string{}, inbox[i]...)
			sort.Strings(items)
			if m.id == c.Omit {
				items = []string{}
			}
			lists[i] = statement(m.private, ctx, "final_list", m.id, round, items)
			r.FinalLists = append(r.FinalLists, lists[i])
			record(closeAt, "final_list", m.id, "", fmt.Sprintf("round=%d items=%d", round, len(items)))
			for _, p := range r.Promises {
				if p.Round == round && p.Node == m.id && !contains(items, p.Items[0]) {
					ev := Evidence{"omitted_promise", p, lists[i]}
					if !ev.Verify(r.Audit.Members, ctx) {
						return nil, errors.New("invalid omission evidence")
					}
					r.Audit.Evidence = append(r.Audit.Evidence, ev)
					record(closeAt, "evidence", m.id, "", ev.Kind)
				}
			}
			if m.id == c.Equivocate && len(items) > 0 {
				other := statement(m.private, ctx, "final_list", m.id, round, []string{})
				r.FinalLists = append(r.FinalLists, other)
				ev := Evidence{"conflicting_lists", lists[i], other}
				r.Audit.Evidence = append(r.Audit.Evidence, ev)
				record(closeAt, "evidence", m.id, "", ev.Kind)
			}
		}
		// Ideal common-registration coordinator: validate signed lists and register
		// their union restricted to orders with q valid, distinct admission signatures.
		candidates := map[string]bool{}
		for _, l := range lists {
			if !l.Verify(r.Audit.Members, ctx) {
				return nil, errors.New("invalid final list")
			}
			for _, id := range l.Items {
				candidates[id] = true
			}
		}
		batch := []Envelope{}
		for id := range candidates {
			e, ok := all[id]
			if !ok || e.Header.Round != round {
				continue
			}
			cert := Certificate{ctx, round, id, promises[id]}
			if !cert.Verify(r.Audit.Members, c.Admission) {
				continue
			}
			if registered[id] {
				continue
			}
			r.Admissions = append(r.Admissions, cert)
			batch = append(batch, e)
		}
		sort.Slice(batch, func(i, j int) bool {
			a, b := batch[i], batch[j]
			if a.Header.Owner != b.Header.Owner {
				return a.Header.Owner < b.Header.Owner
			}
			if a.Header.Nonce != b.Header.Nonce {
				return a.Header.Nonce < b.Header.Nonce
			}
			return a.ID() < b.ID()
		})
		// Stabilize artifact order too (random cipher bytes still differ between runs).
		sort.Slice(r.Admissions, func(i, j int) bool {
			a, b := all[r.Admissions[i].Item], all[r.Admissions[j].Item]
			if a.Header.Round != b.Header.Round {
				return a.Header.Round < b.Header.Round
			}
			if a.Header.Owner != b.Header.Owner {
				return a.Header.Owner < b.Header.Owner
			}
			return a.Header.Nonce < b.Header.Nonce
		})
		ids := []string{}
		for _, e := range batch {
			registered[e.ID()] = true
			queue = append(queue, e)
			ids = append(ids, e.ID())
			record(closeAt, "registered", "", fmt.Sprintf("%s:%d", e.Header.Owner, e.Header.Nonce), fmt.Sprintf("round=%d", round))
		}
		// This signed coordinator record is a simulation artifact, not a quorum certificate.
		r.Registrations = append(r.Registrations, statement(members[0].private, ctx, "ideal_registry", members[0].id, round, ids))
		if err := serve(closeAt); err != nil {
			return nil, err
		}
	}
	for now := (maxRound + 1) * c.Window; len(queue) > 0; now += c.Window {
		if err := serve(now); err != nil {
			return nil, err
		}
	}
	if _, err := VerifyAudit(r.Audit); err != nil {
		return nil, err
	}
	r.SemanticDigest = r.Semantic()
	return r, nil
}
func VerifyAudit(a AuditBundle) (int, error) {
	if a.Context == "" || len(a.Members) == 0 {
		return 0, errors.New("missing context or trust anchors")
	}
	for i, e := range a.Evidence {
		if !e.Verify(a.Members, a.Context) {
			return 0, fmt.Errorf("evidence %d failed verification", i)
		}
	}
	return len(a.Evidence), nil
}
