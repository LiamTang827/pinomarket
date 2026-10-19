package protocol

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

// AuditReport checks supplied artifacts without Run, private keys, or the ideal
// vault. Its trust root is still the supplied scenario key set, not a real chain.
func AuditReport(r Report) error {
	if r.Version != "0.2" {
		return errors.New("audit requires a v0.2 report")
	}
	if err := r.Config.Validate(); err != nil {
		return err
	}
	session, err := hex.DecodeString(r.Session)
	if err != nil || len(session) != 32 {
		return errors.New("invalid session nonce")
	}
	ctx := ContextFor(r.Config, r.Session)
	if r.Context != ctx || r.Audit.Context != ctx {
		return errors.New("public context mismatch")
	}
	keys := r.Audit.Members
	if len(keys) != r.Config.Nodes {
		return errors.New("member set size mismatch")
	}
	seenKeys := map[string]bool{}
	for i := 0; i < r.Config.Nodes; i++ {
		k := keys[NodeID(i)]
		if len(k) != ed25519.PublicKeySize || seenKeys[string(k)] {
			return errors.New("invalid or duplicate member public key")
		}
		seenKeys[string(k)] = true
	}
	if r.Market == nil {
		return errors.New("missing final market")
	}
	if r.Semantic() != r.SemanticDigest {
		return errors.New("semantic digest mismatch")
	}
	if r.Metrics != Summarize(r) {
		return errors.New("metrics mismatch")
	}
	submissions := map[string]Submission{}
	maxRound := 0
	owners := map[string]bool{}
	for _, s := range r.Config.Orders {
		submissions[s.Order.Ref()] = s
		owners[s.Order.Owner] = true
		maxRound = max(maxRound, s.Round)
	}
	if len(r.UserKeys) != len(owners) {
		return errors.New("user key set mismatch")
	}
	for owner := range owners {
		if len(r.UserKeys[owner]) != ed25519.PublicKeySize {
			return errors.New("missing user public key")
		}
	}
	envelopes := map[string]Envelope{}
	byRef := map[string]string{}
	for _, e := range r.Envelopes {
		ref := fmt.Sprintf("%s:%d", e.Header.Owner, e.Header.Nonce)
		s, ok := submissions[ref]
		if !ok || e.Header.Round != s.Round || !e.Verify(r.UserKeys, ctx) || byRef[ref] != "" {
			return errors.New("invalid, duplicate, or unexpected encrypted order")
		}
		envelopes[e.ID()] = e
		byRef[ref] = e.ID()
	}
	if len(envelopes) != len(submissions) {
		return errors.New("missing encrypted order")
	}
	promises := map[string][]Statement{}
	promiseSources := map[string]bool{}
	promiseCounts := map[string]int{}
	for _, p := range r.Promises {
		if p.Kind != "admit" || len(p.Items) != 1 || !p.Verify(keys, ctx) {
			return errors.New("invalid promise")
		}
		id := p.Items[0]
		e, ok := envelopes[id]
		if !ok || e.Header.Round != p.Round {
			return errors.New("promise context/round mismatch")
		}
		unique := fmt.Sprintf("%s/%d/%s", p.Node, p.Round, id)
		if promiseSources[unique] {
			return errors.New("duplicate promise")
		}
		promiseSources[unique] = true
		group := fmt.Sprintf("%s/%d", p.Node, p.Round)
		promiseCounts[group]++
		if promiseCounts[group] > r.Config.PerNode {
			return errors.New("node exceeded promise capacity")
		}
		promises[id] = append(promises[id], p)
	}
	selected := map[int]map[string]Statement{}
	listSources := map[string]bool{}
	expectedEvidence := map[string]bool{}
	for _, l := range r.FinalLists {
		if l.Kind != "final_list" || !l.Verify(keys, ctx) || l.Round < 1 || l.Round > maxRound || !canonicalItems(l.Items) || len(l.Items) > r.Config.PerNode {
			return errors.New("invalid final list")
		}
		for _, id := range l.Items {
			e, ok := envelopes[id]
			if !ok || e.Header.Round != l.Round || !promiseSources[fmt.Sprintf("%s/%d/%s", l.Node, l.Round, id)] {
				return errors.New("list item lacks same-node promise")
			}
		}
		if listSources[digest(l)] {
			return errors.New("duplicate final-list artifact")
		}
		listSources[digest(l)] = true
		if selected[l.Round] == nil {
			selected[l.Round] = map[string]Statement{}
		}
		if first, ok := selected[l.Round][l.Node]; ok {
			if digest(first.Items) == digest(l.Items) {
				return errors.New("duplicate final list")
			}
			expectedEvidence[digest(Evidence{"conflicting_lists", first, l})] = true
		} else {
			selected[l.Round][l.Node] = l
		}
	}
	for round := 1; round <= maxRound; round++ {
		if len(selected[round]) != r.Config.Nodes {
			return errors.New("missing member final list")
		}
	}
	for _, p := range r.Promises {
		l := selected[p.Round][p.Node]
		if !contains(l.Items, p.Items[0]) {
			expectedEvidence[digest(Evidence{"omitted_promise", p, l})] = true
		}
	}
	if _, err := VerifyAudit(r.Audit); err != nil {
		return err
	}
	actualEvidence := map[string]bool{}
	for _, ev := range r.Audit.Evidence {
		d := digest(ev)
		if !expectedEvidence[d] || actualEvidence[d] {
			return errors.New("unexpected or duplicate evidence")
		}
		actualEvidence[d] = true
	}
	if len(actualEvidence) != len(expectedEvidence) {
		return errors.New("missing evidence for published contradictions")
	}
	admissions := map[string]Certificate{}
	for _, cert := range r.Admissions {
		e, ok := envelopes[cert.Item]
		if !ok || cert.Context != ctx || cert.Round != e.Header.Round || !cert.Verify(keys, r.Config.Admission) || admissions[cert.Item].Item != "" {
			return errors.New("invalid admission certificate")
		}
		for _, p := range cert.Votes {
			if !promiseSources[fmt.Sprintf("%s/%d/%s", p.Node, p.Round, cert.Item)] {
				return errors.New("certificate vote absent from promises")
			}
		}
		admissions[cert.Item] = cert
	}
	if len(r.Registrations) != maxRound {
		return errors.New("registration round count mismatch")
	}
	queue := []string{}
	expectedIDs := map[string]bool{}
	nextRegistration := 1
	appendThrough := func(through int) error {
		if through < nextRegistration-1 || through > maxRound {
			return errors.New("invalid registration cutoff")
		}
		for nextRegistration <= through {
			round := nextRegistration
			reg := r.Registrations[round-1]
			if reg.Kind != "ideal_registry" || reg.Node != NodeID(0) || reg.Round != round || !reg.Verify(keys, ctx) {
				return errors.New("invalid ideal registration record")
			}
			union := map[string]bool{}
			for _, l := range selected[round] {
				for _, id := range l.Items {
					union[id] = true
				}
			}
			eligible := []string{}
			for id := range union {
				cert := Certificate{Context: ctx, Round: round, Item: id, Votes: promises[id]}
				if cert.Verify(keys, r.Config.Admission) {
					eligible = append(eligible, id)
				}
			}
			sort.Slice(eligible, func(i, j int) bool {
				a, b := envelopes[eligible[i]], envelopes[eligible[j]]
				if a.Header.Owner != b.Header.Owner {
					return a.Header.Owner < b.Header.Owner
				}
				if a.Header.Nonce != b.Header.Nonce {
					return a.Header.Nonce < b.Header.Nonce
				}
				return eligible[i] < eligible[j]
			})
			if !sameItems(reg.Items, eligible) {
				return errors.New("registration is not the eligible sorted union")
			}
			for _, id := range eligible {
				if admissions[id].Item == "" {
					return errors.New("registered item lacks certificate")
				}
				expectedIDs[id] = true
				queue = append(queue, id)
			}
			nextRegistration++
		}
		return nil
	}
	if len(r.Services) != len(r.ServiceRecords) {
		return errors.New("missing service record")
	}
	executedIDs := []string{}
	releaseCount := 0
	for i, rec := range r.ServiceRecords {
		if err := appendThrough(rec.RegisteredThrough); err != nil {
			return err
		}
		cert := rec.Certificate
		if cert.Context != ctx || cert.Round != i+1 || digest(cert) != digest(r.Services[i]) || !verifyService(cert, keys, r.Config.Admission) || cert.Item != digest(rec.Items) {
			return errors.New("invalid service certificate")
		}
		count := min(r.Config.Service, len(queue))
		if count == 0 || !sameItems(rec.Items, queue[:count]) {
			return errors.New("service did not take exact queue prefix")
		}
		approvals := []Statement{}
		for _, a := range r.Releases {
			if a.Round == cert.Round {
				approvals = append(approvals, a)
			}
		}
		seen := map[string]bool{}
		for _, a := range approvals {
			if a.Kind != "release" || len(a.Items) != 1 || a.Items[0] != cert.Item || !a.Verify(keys, ctx) || seen[a.Node] {
				return errors.New("invalid release approval")
			}
			seen[a.Node] = true
			releaseCount++
		}
		if len(seen) < r.Config.Release {
			return errors.New("insufficient release approvals")
		}
		executedIDs = append(executedIDs, rec.Items...)
		queue = queue[count:]
	}
	if err := appendThrough(maxRound); err != nil {
		return err
	}
	if len(queue) != 0 || len(expectedIDs) != len(admissions) || releaseCount != len(r.Releases) {
		return errors.New("incomplete queue drain or extra artifacts")
	}
	if len(executedIDs) != len(r.Openings) || len(r.Results) != len(executedIDs) {
		return errors.New("opening/result count mismatch")
	}
	orders := []Order{}
	for i, id := range executedIDs {
		opening := r.Openings[i]
		e := envelopes[id]
		if opening.ID != id || !verifyOpening(e, opening, r.UserKeys) || opening.Order != submissions[opening.Order.Ref()].Order {
			return errors.New("invalid opening, signature, or scenario plaintext")
		}
		orders = append(orders, opening.Order)
	}
	if err := AuditMarket(orders, r.Results, r.Config.InitialCash, r.Market); err != nil {
		return err
	}
	// These are unsigned virtual logs, not evidence of actual physical arrival time.
	registeredEvents := []string{}
	lockEvents := []string{}
	openEvents := []string{}
	executeEvents := []string{}
	lastTime := -1
	locked := map[string]bool{}
	registered := map[string]bool{}
	opened := map[string]bool{}
	for _, event := range r.Events {
		if event.Time < 0 || event.Time < lastTime {
			return errors.New("non-monotonic event time")
		}
		lastTime = event.Time
		switch event.Kind {
		case "registered":
			registeredEvents = append(registeredEvents, event.Order)
			registered[event.Order] = true
		case "service_locked":
			if !registered[event.Order] {
				return errors.New("lock before registration")
			}
			lockEvents = append(lockEvents, event.Order)
			locked[event.Order] = true
		case "decrypted":
			if !locked[event.Order] || opened[event.Order] {
				return errors.New("open before service lock")
			}
			opened[event.Order] = true
			openEvents = append(openEvents, event.Order)
		case "executed":
			if !opened[event.Order] {
				return errors.New("execution before opening")
			}
			executeEvents = append(executeEvents, event.Order)
		}
	}
	refs := []string{}
	for _, id := range executedIDs {
		e := envelopes[id]
		refs = append(refs, fmt.Sprintf("%s:%d", e.Header.Owner, e.Header.Nonce))
	}
	if !sameItems(registeredEvents, refs) || !sameItems(lockEvents, refs) || !sameItems(openEvents, refs) || !sameItems(executeEvents, refs) {
		return errors.New("event/result order mismatch")
	}
	return nil
}
func canonicalItems(items []string) bool {
	if items == nil || !sort.StringsAreSorted(items) {
		return false
	}
	for i := 1; i < len(items); i++ {
		if items[i] == items[i-1] {
			return false
		}
	}
	return true
}
func sameItems(a, b []string) bool {
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
