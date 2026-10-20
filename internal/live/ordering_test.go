package live

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"testing"
)

func medianFixture(t *testing.T) liveTestFixture {
	f := newLiveTestFixture(t)
	f.manifest.Policy.Ordering = OrderingMedian
	f.manifest.Policy.QueueCapacity = 16
	f.manifest.Context = f.manifest.ContextID()
	return f
}

func sequencedList(f liveTestFixture, index, round int, packets ...Packet) FinalList {
	node := f.manifest.Peers[index].ID
	seq := map[string]int{}
	for i, p := range packets {
		seq[p.ID()] = i + 1
	}
	items := append([]Packet{}, packets...)
	sort.Slice(items, func(i, j int) bool { return items[i].ID() < items[j].ID() })
	l := FinalList{Context: f.manifest.Context, Node: node, Round: round, Packets: items, Promises: []Promise{}}
	for _, p := range items {
		l.Promises = append(l.Promises, NewSequencedPromise(f.manifest, node, round, p.ID(), seq[p.ID()], f.nodes[index]))
	}
	l.Signature = Sign(f.nodes[index], l.body())
	return l
}

func TestMedianRegistrationSignedObservationsAndIndependentAudit(t *testing.T) {
	f := medianFixture(t)
	a, b, c := f.packet(t, 1, "alice", 0), f.packet(t, 1, "bob", 0), f.packet(t, 1, "carol", 0)
	s := f.mustApply(t, NewState(f.manifest), 0, "open", nil, 1)
	s = f.register(t, s, 1, 5, sequencedList(f, 0, 1, b, a, c), sequencedList(f, 1, 1, b, a, c), sequencedList(f, 2, 1, a, c, b))
	if !equalStrings(s.Queue, []string{b.ID(), a.ID(), c.ID()}) {
		t.Fatal("median did not replace identity ordering")
	}
	for i, r := range s.Registrations[0].Ordering {
		if !r.Qualified || len(r.Samples) != 3 || r.Median != i+1 {
			t.Fatalf("bad rank: %+v", r)
		}
	}
	if err := AuditState(f.manifest, s); err != nil {
		t.Fatal(err)
	}
	bad := s.Clone()
	bad.Registrations[0].Ordering[0].Median = 99
	if err := AuditState(f.manifest, bad); err == nil {
		t.Fatal("auditor accepted invented median")
	}
	bad = s.Clone()
	bad.Registrations[0].Items[0], bad.Registrations[0].Items[1] = bad.Registrations[0].Items[1], bad.Registrations[0].Items[0]
	bad.Queue = append([]string{}, bad.Registrations[0].Items...)
	if err := AuditState(f.manifest, bad); err == nil {
		t.Fatal("auditor accepted self-consistent reordering")
	}
	bad = s.Clone()
	bad.Registrations[0].Items = bad.Registrations[0].Items[1:]
	bad.Registrations[0].Ordering = bad.Registrations[0].Ordering[1:]
	bad.Queue = bad.Queue[1:]
	if err := AuditState(f.manifest, bad); err == nil {
		t.Fatal("auditor accepted omitted union member")
	}
	for len(s.Queue) > 0 {
		s = f.serve(t, s, s.Height+1)
	}
	if err := AuditState(f.manifest, s); err != nil {
		t.Fatal(err)
	}
	if s.Results[0].Order != "bob:0" {
		t.Fatal("execution ignored median queue")
	}
}

func TestMedianSparseEvidenceKeepsInclusionWithExplicitFallback(t *testing.T) {
	f := medianFixture(t)
	a, b := f.packet(t, 1, "alice", 0), f.packet(t, 1, "bob", 0)
	s := f.mustApply(t, NewState(f.manifest), 0, "open", nil, 1)
	s = f.register(t, s, 1, 5, sequencedList(f, 0, 1, a, b), sequencedList(f, 1, 1, b), sequencedList(f, 2, 1, b))
	if !equalStrings(s.Queue, []string{b.ID(), a.ID()}) {
		t.Fatal("sparse fallback lost inclusion or precedes qualified item")
	}
	ranks := s.Registrations[0].Ordering
	if !ranks[0].Qualified || ranks[1].Qualified || ranks[1].Median != 0 || len(ranks[1].Samples) != 1 {
		t.Fatal("fallback must not assert a certified median")
	}
	if err := AuditState(f.manifest, s); err != nil {
		t.Fatal(err)
	}
}

func TestMedianRejectsTamperedDuplicateAndOutOfBudgetSequences(t *testing.T) {
	f := medianFixture(t)
	a, b := f.packet(t, 1, "alice", 0), f.packet(t, 1, "bob", 0)
	l := sequencedList(f, 0, 1, b, a)
	mutations := []func(*FinalList){
		func(l *FinalList) { l.Promises[0].Sequence = 0 },
		func(l *FinalList) { l.Promises[0].Sequence = 100 },
		func(l *FinalList) { l.Promises[0].Sequence = l.Promises[1].Sequence },
		func(l *FinalList) { l.Promises[0].Node = "node-2" },
	}
	for i, mutate := range mutations {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var bad FinalList
			if err := json.Unmarshal(JSON(l), &bad); err != nil {
				t.Fatal(err)
			}
			mutate(&bad)
			bad.Promises[0].Signature = Sign(f.nodes[0], bad.Promises[0].body())
			bad.Signature = Sign(f.nodes[0], bad.body())
			if err := bad.Validate(f.manifest, 4); err == nil {
				t.Fatal("accepted invalid observation")
			}
		})
	}
	pr := l.Promises[0]
	pr.Sequence++
	if err := pr.Validate(f.manifest); err == nil {
		t.Fatal("sequence is not signed")
	}
}

func TestMedianLocalSequenceSurvivesRestartAndDuplicateSubmission(t *testing.T) {
	f := medianFixture(t)
	dir := t.TempDir()
	machine, err := NewMachine(f.manifest, filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	machine.state = f.mustApply(t, NewState(f.manifest), 0, "open", nil, 1)
	makeNode := func() *liveNode {
		return &liveNode{cfg: NodeConfig{Manifest: f.manifest}, peer: f.manifest.Peers[0], private: f.nodes[0], machine: machine, journalPath: filepath.Join(dir, "admission.json")}
	}
	n := makeNode()
	if err := n.loadJournal(); err != nil {
		t.Fatal(err)
	}
	a, b := f.packet(t, 1, "alice", 0), f.packet(t, 1, "bob", 0)
	first, err := n.accept(b)
	if err != nil || first.Sequence != 1 {
		t.Fatalf("first: %+v %v", first, err)
	}
	n = makeNode()
	if err := n.loadJournal(); err != nil {
		t.Fatal(err)
	}
	again, err := n.accept(b)
	if err != nil || !bytes.Equal(JSON(first), JSON(again)) {
		t.Fatal("restart changed receipt")
	}
	second, err := n.accept(a)
	if err != nil || second.Sequence != 2 {
		t.Fatalf("second: %+v %v", second, err)
	}
}

func TestMedianOrderingIgnoresListArrivalAndMapIteration(t *testing.T) {
	f := medianFixture(t)
	a, b := f.packet(t, 1, "alice", 0), f.packet(t, 1, "bob", 0)
	lists := []FinalList{sequencedList(f, 0, 1, b, a), sequencedList(f, 1, 1, b, a), sequencedList(f, 2, 1, a, b)}
	packets := map[string]Packet{a.ID(): a, b.ID(): b}
	ids := []string{a.ID(), b.ID()}
	one := orderRegistration(f.manifest, lists, packets, ids)
	lists[0], lists[2] = lists[2], lists[0]
	reversed := []string{b.ID(), a.ID()}
	two := orderRegistration(f.manifest, lists, packets, reversed)
	if !equalStrings(ids, reversed) || !bytes.Equal(JSON(one), JSON(two)) {
		t.Fatal("non-deterministic ordering")
	}
}
