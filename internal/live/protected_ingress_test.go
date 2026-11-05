package live

import (
	"crypto/ed25519"
	"crypto/rand"
	"sort"
	"testing"
)

func softwareIngressFixture(t *testing.T) (liveTestFixture, []ed25519.PrivateKey) {
	t.Helper()
	f := newLiveTestFixture(t)
	f.manifest.Policy.Ingress = IngressSoftware
	keys := make([]ed25519.PrivateKey, len(f.manifest.Peers))
	for i := range f.manifest.Peers {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		f.manifest.Peers[i].IngressKey = public
		keys[i] = private
	}
	f.manifest.Context = f.manifest.ContextID()
	if err := f.manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	return f, keys
}

func softwareIngressList(t *testing.T, f liveTestFixture, key ed25519.PrivateKey, index, round int, received []Packet) FinalList {
	t.Helper()
	node := f.manifest.Peers[index].ID
	records := make([]IngressRecord, 0, len(received))
	byID := make(map[string]IngressRecord, len(received))
	head := ""
	for i, packet := range received {
		record := NewIngressRecord(f.manifest, node, round, packet.ID(), uint64(i+1), int64(100+i), head, key)
		records = append(records, record)
		byID[packet.ID()] = record
		head = Hash(record)
	}
	seal, err := NewIngressSeal(f.manifest, node, round, records, key)
	if err != nil {
		t.Fatal(err)
	}
	packets := append([]Packet{}, received...)
	sort.Slice(packets, func(i, j int) bool { return packets[i].ID() < packets[j].ID() })
	list := FinalList{Context: f.manifest.Context, Node: node, Round: round, Packets: packets, Promises: []Promise{}, IngressSeal: &seal}
	for _, packet := range packets {
		record := byID[packet.ID()]
		promise := NewPromise(f.manifest, node, round, packet.ID(), f.nodes[index])
		promise.Ingress = &record
		promise.Signature = Sign(f.nodes[index], promise.body())
		list.Promises = append(list.Promises, promise)
	}
	list.Signature = Sign(f.nodes[index], list.body())
	return list
}

func copySoftwareList(t *testing.T, l FinalList) FinalList {
	t.Helper()
	var copied FinalList
	if err := decode(SignedTx{Payload: JSON(l)}, &copied); err != nil {
		t.Fatal(err)
	}
	return copied
}

func TestSoftwareIngressRecordBindingsAndLocalChain(t *testing.T) {
	f, keys := softwareIngressFixture(t)
	a := f.packet(t, 1, "alice", 0)
	b := f.packet(t, 1, "bob", 0)
	node := f.manifest.Peers[0].ID
	first := NewIngressRecord(f.manifest, node, 1, a.ID(), 1, 100, "", keys[0])
	second := NewIngressRecord(f.manifest, node, 1, b.ID(), 2, 100, Hash(first), keys[0])
	// Equal wall-clock observations are permitted; the signed local sequence is
	// authoritative within this adapter and is not a global ordering policy.
	head, err := ValidateIngressRecords(f.manifest, node, 1, []IngressRecord{second, first})
	if err != nil || head != Hash(second) {
		t.Fatalf("valid record chain rejected: head=%s err=%v", head, err)
	}
	for name, mutate := range map[string]func(*IngressRecord){
		"time":       func(r *IngressRecord) { r.ReceivedUnixNano++ },
		"sequence":   func(r *IngressRecord) { r.Sequence++ },
		"ciphertext": func(r *IngressRecord) { r.ID = b.ID() },
		"node":       func(r *IngressRecord) { r.Node = f.manifest.Peers[1].ID },
		"round":      func(r *IngressRecord) { r.Round++ },
		"context":    func(r *IngressRecord) { r.Context = "other-session" },
		"mode":       func(r *IngressRecord) { r.Mode = "hardware" },
	} {
		t.Run(name, func(t *testing.T) {
			r := first
			mutate(&r)
			if err := r.Validate(f.manifest); err == nil {
				t.Fatal("mutated ingress record verified")
			}
		})
	}
	if _, err := ValidateIngressRecords(f.manifest, node, 1, []IngressRecord{second}); err == nil {
		t.Fatal("missing first record accepted")
	}
	duplicate := NewIngressRecord(f.manifest, node, 1, a.ID(), 2, 101, Hash(first), keys[0])
	if _, err := ValidateIngressRecords(f.manifest, node, 1, []IngressRecord{first, duplicate}); err == nil {
		t.Fatal("same packet accepted twice in a chain")
	}
	backwards := NewIngressRecord(f.manifest, node, 1, b.ID(), 2, 99, Hash(first), keys[0])
	if _, err := ValidateIngressRecords(f.manifest, node, 1, []IngressRecord{first, backwards}); err == nil {
		t.Fatal("backwards clock observation accepted")
	}
}

func TestSoftwareIngressSealDetectsOmissionAndTampering(t *testing.T) {
	f, keys := softwareIngressFixture(t)
	a := f.packet(t, 1, "alice", 0)
	b := f.packet(t, 1, "bob", 0)
	list := softwareIngressList(t, f, keys[0], 0, 1, []Packet{b, a})
	if err := list.Validate(f.manifest, 2); err != nil {
		t.Fatalf("sealed list rejected: %v", err)
	}
	for name, mutate := range map[string]func(*FinalList){
		"omit": func(l *FinalList) {
			l.Packets = l.Packets[:1]
			l.Promises = l.Promises[:1]
		},
		"omit-all": func(l *FinalList) {
			l.Packets = []Packet{}
			l.Promises = []Promise{}
		},
		"replace-seal-head":  func(l *FinalList) { l.IngressSeal.Head = Hash("replacement") },
		"replace-seal-count": func(l *FinalList) { l.IngressSeal.Count = 0 },
		"omit-seal":          func(l *FinalList) { l.IngressSeal = nil },
		"omit-record":        func(l *FinalList) { l.Promises[0].Ingress = nil },
		"edit-record": func(l *FinalList) {
			l.Promises[0].Ingress.ReceivedUnixNano++
			l.Promises[0].Signature = Sign(f.nodes[0], l.Promises[0].body())
		},
		"swap-records": func(l *FinalList) {
			l.Promises[0].Ingress, l.Promises[1].Ingress = l.Promises[1].Ingress, l.Promises[0].Ingress
			for i := range l.Promises {
				l.Promises[i].Signature = Sign(f.nodes[0], l.Promises[i].body())
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := copySoftwareList(t, list)
			mutate(&changed)
			// Re-sign with the ordinary member key: protected evidence is checked
			// independently, so this cannot make a changed seal/record valid.
			changed.Signature = Sign(f.nodes[0], changed.body())
			if err := changed.Validate(f.manifest, 2); err == nil {
				t.Fatal("changed signed list accepted")
			}
		})
	}
	wrong := copySoftwareList(t, list)
	wrong.IngressSeal.Signature = Sign(keys[1], wrong.IngressSeal.body())
	wrong.Signature = Sign(f.nodes[0], wrong.body())
	if err := wrong.Validate(f.manifest, 2); err == nil {
		t.Fatal("another member's ingress seal accepted")
	}
}

func TestSoftwareIngressEmptyRoundAndConfigurationBinding(t *testing.T) {
	f, keys := softwareIngressFixture(t)
	empty := softwareIngressList(t, f, keys[0], 0, 1, nil)
	if empty.IngressSeal.Count != 0 || empty.IngressSeal.Head != "" {
		t.Fatal("unexpected empty seal")
	}
	if err := empty.Validate(f.manifest, 2); err != nil {
		t.Fatalf("empty sealed round rejected: %v", err)
	}
	if _, err := NewIngressSeal(f.manifest, f.manifest.Peers[0].ID, 1, nil, keys[1]); err == nil {
		t.Fatal("seal signed using a different member's key")
	}
	changed := f.manifest
	changed.Session = "another-session"
	changed.Context = changed.ContextID()
	if err := ValidateIngressList(changed, empty); err == nil {
		t.Fatal("seal replayed in another context")
	}
	baseline := f.manifest
	baseline.Policy.Ingress = ""
	if err := ValidateIngressList(baseline, empty); err == nil {
		t.Fatal("unexpected ingress seal accepted by baseline")
	}
	plain := newLiveTestFixture(t)
	packet := plain.packet(t, 1, "alice", 0)
	ordinary := plain.list(0, 1, packet)
	if err := ordinary.Validate(plain.manifest, 2); err != nil {
		t.Fatalf("baseline behavior changed: %v", err)
	}
	ordinary.Promises[0].Ingress = &IngressRecord{}
	if err := ValidateIngressPromise(plain.manifest, ordinary.Promises[0]); err == nil {
		t.Fatal("unexpected ingress record accepted by baseline")
	}
}
