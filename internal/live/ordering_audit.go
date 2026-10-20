package live

import (
	"bytes"
	"errors"
	"sort"
)

// Reconstruct eligibility and ranking from signed lists, not from the state
// machine's sorting function or its stored rank assertions.
func auditRegistrationOrder(m Manifest, r Registration, used map[string]bool) error {
	packets := map[string]Packet{}
	refs := map[string]map[string]bool{}
	observations := map[string][]SequenceObservation{}
	for _, list := range r.Lists {
		for i, p := range list.Packets {
			id := p.ID()
			packets[id] = p
			if refs[p.Ref()] == nil {
				refs[p.Ref()] = map[string]bool{}
			}
			refs[p.Ref()][id] = true
			pr := list.Promises[i]
			observations[id] = append(observations[id], SequenceObservation{pr.Node, pr.Sequence})
		}
	}
	type entry struct {
		packet Packet
		rank   OrderRank
	}
	entries := []entry{}
	for id, p := range packets {
		if used[p.Ref()] || len(refs[p.Ref()]) != 1 {
			continue
		}
		rank := OrderRank{ID: id}
		if m.Policy.Ordering == OrderingMedian {
			samples := observations[id]
			sort.Slice(samples, func(i, j int) bool { return samples[i].Node < samples[j].Node })
			need := 2*m.Policy.Faults + 1
			rank.Qualified = len(samples) >= need
			if rank.Qualified {
				samples = samples[:need]
				values := []int{}
				for _, s := range samples {
					values = append(values, s.Sequence)
				}
				sort.Ints(values)
				rank.Median = values[m.Policy.Faults]
			}
			rank.Samples = samples
		}
		entries = append(entries, entry{p, rank})
	}
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if m.Policy.Ordering == OrderingMedian {
			if a.rank.Qualified != b.rank.Qualified {
				return a.rank.Qualified
			}
			if a.rank.Median != b.rank.Median {
				return a.rank.Median < b.rank.Median
			}
		}
		if a.packet.Header.Owner != b.packet.Header.Owner {
			return a.packet.Header.Owner < b.packet.Header.Owner
		}
		if a.packet.Header.Nonce != b.packet.Header.Nonce {
			return a.packet.Header.Nonce < b.packet.Header.Nonce
		}
		return a.rank.ID < b.rank.ID
	})
	if len(entries) != len(r.Items) {
		return errors.New("registration union is incomplete or contains extra orders")
	}
	if m.Policy.Ordering == OrderingMedian && len(r.Ordering) != len(entries) {
		return errors.New("missing median ordering evidence")
	}
	if m.Policy.Ordering != OrderingMedian && len(r.Ordering) != 0 {
		return errors.New("unexpected median ordering evidence")
	}
	for i, e := range entries {
		if e.rank.ID != r.Items[i] {
			return errors.New("registration violates committed ordering policy")
		}
		if m.Policy.Ordering == OrderingMedian && !bytes.Equal(JSON(e.rank), JSON(r.Ordering[i])) {
			return errors.New("median ordering evidence disagrees with signed observations")
		}
	}
	return nil
}
