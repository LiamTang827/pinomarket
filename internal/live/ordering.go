package live

import "sort"

const (
	OrderingIdentity = "identity"
	// OrderingMedian borrows signed local observations and a median from AOAB.
	// It uses Pinocchio's existing committed lists, not AOAB's full protocol.
	OrderingMedian = "median-receipts"
)

type SequenceObservation struct {
	Node     string `json:"node"`
	Sequence int    `json:"sequence"`
}

type OrderRank struct {
	ID        string                `json:"id"`
	Qualified bool                  `json:"qualified"`
	Median    int                   `json:"median,omitempty"`
	Samples   []SequenceObservation `json:"samples"`
}

func identityLess(a, b Packet) bool {
	if a.Header.Owner != b.Header.Owner {
		return a.Header.Owner < b.Header.Owner
	}
	if a.Header.Nonce != b.Header.Nonce {
		return a.Header.Nonce < b.Header.Nonce
	}
	return a.ID() < b.ID()
}

// Lists have already been verified and fixed by consensus. Pick the first
// 2f+1 observations in member-ID order so no local map iteration affects output.
// A sparsely observed item still registers, AFTER qualified items, by the
// identity fallback. This preserves inclusion, not AOAB ordering linearizability.
func orderRegistration(m Manifest, lists []FinalList, packets map[string]Packet, ids []string) []OrderRank {
	if m.Policy.Ordering != OrderingMedian {
		sort.Slice(ids, func(i, j int) bool { return identityLess(packets[ids[i]], packets[ids[j]]) })
		return nil
	}
	byID := map[string][]SequenceObservation{}
	for _, list := range lists {
		for _, p := range list.Promises {
			byID[p.ID] = append(byID[p.ID], SequenceObservation{p.Node, p.Sequence})
		}
	}
	ranks := map[string]OrderRank{}
	needed := 2*m.Policy.Faults + 1
	for _, id := range ids {
		samples := byID[id]
		sort.Slice(samples, func(i, j int) bool { return samples[i].Node < samples[j].Node })
		rank := OrderRank{ID: id, Samples: samples}
		if len(samples) >= needed {
			rank.Qualified = true
			rank.Samples = samples[:needed]
			values := make([]int, needed)
			for i, s := range rank.Samples {
				values[i] = s.Sequence
			}
			sort.Ints(values)
			rank.Median = values[needed/2]
		}
		ranks[id] = rank
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := ranks[ids[i]], ranks[ids[j]]
		if a.Qualified != b.Qualified {
			return a.Qualified
		}
		if a.Median != b.Median {
			return a.Median < b.Median
		}
		return identityLess(packets[a.ID], packets[b.ID])
	})
	out := make([]OrderRank, 0, len(ids))
	for _, id := range ids {
		out = append(out, ranks[id])
	}
	return out
}
