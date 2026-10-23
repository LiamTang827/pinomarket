package live

import "sort"

// OrderingIdentity is a deterministic execution placeholder, not a fairness rule.
const OrderingIdentity = "identity"

func identityLess(a, b Packet) bool {
	if a.Header.Owner != b.Header.Owner {
		return a.Header.Owner < b.Header.Owner
	}
	if a.Header.Nonce != b.Header.Nonce {
		return a.Header.Nonce < b.Header.Nonce
	}
	return a.ID() < b.ID()
}

// All eligible union members use the same rule, regardless of how many selected
// lists include them. Registered rounds retain FIFO order in the service queue.
func orderRegistration(packets map[string]Packet, ids []string) {
	sort.Slice(ids, func(i, j int) bool { return identityLess(packets[ids[i]], packets[ids[j]]) })
}
