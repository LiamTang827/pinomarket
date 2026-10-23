package live

import (
	"errors"
	"sort"
)

// Independently reconstruct the eligible union and deterministic placeholder
// order. Do not trust the stored queue or call the state's sorting function.
func auditRegistrationOrder(_ Manifest, r Registration, used map[string]bool) error {
	packets := map[string]Packet{}
	refs := map[string]map[string]bool{}
	for _, list := range r.Lists {
		for _, p := range list.Packets {
			id := p.ID()
			packets[id] = p
			if refs[p.Ref()] == nil {
				refs[p.Ref()] = map[string]bool{}
			}
			refs[p.Ref()][id] = true
		}
	}
	ids := []string{}
	for id, p := range packets {
		if !used[p.Ref()] && len(refs[p.Ref()]) == 1 {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := packets[ids[i]], packets[ids[j]]
		if a.Header.Owner != b.Header.Owner {
			return a.Header.Owner < b.Header.Owner
		}
		if a.Header.Nonce != b.Header.Nonce {
			return a.Header.Nonce < b.Header.Nonce
		}
		return ids[i] < ids[j]
	})
	if len(ids) != len(r.Items) {
		return errors.New("registration union is incomplete or contains extra orders")
	}
	for i, id := range ids {
		if id != r.Items[i] {
			return errors.New("registration violates deterministic placeholder order")
		}
	}
	return nil
}
