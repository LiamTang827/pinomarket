package live

import "sort"

// OrderingIdentity is a deterministic execution placeholder, not a fairness rule.
const (
	OrderingIdentity = "identity"
	OrderingAion     = "aion"
)

// Multiple selected lists may contain distinct valid proofs for one envelope.
func preferRegistrationPacket(candidate, existing Packet) bool {
	if existing.TimeProof == nil {
		return true
	}
	if candidate.TimeProof.Timestamp() != existing.TimeProof.Timestamp() {
		return candidate.TimeProof.Timestamp() < existing.TimeProof.Timestamp()
	}
	return candidate.timeProofID() < existing.timeProofID()
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

// All eligible union members use the same rule, regardless of how many selected
// lists include them. Registered rounds retain FIFO order in the service queue.
func orderRegistration(packets map[string]Packet, ids []string) {
	sort.Slice(ids, func(i, j int) bool {
		a, b := packets[ids[i]], packets[ids[j]]
		if a.TimeProof != nil {
			if a.TimeProof.Timestamp() != b.TimeProof.Timestamp() {
				return a.TimeProof.Timestamp() < b.TimeProof.Timestamp()
			}
			return ids[i] < ids[j]
		}
		return identityLess(a, b)
	})
}
