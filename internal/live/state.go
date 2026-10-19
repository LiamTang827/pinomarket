package live

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/LiamTang827/pinocchio-market/protocol"
	"github.com/LiamTang827/pinocchio-market/threshold"
)

type Round struct {
	Number      int         `json:"number"`
	OpenHeight  int64       `json:"open_height"`
	CloseHeight int64       `json:"close_height"`
	Capacity    int         `json:"per_node_capacity"`
	Lists       []FinalList `json:"lists"`
	Registered  bool        `json:"registered"`
}

func (r Round) HasList(node string) bool {
	for _, l := range r.Lists {
		if l.Node == node {
			return true
		}
	}
	return false
}

type Registration struct {
	Round  int         `json:"round"`
	Height int64       `json:"height"`
	Lists  []FinalList `json:"selected_lists"`
	Items  []string    `json:"ordered_ids"`
}
type Lock struct {
	Number int                                    `json:"number"`
	ID     string                                 `json:"id"`
	Height int64                                  `json:"height"`
	Items  []string                               `json:"items"`
	Shares map[string][]threshold.DecryptionShare `json:"shares"`
}
type ShareBatch struct {
	LockID string                               `json:"lock_id"`
	Shares map[string]threshold.DecryptionShare `json:"shares"`
}
type Evidence struct {
	Promise Promise   `json:"promise"`
	List    FinalList `json:"final_list"`
}

func (e Evidence) Validate(m Manifest) error {
	if err := e.Promise.Validate(m); err != nil {
		return err
	}
	if err := e.List.Validate(m, m.Policy.QueueCapacity); err != nil {
		return err
	}
	if e.Promise.Node != e.List.Node || e.Promise.Round != e.List.Round || e.List.Has(e.Promise.ID) {
		return errors.New("not an omission contradiction")
	}
	return nil
}

type State struct {
	Height        int64             `json:"height"`
	Context       string            `json:"context"`
	Round         *Round            `json:"round"`
	Queue         []string          `json:"queue"`
	Orders        map[string]Packet `json:"orders"`
	Used          map[string]string `json:"used_commands"`
	Registrations []Registration    `json:"registrations"`
	Active        *Lock             `json:"active_service"`
	Services      []Lock            `json:"services"`
	Openings      []Opened          `json:"openings"`
	Results       []protocol.Result `json:"results"`
	Market        *protocol.Market  `json:"market"`
	Evidence      []Evidence        `json:"evidence"`
}

func NewState(m Manifest) *State {
	return &State{Context: m.Context, Queue: []string{}, Orders: map[string]Packet{}, Used: map[string]string{}, Market: protocol.NewMarket(), Results: []protocol.Result{}, Openings: []Opened{}, Registrations: []Registration{}, Services: []Lock{}, Evidence: []Evidence{}}
}
func (s *State) Clone() *State {
	var out State
	if err := json.Unmarshal(JSON(s), &out); err != nil {
		panic(err)
	}
	return &out
}
func decode(t SignedTx, v any) error { return json.Unmarshal(t.Payload, v) }

// Apply is deterministic and runs identically in all validators. Rejected
// transactions must not mutate s: callers apply each transaction to a clone.
func (s *State) Apply(m Manifest, t SignedTx, height int64) error {
	switch t.Type {
	case "open":
		if s.Round != nil && !s.Round.Registered {
			return errors.New("previous round still open")
		}
		round := 1
		if s.Round != nil {
			round = s.Round.Number + 1
		}
		var request struct {
			Round int `json:"round"`
		}
		if err := decode(t, &request); err != nil || request.Round != round {
			return errors.New("open round replay/mismatch")
		}
		free := m.Policy.QueueCapacity - len(s.Queue)
		if free < 0 {
			return errors.New("queue over capacity")
		}
		s.Round = &Round{Number: round, OpenHeight: height, CloseHeight: height + m.Policy.WindowBlocks, Capacity: free / m.Policy.Nodes, Lists: []FinalList{}}
	case "list":
		var l FinalList
		if err := decode(t, &l); err != nil {
			return err
		}
		r := s.Round
		if r == nil || r.Registered || height <= r.CloseHeight || l.Round != r.Number || l.Node != t.Node || r.HasList(l.Node) {
			return errors.New("list outside sealing phase or duplicate")
		}
		if err := l.Validate(m, r.Capacity); err != nil {
			return err
		}
		r.Lists = append(r.Lists, l)
	case "register":
		r := s.Round
		if r == nil || r.Registered || len(r.Lists) < m.Policy.Quorum {
			return errors.New("not enough complete lists")
		}
		var request struct {
			Round int `json:"round"`
		}
		if err := decode(t, &request); err != nil || request.Round != r.Number {
			return errors.New("registration round replay/mismatch")
		}
		selected := append([]FinalList{}, r.Lists[:m.Policy.Quorum]...)
		packets := map[string]Packet{}
		refs := map[string]map[string]bool{}
		for _, l := range selected {
			for _, p := range l.Packets {
				packets[p.ID()] = p
				if refs[p.Ref()] == nil {
					refs[p.Ref()] = map[string]bool{}
				}
				refs[p.Ref()][p.ID()] = true
			}
		}
		ids := []string{}
		for id, p := range packets {
			if len(refs[p.Ref()]) == 1 && s.Used[p.Ref()] == "" {
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
		if len(s.Queue)+len(ids) > m.Policy.QueueCapacity {
			return errors.New("registration exceeds reserved queue capacity")
		}
		for _, id := range ids {
			p := packets[id]
			s.Queue = append(s.Queue, id)
			s.Orders[id] = p
			s.Used[p.Ref()] = id
		}
		s.Registrations = append(s.Registrations, Registration{r.Number, height, selected, ids})
		r.Registered = true
	case "lock":
		if s.Active != nil || len(s.Queue) == 0 {
			return errors.New("no unlocked queue prefix")
		}
		var request struct {
			Number int    `json:"number"`
			Head   string `json:"head"`
		}
		if err := decode(t, &request); err != nil || request.Number != len(s.Services)+1 || request.Head != s.Queue[0] {
			return errors.New("service number/head replay mismatch")
		}
		count := min(m.Policy.ServiceCapacity, len(s.Queue))
		ids := append([]string{}, s.Queue[:count]...)
		number := len(s.Services) + 1
		s.Active = &Lock{Number: number, Height: height, Items: ids, Shares: map[string][]threshold.DecryptionShare{}}
		s.Active.ID = Hash(struct {
			Context string
			Number  int
			Items   []string
		}{m.Context, number, ids})
	case "shares":
		var batch ShareBatch
		if err := decode(t, &batch); err != nil {
			return err
		}
		lock := s.Active
		peer, _ := m.Peer(t.Node)
		if lock == nil || lock.ID != batch.LockID || height <= lock.Height || len(batch.Shares) == 0 || len(batch.Shares) > len(lock.Items) {
			return errors.New("shares before finalized service or for wrong lock")
		}
		for id, share := range batch.Shares {
			if !Contains(lock.Items, id) || share.Index != peer.Index {
				return errors.New("unauthorized share index/order")
			}
			if err := threshold.VerifyDecryptionShare(m.Crypto, s.Orders[id].Wrapped, share); err != nil {
				return err
			}
			for _, previous := range lock.Shares[id] {
				if previous.Index == share.Index {
					return errors.New("duplicate share")
				}
			}
		}
		for id, share := range batch.Shares {
			lock.Shares[id] = append(lock.Shares[id], share)
		}
	case "execute":
		lock := s.Active
		if lock == nil {
			return errors.New("no active service")
		}
		var request struct {
			LockID string `json:"lock_id"`
		}
		if err := decode(t, &request); err != nil || request.LockID != lock.ID {
			return errors.New("execute service replay/mismatch")
		}
		for _, id := range lock.Items {
			if len(lock.Shares[id]) < m.Policy.Threshold {
				return errors.New("waiting for threshold shares")
			}
		}
		for _, id := range lock.Items {
			p := s.Orders[id]
			shares := append([]threshold.DecryptionShare{}, lock.Shares[id]...)
			sort.Slice(shares, func(i, j int) bool { return shares[i].Index < shares[j].Index })
			opened, err := OpenPacket(m, p, shares)
			if err != nil {
				s.Results = append(s.Results, protocol.Result{Order: p.Ref(), Status: "invalid_encrypted_payload"})
				continue
			}
			s.Openings = append(s.Openings, opened)
			s.Results = append(s.Results, s.Market.Execute(opened.Order))
		}
		s.Queue = s.Queue[len(lock.Items):]
		s.Services = append(s.Services, *lock)
		s.Active = nil
	case "evidence":
		var e Evidence
		if err := decode(t, &e); err != nil {
			return err
		}
		if err := e.Validate(m); err != nil {
			return err
		}
		for _, old := range s.Evidence {
			if Hash(old) == Hash(e) {
				return errors.New("duplicate evidence")
			}
		}
		s.Evidence = append(s.Evidence, e)
	default:
		return fmt.Errorf("unknown transaction type %s", t.Type)
	}
	return nil
}
func Contains(xs []string, x string) bool {
	for _, a := range xs {
		if a == x {
			return true
		}
	}
	return false
}
