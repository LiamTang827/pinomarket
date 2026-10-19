package protocol

type Result struct {
	Order  string `json:"order"`
	Status string `json:"status"`
	Filled int64  `json:"filled"`
	Cost   int64  `json:"cost_cents"`
}
type Market struct {
	Cash      map[string]int64 `json:"cash_cents"`
	Shares    map[string]int64 `json:"yes_shares"`
	Inventory int64            `json:"locked_seller_inventory"`
	Closed    bool             `json:"listing_cancelled"`
	processed map[string]bool
}

func NewMarket() *Market {
	return &Market{Cash: map[string]int64{"alice": 1000, "bob": 1000, "carol": 1000, "seller": 0}, Shares: map[string]int64{"alice": 0, "bob": 0, "carol": 0, "seller": 0}, Inventory: 10, processed: map[string]bool{}}
}

// One pre-funded listing, price 60 cents. No minting, AMM, oracle, or external chain.
func (m *Market) Execute(o Order) Result {
	r := Result{Order: o.Ref(), Status: "invalid"}
	if m.processed[o.Ref()] {
		r.Status = "duplicate"
		return r
	}
	m.processed[o.Ref()] = true
	if o.Listing != "yes-1" {
		return r
	}
	if o.Kind == "cancel" {
		if o.Owner != "seller" {
			r.Status = "unauthorized"
			return r
		}
		if m.Closed {
			r.Status = "already_cancelled"
			return r
		}
		m.Shares["seller"] += m.Inventory
		m.Inventory = 0
		m.Closed = true
		r.Status = "cancelled"
		return r
	}
	if o.Kind != "buy" || o.Quantity <= 0 || o.Quantity > 1000000 || o.Limit < 0 || o.Owner == "seller" {
		return r
	}
	if _, ok := m.Cash[o.Owner]; !ok {
		r.Status = "unknown_account"
		return r
	}
	if m.Closed || m.Inventory == 0 {
		r.Status = "no_inventory"
		return r
	}
	if o.Limit < 60 {
		r.Status = "limit_not_met"
		return r
	}
	fill := min(o.Quantity, m.Inventory)
	// All-or-fail funds check for the fill available at execution; no pre-reservation.
	if m.Cash[o.Owner] < fill*60 {
		r.Status = "insufficient_funds"
		return r
	}
	m.Cash[o.Owner] -= fill * 60
	m.Cash["seller"] += fill * 60
	m.Shares[o.Owner] += fill
	m.Inventory -= fill
	r.Status = "filled"
	if fill < o.Quantity {
		r.Status = "partially_filled"
	}
	r.Filled = fill
	r.Cost = fill * 60
	return r
}
