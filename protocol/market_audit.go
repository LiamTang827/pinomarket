package protocol

import "fmt"

// AuditMarket 从明确的订单顺序独立推导成交和余额，检查已发布结果与最终状态。
// 它不调用撮合器，也不修改调用者提供的订单、结果或账户数据。
func AuditMarket(orders []Order, results []Result, initialCash map[string]int64, final *Market) error {
	if final == nil {
		return fmt.Errorf("market audit: final market is nil")
	}
	if len(results) != len(orders) {
		return fmt.Errorf("market audit: result count %d does not match order count %d", len(results), len(orders))
	}

	state := marketAuditState{
		cash:      map[string]int64{"alice": 1000, "bob": 1000, "carol": 1000, "seller": 0},
		shares:    map[string]int64{"alice": 0, "bob": 0, "carol": 0, "seller": 0},
		inventory: 10,
		seen:      make(map[string]bool),
	}
	for owner, amount := range initialCash {
		if _, exists := state.cash[owner]; !exists {
			return fmt.Errorf("market audit: unknown initial cash account %q", owner)
		}
		if amount < 0 {
			return fmt.Errorf("market audit: negative initial cash for %q", owner)
		}
		state.cash[owner] = amount
	}

	for i, order := range orders {
		expected := state.apply(order)
		if results[i] != expected {
			return fmt.Errorf("market audit: result %d for %s: got %+v, want %+v", i, expected.Order, results[i], expected)
		}
	}

	// 按固定账户集合逐项核对，防止总量守恒掩盖转错账户、缺账户或额外账户。
	if err := auditMarketBalances("cash", final.Cash, state.cash); err != nil {
		return err
	}
	if err := auditMarketBalances("shares", final.Shares, state.shares); err != nil {
		return err
	}
	if final.Inventory < 0 {
		return fmt.Errorf("market audit: negative final inventory %d", final.Inventory)
	}
	if final.Inventory != state.inventory {
		return fmt.Errorf("market audit: final inventory %d, want %d", final.Inventory, state.inventory)
	}
	if final.Closed != state.closed {
		return fmt.Errorf("market audit: final closed flag %t, want %t", final.Closed, state.closed)
	}
	return nil
}

// marketAuditState 只保存审计所需的模型状态，与执行器的内部状态相互独立。
type marketAuditState struct {
	cash      map[string]int64
	shares    map[string]int64
	inventory int64
	closed    bool
	seen      map[string]bool
}

func (s *marketAuditState) apply(order Order) Result {
	ref := fmt.Sprintf("%s:%d", order.Owner, order.Nonce)
	expected := Result{Order: ref, Status: "invalid"}
	if s.seen[ref] {
		expected.Status = "duplicate"
		return expected
	}
	// 首次出现即消耗 owner:nonce，包括后续业务权限检查失败或其他业务拒绝的订单。
	s.seen[ref] = true
	if order.Listing != "yes-1" {
		return expected
	}
	if order.Kind == "cancel" {
		if order.Owner != "seller" {
			expected.Status = "unauthorized"
			return expected
		}
		if s.closed {
			expected.Status = "already_cancelled"
			return expected
		}
		s.shares["seller"] += s.inventory
		s.inventory = 0
		s.closed = true
		expected.Status = "cancelled"
		return expected
	}
	if order.Kind != "buy" || order.Quantity < 1 || order.Quantity > 1000000 || order.Limit < 0 || order.Owner == "seller" {
		return expected
	}
	if _, exists := s.cash[order.Owner]; !exists {
		expected.Status = "unknown_account"
		return expected
	}
	if s.closed || s.inventory == 0 {
		expected.Status = "no_inventory"
		return expected
	}
	if order.Limit < 60 {
		expected.Status = "limit_not_met"
		return expected
	}

	fill := order.Quantity
	if fill > s.inventory {
		fill = s.inventory
	}
	cost := fill * 60
	// 只检验当前库存对应的完整成交金额；余额不足时整单不成交。
	if s.cash[order.Owner] < cost {
		expected.Status = "insufficient_funds"
		return expected
	}
	s.cash[order.Owner] -= cost
	s.cash["seller"] += cost
	s.shares[order.Owner] += fill
	s.inventory -= fill
	expected.Status = "filled"
	if fill < order.Quantity {
		expected.Status = "partially_filled"
	}
	expected.Filled = fill
	expected.Cost = cost
	return expected
}

func auditMarketBalances(kind string, actual, expected map[string]int64) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("market audit: final %s account count %d, want %d", kind, len(actual), len(expected))
	}
	for _, owner := range []string{"alice", "bob", "carol", "seller"} {
		amount, exists := actual[owner]
		if !exists {
			return fmt.Errorf("market audit: missing final %s account %q", kind, owner)
		}
		if amount < 0 {
			return fmt.Errorf("market audit: negative final %s for %q", kind, owner)
		}
		if amount != expected[owner] {
			return fmt.Errorf("market audit: final %s for %q is %d, want %d", kind, owner, amount, expected[owner])
		}
	}
	return nil
}
