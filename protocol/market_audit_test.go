package protocol

import (
	"reflect"
	"strings"
	"testing"
)

// 执行器仅用于生成测试样本；被测审计器必须自行计算期望值。
func executeMarketAuditOrders(orders []Order, initialCash map[string]int64) ([]Result, *Market) {
	market := NewMarket()
	for owner, cash := range initialCash {
		market.Cash[owner] = cash
	}
	results := make([]Result, 0, len(orders))
	for _, order := range orders {
		results = append(results, market.Execute(order))
	}
	return results, market
}

func TestAuditMarketAcceptsExecutionRules(t *testing.T) {
	buy := func(owner string, nonce int, quantity, limit int64) Order {
		return Order{Owner: owner, Nonce: nonce, Kind: "buy", Listing: "yes-1", Quantity: quantity, Limit: limit}
	}
	cancel := func(owner string, nonce int) Order {
		return Order{Owner: owner, Nonce: nonce, Kind: "cancel", Listing: "yes-1"}
	}
	tests := []struct {
		name        string
		orders      []Order
		initialCash map[string]int64
		statuses    []string
	}{
		{name: "empty"},
		{name: "full partial and exhausted", orders: []Order{buy("alice", 0, 3, 60), buy("bob", 0, 20, 70), buy("carol", 0, 1, 60)}, statuses: []string{"filled", "partially_filled", "no_inventory"}},
		{name: "funds all or fail", orders: []Order{buy("alice", 0, 3, 60), buy("bob", 0, 9, 60)}, initialCash: map[string]int64{"alice": 179, "bob": 600, "seller": 5}, statuses: []string{"insufficient_funds", "filled"}},
		{name: "funds for available fill", orders: []Order{buy("alice", 0, 8, 60), buy("bob", 0, 10, 60)}, initialCash: map[string]int64{"bob": 120}, statuses: []string{"filled", "partially_filled"}},
		{name: "seller cancellation releases remainder", orders: []Order{buy("alice", 0, 3, 60), cancel("seller", 0), buy("bob", 0, 1, 60), cancel("seller", 1)}, statuses: []string{"filled", "cancelled", "no_inventory", "already_cancelled"}},
		{name: "cancel exhausted listing", orders: []Order{buy("alice", 0, 10, 60), cancel("seller", 0)}, statuses: []string{"filled", "cancelled"}},
		{name: "unauthorized consumes nonce", orders: []Order{cancel("alice", 0), buy("alice", 0, 1, 60), cancel("outsider", 0)}, statuses: []string{"unauthorized", "duplicate", "unauthorized"}},
		{name: "business failure consumes nonce", orders: []Order{buy("alice", 0, 1, 59), buy("alice", 0, 1, 60)}, statuses: []string{"limit_not_met", "duplicate"}},
		{name: "listing checked before cancel authorization", orders: []Order{{Owner: "alice", Nonce: 0, Kind: "cancel", Listing: "other"}, buy("alice", 0, 1, 60)}, statuses: []string{"invalid", "duplicate"}},
		{name: "buy validation", orders: []Order{buy("alice", 0, 0, 60), buy("alice", 1, -1, 60), buy("alice", 2, 1000001, 60), buy("alice", 3, 1, -1), buy("seller", 0, 1, 60), buy("outsider", 0, 1, 60), {Owner: "bob", Nonce: 0, Kind: "sell", Listing: "yes-1"}}, statuses: []string{"invalid", "invalid", "invalid", "invalid", "invalid", "unknown_account", "invalid"}},
		{name: "maximum quantity is valid", orders: []Order{buy("alice", 0, 1000000, 60)}, statuses: []string{"partially_filled"}},
		{name: "inventory precedes limit", orders: []Order{cancel("seller", 0), buy("alice", 0, 1, 59)}, statuses: []string{"cancelled", "no_inventory"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results, market := executeMarketAuditOrders(test.orders, test.initialCash)
			for i, status := range test.statuses {
				if results[i].Status != status {
					t.Fatalf("result %d status = %q, want %q", i, results[i].Status, status)
				}
			}
			if err := AuditMarket(test.orders, results, test.initialCash, market); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAuditMarketRejectsTampering(t *testing.T) {
	orders := []Order{{Owner: "alice", Nonce: 0, Kind: "buy", Listing: "yes-1", Quantity: 3, Limit: 60}}
	tests := []struct {
		name   string
		tamper func(*[]Result, *Market)
		want   string
	}{
		{name: "cost", tamper: func(results *[]Result, market *Market) { (*results)[0].Cost++ }, want: "result 0"},
		{name: "status", tamper: func(results *[]Result, market *Market) { (*results)[0].Status = "partially_filled" }, want: "result 0"},
		{name: "fill", tamper: func(results *[]Result, market *Market) { (*results)[0].Filled++ }, want: "result 0"},
		{name: "order reference", tamper: func(results *[]Result, market *Market) { (*results)[0].Order = "bob:0" }, want: "result 0"},
		{name: "removed result", tamper: func(results *[]Result, market *Market) { *results = nil }, want: "result count"},
		{name: "extra result", tamper: func(results *[]Result, market *Market) { *results = append(*results, (*results)[0]) }, want: "result count"},
		{name: "cash transfer preserves total", tamper: func(results *[]Result, market *Market) { market.Cash["alice"]--; market.Cash["bob"]++ }, want: "final cash"},
		{name: "shares transfer preserves total", tamper: func(results *[]Result, market *Market) { market.Shares["alice"]--; market.Shares["bob"]++ }, want: "final shares"},
		{name: "negative cash", tamper: func(results *[]Result, market *Market) { market.Cash["alice"] = -1 }, want: "negative final cash"},
		{name: "negative shares", tamper: func(results *[]Result, market *Market) { market.Shares["alice"] = -1 }, want: "negative final shares"},
		{name: "missing cash account", tamper: func(results *[]Result, market *Market) { delete(market.Cash, "carol") }, want: "cash account count"},
		{name: "extra shares account", tamper: func(results *[]Result, market *Market) { market.Shares["outsider"] = 0 }, want: "shares account count"},
		{name: "replaced account", tamper: func(results *[]Result, market *Market) { delete(market.Cash, "carol"); market.Cash["outsider"] = 1000 }, want: "missing final cash"},
		{name: "inventory", tamper: func(results *[]Result, market *Market) { market.Inventory++ }, want: "final inventory"},
		{name: "negative inventory", tamper: func(results *[]Result, market *Market) { market.Inventory = -1 }, want: "negative final inventory"},
		{name: "closed flag", tamper: func(results *[]Result, market *Market) { market.Closed = true }, want: "final closed flag"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results, market := executeMarketAuditOrders(orders, nil)
			test.tamper(&results, market)
			err := AuditMarket(orders, results, nil, market)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got error %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestAuditMarketRejectsUnauthorizedCancellation(t *testing.T) {
	orders := []Order{{Owner: "alice", Nonce: 0, Kind: "cancel", Listing: "yes-1"}}
	results, market := executeMarketAuditOrders(orders, nil)
	if err := AuditMarket(orders, results, nil, market); err != nil {
		t.Fatalf("valid rejection of cancellation failed audit: %v", err)
	}
	// 伪造取消结果并同步篡改状态，总份额仍守恒，审计仍应拒绝。
	results[0].Status = "cancelled"
	market.Shares["seller"] = market.Inventory
	market.Inventory = 0
	market.Closed = true
	if err := AuditMarket(orders, results, nil, market); err == nil {
		t.Fatal("unauthorized cancellation passed audit")
	}
}

func TestAuditMarketRejectsInvalidInputs(t *testing.T) {
	for _, cash := range []map[string]int64{{"outsider": 10}, {"alice": -1}} {
		if err := AuditMarket(nil, nil, cash, NewMarket()); err == nil {
			t.Fatalf("invalid initial cash accepted: %v", cash)
		}
	}
	if err := AuditMarket(nil, nil, nil, nil); err == nil {
		t.Fatal("nil final market accepted")
	}
}

func TestAuditMarketDoesNotMutateInputs(t *testing.T) {
	orders := []Order{{Owner: "alice", Nonce: 0, Kind: "buy", Listing: "yes-1", Quantity: 3, Limit: 60}}
	initialCash := map[string]int64{"alice": 500}
	results, market := executeMarketAuditOrders(orders, initialCash)
	ordersBefore := append([]Order(nil), orders...)
	resultsBefore := append([]Result(nil), results...)
	_, marketBefore := executeMarketAuditOrders(orders, initialCash)
	if err := AuditMarket(orders, results, initialCash, market); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(orders, ordersBefore) || !reflect.DeepEqual(results, resultsBefore) || !reflect.DeepEqual(market, marketBefore) || initialCash["alice"] != 500 || len(initialCash) != 1 {
		t.Fatal("audit mutated its inputs")
	}
}
