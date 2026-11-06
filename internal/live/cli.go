package live

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/LiamTang827/pinomarket/protocol"
)

func RequestJSON(ctx context.Context, method, url string, input, output any) error {
	var body io.Reader
	if input != nil {
		body = bytes.NewReader(JSON(input))
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 4 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	b, err := io.ReadAll(io.LimitReader(response.Body, 8*1024*1024))
	if err != nil {
		return err
	}
	if response.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", response.StatusCode, string(b))
	}
	if output != nil {
		return json.Unmarshal(b, output)
	}
	return nil
}
func FetchState(ctx context.Context, m Manifest) (*State, error) {
	var last error
	for _, p := range m.Peers {
		var s State
		if err := RequestJSON(ctx, "GET", p.API+"/state", nil, &s); err == nil {
			return &s, nil
		} else {
			last = err
		}
	}
	return nil, fmt.Errorf("no reachable node: %v", last)
}
func OpenRound(ctx context.Context, m Manifest) (*Round, error) {
	s, err := FetchState(ctx, m)
	if err != nil {
		return nil, err
	}
	previous := 0
	if s.Round != nil {
		previous = s.Round.Number
		if !s.Round.Registered {
			return s.Round, nil
		}
	}
	accepted := false
	for _, p := range m.Peers {
		if RequestJSON(ctx, "POST", p.API+"/open", struct{}{}, nil) == nil {
			accepted = true
			break
		}
	}
	if !accepted {
		return nil, errors.New("no node accepted round request")
	}
	for {
		state, e := FetchState(ctx, m)
		if e == nil && state.Round != nil && state.Round.Number > previous {
			return state.Round, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

type SubmissionReceipt struct {
	Packet         Packet             `json:"packet"`
	Promises       []Promise          `json:"promises"`
	Errors         map[string]string  `json:"node_errors"`
	Quorum         bool               `json:"quorum_obtained"`
	NodeResponseMS map[string]float64 `json:"node_response_ms,omitempty"`
	QuorumMS       *float64           `json:"quorum_ms,omitempty"`
}

// VerifyReceipt authenticates client-collected promises independently of whether
// the packet was eventually registered. A valid partial receipt is not a quorum.
func VerifyReceipt(m Manifest, receipt SubmissionReceipt) (int, error) {
	if err := receipt.Packet.ValidateAdmission(m); err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	for _, promise := range receipt.Promises {
		if err := promise.Validate(m); err != nil {
			return 0, err
		}
		if seen[promise.Node] {
			return 0, errors.New("duplicate receipt member")
		}
		if !promise.matches(receipt.Packet) {
			return 0, errors.New("receipt promise does not match packet/round")
		}
		seen[promise.Node] = true
	}
	return len(seen), nil
}

func certifyPacketTime(ctx context.Context, m Manifest, p Packet) (Packet, error) {
	if err := p.Validate(m); err != nil {
		return p, err
	}
	if m.Policy.Ordering == OrderingAion && p.TimeProof == nil {
		lastErr := errors.New("no configured time-proof origin")
		for _, peer := range m.Peers {
			var proof TimeProof
			lastErr = RequestJSON(ctx, "POST", peer.API+"/aion/prove", p, &proof)
			if lastErr == nil {
				lastErr = proof.Validate(m, p)
			}
			if lastErr == nil {
				p.TimeProof = &proof
				break
			}
			if ctx.Err() != nil {
				break
			}
		}
		if p.TimeProof == nil {
			return p, fmt.Errorf("certify packet time: %w", lastErr)
		}
	}
	return p, p.ValidateAdmission(m)
}

func SubmitPacket(ctx context.Context, m Manifest, p Packet) (SubmissionReceipt, error) {
	started := time.Now()
	certified, err := certifyPacketTime(ctx, m, p)
	if err != nil {
		return SubmissionReceipt{Packet: p}, err
	}
	return submitCertified(ctx, m, certified, started), nil
}

func submitCertified(ctx context.Context, m Manifest, p Packet, started time.Time) SubmissionReceipt {
	out := SubmissionReceipt{Packet: p, Promises: []Promise{}, Errors: map[string]string{}, NodeResponseMS: map[string]float64{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, peer := range m.Peers {
		wg.Add(1)
		go func(peer Peer) {
			defer wg.Done()
			var pr Promise
			err := RequestJSON(ctx, "POST", peer.API+"/submit", p, &pr)
			if err == nil {
				err = pr.Validate(m)
				if err == nil && (pr.Node != peer.ID || !pr.matches(p)) {
					err = errors.New("receipt does not match contacted member/order")
				}
			}
			mu.Lock()
			defer mu.Unlock()
			elapsed := float64(time.Since(started)) / float64(time.Millisecond)
			out.NodeResponseMS[peer.ID] = elapsed
			if err != nil {
				out.Errors[peer.ID] = err.Error()
			} else {
				out.Promises = append(out.Promises, pr)
				if len(out.Promises) == m.Policy.Quorum {
					value := elapsed
					out.QuorumMS = &value
				}
			}
		}(peer)
	}
	wg.Wait()
	out.Quorum = len(out.Promises) >= m.Policy.Quorum
	return out
}
func RunCLI(args []string) error {
	if len(args) == 0 {
		fmt.Println("network init|node|ready|open|prepare|submit|verify-receipt|measure|benchmark|wait|status|audit|evm-config|evm-batch (use -h after command)")
		return nil
	}
	fs := flag.NewFlagSet("network "+args[0], flag.ContinueOnError)
	dir := fs.String("dir", "runs/local-network", "network directory")
	config := fs.String("config", "", "private node configuration")
	processed := fs.Int("processed", 1, "completed business commands to wait for")
	nodes := fs.Int("nodes", 5, "validator count")
	t := fs.Int("threshold", 3, "decryption threshold")
	capacity := fs.Int("queue-capacity", 30, "global queue capacity")
	service := fs.Int("service-capacity", 2, "orders per service")
	window := fs.Int64("window-blocks", 30, "admission window in consensus blocks")
	base := fs.Int("base-port", 26656, "Comet base P2P port (RPC=base+1, next node+10)")
	api := fs.Int("api-port", 28000, "first application HTTP port")
	interval := fs.Duration("block-interval", 500*time.Millisecond, "minimum block commit interval")
	ordering := fs.String("ordering", OrderingIdentity, "init only: identity or aion")
	ingress := fs.String("ingress", "", "init only: software to simulate protected admission records; empty keeps baseline (no real TEE/TNIC)")
	clockSkew := fs.Int64("clock-skew-ms", 5, "aion: assumed clock skew bound in milliseconds")
	delayVariation := fs.Int64("delay-variation-ms", 75, "aion: assumed delay variation bound in milliseconds")
	maxDelay := fs.Int64("max-calibrated-delay-ms", 1000, "aion: maximum accepted delay estimate in milliseconds")
	evm := fs.Bool("evm", false, "init only: enable EVM service certificates")
	batchNumber := fs.Int("number", 1, "evm-batch: completed service number")
	listing := fs.String("listing", "yes-1", "market identifier or evm:<chain id>:<contract>")
	owner := fs.String("owner", "alice", "wallet name")
	prepareRound := fs.Int("round", 0, "prepare only: encrypt for this round before admission opens")
	kind := fs.String("kind", "buy", "buy, sell (EVM), or cancel (local market)")
	quantity := fs.Int64("quantity", 1, "share quantity")
	limit := fs.Int64("limit", 60, "limit in cents")
	nonce := fs.Int("nonce", 0, "unique wallet command number")
	out := fs.String("out", "", "public receipt output file")
	packetFile := fs.String("packet", "", "resend an existing packet or receipt file")
	refuse := fs.Bool("refuse", false, "fault: refuse admission")
	omit := fs.Bool("omit-list", false, "fault: publish empty final list")
	withhold := fs.Bool("withhold-shares", false, "fault: do not release own shares")
	delay := fs.Int("delay-ms", 0, "delay incoming submissions")
	count := fs.Int("count", 3, "measure: number of purchases across alice, bob and carol")
	samples := fs.Int("samples", 30, "benchmark: warmed samples per local operation (identity baseline)")
	timeout := fs.Duration("timeout", 60*time.Second, "client operation deadline")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if args[0] == "init" {
		var aion *AionPolicy
		if *ordering == OrderingAion {
			aion = &AionPolicy{ClockSkewMS: *clockSkew, DelayVariationMS: *delayVariation, MaxDelayMS: *maxDelay}
		}
		m, err := InitNetwork(*dir, InitOptions{Nodes: *nodes, Threshold: *t, QueueCapacity: *capacity, ServiceCapacity: *service, BasePort: *base, APIPort: *api, WindowBlocks: *window, BlockInterval: *interval, Ordering: *ordering, Ingress: *ingress, Aion: aion, EVM: *evm})
		if err != nil {
			return err
		}
		fmt.Printf("Initialized %d independent validator configurations; q=%d t=%d\nContext: %s\nStart one 'network node -config %s/nodeN.json' process per node.\n", len(m.Peers), m.Policy.Quorum, m.Policy.Threshold, m.Context, *dir)
		if m.Policy.Ingress == IngressSoftware {
			fmt.Println("Ingress: SOFTWARE SIMULATION ONLY; host-readable keys and local clock, no hardware attestation.")
		}
		if m.Policy.Ordering == OrderingAion {
			fmt.Println("Ordering: Aion-style certified timestamps within each registered round.")
		}
		return nil
	}
	if args[0] == "node" {
		var cfg NodeConfig
		if err := ReadJSON(*config, &cfg); err != nil {
			return err
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return RunNode(ctx, cfg, NodeOptions{Refuse: *refuse, OmitList: *omit, WithholdShares: *withhold, DelayMS: *delay})
	}
	m, err := LoadManifest(*dir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	switch args[0] {
	case "evm-config", "evm-batch":
		if !m.Policy.EVM {
			return errors.New("initialize network with -evm")
		}
		if args[0] == "evm-config" {
			fmt.Println(string(JSON(evmConfig(m))))
			return nil
		}
		if *batchNumber < 1 {
			return errors.New("batch number must be positive")
		}
		cert, err := fetchEVMBatch(ctx, m, *batchNumber)
		if err != nil {
			return err
		}
		fmt.Println(string(JSON(cert)))
	case "verify-receipt":
		if *packetFile == "" {
			return errors.New("verify-receipt requires -packet receipt file")
		}
		var receipt SubmissionReceipt
		if err := ReadJSON(*packetFile, &receipt); err != nil {
			return err
		}
		count, err := VerifyReceipt(m, receipt)
		if err != nil {
			return err
		}
		fmt.Println(string(JSON(map[string]any{"verified": true, "promises": count, "quorum": count >= m.Policy.Quorum})))
	case "benchmark":
		return BenchmarkCompute(ctx, m, *dir, *samples, *out)
	case "measure":
		if *out == "" {
			return errors.New("measure requires a new -out directory")
		}
		return MeasureNetwork(ctx, m, *count, *nonce, *quantity, *limit, *dir, *out)
	case "open":
		round, err := OpenRound(ctx, m)
		if err != nil {
			return err
		}
		fmt.Println(string(JSON(round)))
	case "submit", "prepare":
		var packet Packet
		if *packetFile != "" {
			var receipt SubmissionReceipt
			if err := ReadJSON(*packetFile, &receipt); err != nil {
				return err
			}
			packet = receipt.Packet
		} else {
			round := *prepareRound
			if args[0] != "prepare" || round <= 0 {
				s, err := FetchState(ctx, m)
				if err != nil {
					return err
				}
				if s.Round == nil || s.Round.Registered || s.Height >= s.Round.CloseHeight {
					return errors.New("open an admission round first")
				}
				round = s.Round.Number
			}
			var key []byte
			if err = ReadJSON(filepath.Join(*dir, "wallets", *owner+".json"), &key); err != nil {
				return err
			}
			packet, err = NewPacket(m, round, protocol.Order{Owner: *owner, Nonce: *nonce, Kind: *kind, Listing: *listing, Quantity: *quantity, Limit: *limit}, ed25519.PrivateKey(key))
			if err != nil {
				return err
			}
		}
		if args[0] == "prepare" {
			if *out == "" {
				return errors.New("prepare requires a new -out file")
			}
			if _, err := os.Stat(*out); err == nil {
				return errors.New("prepare output already exists")
			}
			if err := AtomicJSON(*out, map[string]any{"packet": packet, "packet_id": packet.ID()}); err != nil {
				return err
			}
			fmt.Printf("Prepared encrypted order %s; packet=%s (not submitted)\n", packet.Ref(), packet.ID())
			return nil
		}
		if *out != "" {
			if _, err := os.Stat(*out); !os.IsNotExist(err) {
				return errors.New("receipt output must be a new file")
			}
		}
		started := time.Now()
		packet, err = certifyPacketTime(ctx, m, packet)
		if err != nil {
			return err
		}
		if *out != "" && packet.TimeProof != nil {
			// Keep the exact evidence before any node can sign a promise for it.
			// If interrupted, the file can be used as the next submit's -packet.
			if err := AtomicJSON(*out, SubmissionReceipt{Packet: packet, Promises: []Promise{}}); err != nil {
				return err
			}
		}
		receipt := submitCertified(ctx, m, packet, started)
		if *out != "" {
			if err := AtomicJSON(*out, receipt); err != nil {
				return err
			}
		}
		fmt.Printf("Order %s: %d/%d distinct signed promises; quorum=%v\n", packet.Ref(), len(receipt.Promises), m.Policy.Quorum, receipt.Quorum)
		if !receipt.Quorum {
			return fmt.Errorf("admission quorum not reached (errors: %v)", receipt.Errors)
		}
	case "ready":
		for {
			reachable := 0
			for _, peer := range m.Peers {
				var health struct {
					Height int64 `json:"height"`
				}
				if RequestJSON(ctx, "GET", peer.API+"/health", nil, &health) == nil && health.Height > 0 {
					reachable++
				}
			}
			if reachable == len(m.Peers) {
				fmt.Println("All independent nodes are producing committed blocks.")
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
	case "wait":
		for {
			state, err := FetchState(ctx, m)
			if err == nil && len(state.Results) >= *processed {
				printStatus(state)
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
	case "status":
		s, err := FetchState(ctx, m)
		if err != nil {
			return err
		}
		printStatus(s)
	case "audit":
		result, err := AuditNetwork(ctx, m)
		if err != nil {
			return err
		}
		if *out != "" {
			if _, err := os.Stat(*out); err == nil {
				return errors.New("audit output already exists")
			}
			if err := AtomicJSON(*out, result); err != nil {
				return err
			}
		}
		fmt.Println(string(JSON(result)))
	default:
		return fmt.Errorf("unknown network command %q", args[0])
	}
	return nil
}

func printStatus(s *State) {
	var round any
	var service any
	if s.Round != nil {
		round = map[string]any{"number": s.Round.Number, "open_height": s.Round.OpenHeight, "close_height": s.Round.CloseHeight, "per_node_capacity": s.Round.Capacity, "complete_lists": len(s.Round.Lists), "registered": s.Round.Registered}
	}
	if s.Active != nil {
		service = map[string]any{"number": s.Active.Number, "id": s.Active.ID, "orders": len(s.Active.Items), "committed_height": s.Active.Height}
	}
	fmt.Println(string(JSON(map[string]any{"height": s.Height, "round": round, "queued": len(s.Queue), "active_service": service, "results": s.Results, "market": s.Market, "evidence": len(s.Evidence)})))
}
