package live

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/LiamTang827/pinocchio-market/protocol"
)

type MeasuredOrder struct {
	ID            string           `json:"id"`
	Ref           string           `json:"ref"`
	EncryptMS     float64          `json:"encrypt_ms"`
	SubmitMS      float64          `json:"submitted_at_ms"`
	QuorumMS      *float64         `json:"admission_quorum_ms,omitempty"`
	RegisteredMS  *float64         `json:"registration_observed_at_ms,omitempty"`
	LockedMS      *float64         `json:"lock_observed_at_ms,omitempty"`
	SharesReadyMS *float64         `json:"shares_ready_observed_at_ms,omitempty"`
	ProcessedMS   *float64         `json:"processing_observed_at_ms,omitempty"`
	Quorum        bool             `json:"quorum_obtained"`
	Result        *protocol.Result `json:"result,omitempty"`
}

type Measurement struct {
	Schema        int                `json:"schema"`
	Mode          string             `json:"mode"`
	Context       string             `json:"context"`
	Policy        Policy             `json:"policy"`
	Round         int                `json:"round"`
	Orders        []MeasuredOrder    `json:"orders"`
	Submitted     int                `json:"submitted"`
	Admitted      int                `json:"admitted"`
	Registered    int                `json:"registered"`
	Processed     int                `json:"processed"`
	Filled        int                `json:"filled"`
	Incomplete    int                `json:"incomplete"`
	PollErrors    int                `json:"poll_errors"`
	DurationMS    float64            `json:"duration_ms"`
	ProcessedTPS  float64            `json:"processed_tps"`
	CompletionMS  map[string]float64 `json:"completion_ms"`
	AuditVerified bool               `json:"audit_verified"`
	Error         string             `json:"error,omitempty"`
	Limitations   string             `json:"limitations"`
}

// observe measures first CLIENT POLL visibility, not exact server timestamps.
// Heights/locks are protocol evidence; these elapsed times are local telemetry.
func (m *Measurement) observe(s *State, elapsed float64) {
	if s == nil {
		return
	}
	for i := range m.Orders {
		o := &m.Orders[i]
		stamp := func(dst **float64) {
			if *dst == nil {
				v := elapsed
				*dst = &v
			}
		}
		if _, ok := s.Orders[o.ID]; !ok {
			// A previously used owner/nonce may name a DIFFERENT encrypted packet.
			// Its old business result cannot complete this submitted packet.
			continue
		}
		stamp(&o.RegisteredMS)
		locks := append([]Lock{}, s.Services...)
		if s.Active != nil {
			locks = append(locks, *s.Active)
		}
		for _, lock := range locks {
			if Contains(lock.Items, o.ID) {
				stamp(&o.LockedMS)
				if len(lock.Shares[o.ID]) >= m.Policy.Threshold {
					stamp(&o.SharesReadyMS)
				}
			}
		}
		for _, r := range s.Results {
			if r.Order == o.Ref {
				stamp(&o.ProcessedMS)
				value := r
				o.Result = &value
				break
			}
		}
	}
}

func (m *Measurement) summarize() {
	m.Submitted = len(m.Orders)
	m.Admitted = 0
	m.Registered = 0
	m.Processed = 0
	m.Filled = 0
	completion := []float64{}
	for _, o := range m.Orders {
		if o.Quorum {
			m.Admitted++
		}
		if o.RegisteredMS != nil {
			m.Registered++
		}
		if o.ProcessedMS != nil {
			m.Processed++
			completion = append(completion, *o.ProcessedMS-o.SubmitMS)
		}
		if o.Result != nil && o.Result.Filled > 0 {
			m.Filled++
		}
	}
	m.Incomplete = m.Submitted - m.Processed
	m.CompletionMS = map[string]float64{}
	if len(completion) > 0 {
		sort.Float64s(completion)
		for name, p := range map[string]float64{"p50": 0.5, "p95": 0.95, "p99": 0.99} {
			index := int(float64(len(completion)) * p)
			if float64(index) < float64(len(completion))*p {
				index++
			}
			index--
			if index < 0 {
				index = 0
			}
			m.CompletionMS[name] = completion[index]
		}
	}
	if m.DurationMS > 0 {
		m.ProcessedTPS = float64(m.Processed) * 1000 / m.DurationMS
	}
}

// MeasureNetwork submits a bounded workload to an already running network.
// It uses normal wallet encryption/admission and performs a real chain audit.
// Failed quorum submissions remain in the denominator: they may still register.
func MeasureNetwork(ctx context.Context, manifest Manifest, count, nonce int, quantity, limit int64, networkDir, out string) (runErr error) {
	if count < 1 || count > 80 || nonce < 0 || nonce > 1_000_000 || quantity < 1 || limit < 0 {
		return errors.New("invalid bounded measurement workload")
	}
	if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
		return err
	}
	if err := os.Mkdir(out, 0700); err != nil {
		return fmt.Errorf("measurement output must be new: %w", err)
	}
	measurement := Measurement{Schema: 1, Mode: "real-local-processes", Context: manifest.Context, Policy: manifest.Policy, Orders: []MeasuredOrder{}, Limitations: "Client monotonic clock; stage times are first successful poll observations (upper bounds), not physical arrival proofs. This bounded run includes window wait and is not saturation throughput or a global WAN benchmark. Incomplete orders remain counted; real threshold crypto and CometBFT are used."}
	started := time.Now()
	defer func() {
		if measurement.DurationMS == 0 {
			measurement.DurationMS = float64(time.Since(started)) / float64(time.Millisecond)
		}
		measurement.summarize()
		if runErr != nil {
			measurement.Error = runErr.Error()
		}
		if err := AtomicJSON(filepath.Join(out, "metrics.json"), measurement); runErr == nil && err != nil {
			runErr = err
		}
	}()
	round, err := OpenRound(ctx, manifest)
	if err != nil {
		return err
	}
	measurement.Round = round.Number
	// Avoid measuring a client racing the propagation of the open-round commit
	// as an ordering-policy difference. Offline members need not become ready.
	for {
		ready := 0
		for _, peer := range manifest.Peers {
			var state State
			if RequestJSON(ctx, "GET", peer.API+"/state", nil, &state) == nil && state.Round != nil && state.Round.Number == round.Number && !state.Round.Registered && state.Height < state.Round.CloseHeight {
				ready++
			}
		}
		if ready >= manifest.Policy.Quorum {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	var mu sync.Mutex
	observeCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			s, e := FetchState(observeCtx, manifest)
			mu.Lock()
			if e != nil {
				measurement.PollErrors++
			} else {
				measurement.observe(s, float64(time.Since(started))/float64(time.Millisecond))
			}
			mu.Unlock()
			select {
			case <-observeCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() { cancel(); <-done }()
	owners := []string{"alice", "bob", "carol"}
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		owner := owners[i%len(owners)]
		var key []byte
		if err := ReadJSON(filepath.Join(networkDir, "wallets", owner+".json"), &key); err != nil {
			return err
		}
		encryptStart := time.Now()
		packet, err := NewPacket(manifest, round.Number, protocol.Order{Owner: owner, Nonce: nonce + i/len(owners), Kind: "buy", Listing: "yes-1", Quantity: quantity, Limit: limit}, ed25519.PrivateKey(key))
		if err != nil {
			return err
		}
		sample := MeasuredOrder{ID: packet.ID(), Ref: packet.Ref(), EncryptMS: float64(time.Since(encryptStart)) / float64(time.Millisecond), SubmitMS: float64(time.Since(started)) / float64(time.Millisecond)}
		mu.Lock()
		measurement.Orders = append(measurement.Orders, sample)
		sampleIndex := len(measurement.Orders) - 1
		mu.Unlock()
		receipt, err := SubmitPacket(ctx, manifest, packet)
		if err != nil {
			return err
		}
		if err := AtomicJSON(filepath.Join(out, fmt.Sprintf("receipt-%03d.json", i)), receipt); err != nil {
			return err
		}
		mu.Lock()
		measurement.Orders[sampleIndex].Quorum = receipt.Quorum
		measurement.Orders[sampleIndex].QuorumMS = receipt.QuorumMS
		mu.Unlock()
	}
	for {
		mu.Lock()
		measurement.summarize()
		complete := measurement.Processed == measurement.Submitted
		mu.Unlock()
		if complete {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	cancel()
	<-done
	measurement.DurationMS = float64(time.Since(started)) / float64(time.Millisecond)
	measurement.summarize()
	audit, err := AuditNetwork(ctx, manifest)
	if err != nil {
		return fmt.Errorf("measurement audit: %w", err)
	}
	if err := AtomicJSON(filepath.Join(out, "audit.json"), audit); err != nil {
		return err
	}
	measurement.AuditVerified = true
	fmt.Printf("Measured %d submitted, %d processed, %d fills; metrics: %s\n", measurement.Submitted, measurement.Processed, measurement.Filled, filepath.Join(out, "metrics.json"))
	return nil
}
