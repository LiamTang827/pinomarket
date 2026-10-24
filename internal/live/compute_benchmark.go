package live

// Local API microbenchmarks. These functions do not submit transactions or change
// consensus state. Full API timings deliberately retain their nested validation.
import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/LiamTang827/pinomarket/protocol"
	"github.com/LiamTang827/pinomarket/threshold"
)

type OperationCost struct {
	Samples   int       `json:"samples"`
	Warmups   int       `json:"warmups"`
	MeanMS    float64   `json:"mean_ms"`
	MinMS     float64   `json:"min_ms"`
	P50MS     float64   `json:"p50_ms"`
	P95MS     float64   `json:"p95_ms"`
	MaxMS     float64   `json:"max_ms"`
	SamplesMS []float64 `json:"samples_ms"`
	Includes  string    `json:"includes"`
}

type ComputeCosts struct {
	Schema         int                      `json:"schema"`
	Mode           string                   `json:"mode"`
	Context        string                   `json:"context"`
	Nodes          int                      `json:"nodes"`
	Threshold      int                      `json:"threshold"`
	Samples        int                      `json:"samples_per_operation"`
	Runtime        map[string]any           `json:"runtime"`
	FixtureSizes   map[string]int           `json:"fixture_sizes_bytes"`
	Operations     map[string]OperationCost `json:"operations"`
	FixtureSetupMS float64                  `json:"fixture_setup_ms"`
	Error          string                   `json:"error,omitempty"`
	Limitations    string                   `json:"limitations"`
}

func summarizeOperation(values []float64, warmups int, includes string) OperationCost {
	out := OperationCost{Samples: len(values), Warmups: warmups, SamplesMS: values, Includes: includes}
	if len(values) == 0 {
		return out
	}
	sorted := append([]float64{}, values...)
	sort.Float64s(sorted)
	for _, value := range values {
		out.MeanMS += value / float64(len(values))
	}
	index := func(p float64) int {
		i := int(float64(len(sorted)) * p)
		if float64(i) < float64(len(sorted))*p {
			i++
		}
		if i < 1 {
			i = 1
		}
		return i - 1
	}
	out.MinMS, out.MaxMS = sorted[0], sorted[len(sorted)-1]
	out.P50MS, out.P95MS = sorted[index(.50)], sorted[index(.95)]
	return out
}

func timeOperation(ctx context.Context, samples int, includes string, f func() error) (OperationCost, error) {
	values := make([]float64, 0, samples)
	warmups := 0
	for i := 0; i < 3+samples; i++ {
		if err := ctx.Err(); err != nil {
			return summarizeOperation(values, warmups, includes), err
		}
		started := time.Now()
		err := f()
		elapsed := float64(time.Since(started)) / float64(time.Millisecond)
		if err != nil {
			return summarizeOperation(values, warmups, includes), err
		}
		if i < 3 {
			warmups++
			continue
		}
		values = append(values, elapsed)
	}
	return summarizeOperation(values, warmups, includes), nil
}

// BenchmarkCompute reads only local demo keys, returns only sizes/timings and
// public context, and creates a new output file. Secret values are never logged.
func BenchmarkCompute(ctx context.Context, m Manifest, dir string, samples int, out string) (runErr error) {
	if samples < 1 || samples > 10000 || out == "" {
		return errors.New("benchmark requires 1..10000 samples and a new output file")
	}
	if err := m.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	report := ComputeCosts{Schema: 1, Mode: "serial-local-api-wall-time", Context: m.Context, Nodes: m.Policy.Nodes, Threshold: m.Policy.Threshold, Samples: samples,
		Runtime:      map[string]any{"go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "logical_cpus": runtime.NumCPU(), "gomaxprocs": runtime.GOMAXPROCS(0)},
		FixtureSizes: map[string]int{}, Operations: map[string]OperationCost{},
		Limitations: "Sequential warmed local API elapsed times, not isolated CPU cycles or a security/performance proof. Nested full APIs overlap and MUST NOT be summed; timings include repeated configuration/ciphertext/share validation, allocations and serialization where used by that API. Fixed small valid inputs and t shares. Fixture setup, DKG provisioning, disk/network/consensus and AI calls excluded from operation timings. No node workload runs concurrently in this runner phase; node background consensus may remain active."}
	defer func() {
		if runErr != nil {
			report.Error = runErr.Error()
		}
		if _, err := file.Write(append(JSON(report), '\n')); runErr == nil && err != nil {
			runErr = err
		}
	}()
	setup := time.Now()
	var wallet []byte
	if err := ReadJSON(filepath.Join(dir, "wallets", "alice.json"), &wallet); err != nil {
		return err
	}
	var config NodeConfig
	if err := ReadJSON(filepath.Join(dir, "node0.json"), &config); err != nil {
		return err
	}
	if config.Manifest.Context != m.Context || len(config.Private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.PrivateKey(config.Private).Public().(ed25519.PublicKey), m.Peers[0].Key) {
		return errors.New("benchmark local config mismatch")
	}
	order := protocol.Order{Owner: "alice", Nonce: 0, Kind: "buy", Listing: "yes-1", Quantity: 1, Limit: 60}
	packet, err := NewPacket(m, 1, order, ed25519.PrivateKey(wallet))
	if err != nil {
		return err
	}
	plain := JSON(Body{order, Sign(ed25519.PrivateKey(wallet), orderAuth(packet.Header, order))})
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return err
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	aad := JSON(packet.Header)
	// A fixed ciphertext is used only for the decryption timing fixture. Encryption
	// benchmarks below use a fresh nonce each call.
	packetNonceFixture := append([]byte{}, nonce...)
	body := gcm.Seal(nil, packetNonceFixture, plain, aad)
	wrapped, err := threshold.Encrypt(m.Crypto, []byte("benchmark-only"), key)
	if err != nil {
		return err
	}
	shares := []threshold.DecryptionShare{}
	packetShares := []threshold.DecryptionShare{}
	for i := 0; i < m.Policy.Threshold; i++ {
		var c NodeConfig
		if err = ReadJSON(filepath.Join(dir, fmt.Sprintf("node%d.json", i)), &c); err != nil {
			return err
		}
		s, e := threshold.CreateDecryptionShare(m.Crypto, c.Share, wrapped)
		if e != nil {
			return e
		}
		shares = append(shares, s)
		ps, e := threshold.CreateDecryptionShare(m.Crypto, c.Share, packet.Wrapped)
		if e != nil {
			return e
		}
		packetShares = append(packetShares, ps)
	}
	packetID := packet.ID()
	promise := NewPromise(m, m.Peers[0].ID, 1, packetID, ed25519.PrivateKey(config.Private))
	list := FinalList{Context: m.Context, Node: m.Peers[0].ID, Round: 1}
	for i := 0; i < 4; i++ {
		o := order
		o.Nonce = i
		p, e := NewPacket(m, 1, o, ed25519.PrivateKey(wallet))
		if e != nil {
			return e
		}
		list.Packets = append(list.Packets, p)
	}
	sort.Slice(list.Packets, func(i, j int) bool { return list.Packets[i].ID() < list.Packets[j].ID() })
	for _, p := range list.Packets {
		list.Promises = append(list.Promises, NewPromise(m, m.Peers[0].ID, 1, p.ID(), ed25519.PrivateKey(config.Private)))
	}
	list.Signature = Sign(ed25519.PrivateKey(config.Private), list.body())
	report.FixtureSizes = map[string]int{"signed_packet_json": len(JSON(packet)), "signed_body_plaintext_json": len(plain), "aes_plaintext": len(plain), "aes_ciphertext": len(body), "wrapped_key_json": len(JSON(wrapped)), "promise_json": len(JSON(promise)), "complete_list_4_json": len(JSON(list)), "decryption_share_json": len(JSON(shares[0])), "threshold_plaintext": len(key)}
	report.FixtureSetupMS = float64(time.Since(setup)) / float64(time.Millisecond)
	operations := []struct {
		name, includes string
		f              func() error
	}{
		{"packet_create_full", "Two user signatures, JSON, fresh AES key/nonce, AES-GCM, threshold key encryption and its configuration checks", func() error { _, e := NewPacket(m, 1, order, ed25519.PrivateKey(wallet)); return e }},
		{"packet_validate_full", "Outer signature/binding and threshold ciphertext/configuration validation", func() error { return packet.Validate(m) }},
		{"aes_gcm_encrypt_body", "Fresh nonce generation plus AES-GCM over signed-order-sized fixture and public header AAD", func() error {
			if _, e := rand.Read(nonce); e != nil {
				return e
			}
			_ = gcm.Seal(nil, nonce, plain, aad)
			return nil
		}},
		{"aes_gcm_decrypt_body", "AES-GCM authentication and opening; no threshold operation", func() error { _, e := gcm.Open(nil, packetNonceFixture, body, aad); return e }},
		{"threshold_encrypt_key_full", "Encrypt 32-byte key with fresh identity nonce and full configuration validation", func() error { _, e := threshold.Encrypt(m.Crypto, []byte("benchmark-only"), key); return e }},
		{"promise_sign", "NewPromise JSON serialization and Ed25519 signature", func() error {
			_ = NewPromise(m, m.Peers[0].ID, 1, packetID, ed25519.PrivateKey(config.Private))
			return nil
		}},
		{"promise_verify", "Promise context/member checks, JSON and Ed25519 verification", func() error { return promise.Validate(m) }},
		{"complete_list_sign_4", "Sign full JSON list of four packets and promises", func() error { _ = Sign(ed25519.PrivateKey(config.Private), list.body()); return nil }},
		{"complete_list_validate_4", "List signature plus four full packet/promise validations", func() error { return list.Validate(m, 4) }},
		{"threshold_share_create_full", "Share creation includes ciphertext/config validation and an internal share verification", func() error { _, e := threshold.CreateDecryptionShare(m.Crypto, config.Share, wrapped); return e }},
		{"threshold_share_verify_full", "Full envelope/config/ciphertext checks and BLS pairing verification", func() error { return threshold.VerifyDecryptionShare(m.Crypto, wrapped, shares[0]) }},
		{"threshold_decrypt_t_shares_full", "Reverify t shares, interpolate key and authenticate threshold ciphertext", func() error { _, e := threshold.Decrypt(m.Crypto, wrapped, shares); return e }},
		{"packet_open_full", "Threshold decryption including t share verifications, AES-GCM, decode and inner signature verification", func() error { _, e := OpenPacket(m, packet, packetShares); return e }},
		{"market_new_and_execute_one", "Initialize fresh in-memory market and execute a single valid purchase; no signatures/consensus", func() error {
			r := protocol.NewMarket().Execute(order)
			if r.Status != "filled" {
				return errors.New("benchmark execution failed")
			}
			return nil
		}},
	}
	for _, op := range operations {
		result, e := timeOperation(ctx, samples, op.includes, op.f)
		report.Operations[op.name] = result
		if e != nil {
			return fmt.Errorf("%s: %w", op.name, e)
		}
	}
	return nil
}
