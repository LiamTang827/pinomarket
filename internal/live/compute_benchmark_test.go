package live

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOperationCostQuantilesAndCancellation(t *testing.T) {
	s := summarizeOperation([]float64{4, 1, 3, 2}, 3, "full API")
	if s.MeanMS != 2.5 || s.P50MS != 2 || s.P95MS != 4 || s.MinMS != 1 || s.MaxMS != 4 {
		t.Fatalf("wrong statistics: %+v", s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	partial, err := timeOperation(ctx, 3, "cancelled", func() error { calls++; return nil })
	if err == nil || partial.Samples != 0 || calls != 0 {
		t.Fatal("cancelled benchmark invented successful timings")
	}
}

func TestComputeBenchmarkValidatesActualAPIsAndPreservesOutput(t *testing.T) {
	f := newLiveTestFixture(t)
	dir := t.TempDir()
	if err := AtomicJSON(filepath.Join(dir, "wallets", "alice.json"), []byte(f.users["alice"])); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < f.manifest.Policy.Threshold; i++ {
		c := NodeConfig{Manifest: f.manifest, Index: i, Private: []byte(f.nodes[i]), Share: f.secrets[i]}
		if err := AtomicJSON(filepath.Join(dir, "node"+string(rune('0'+i))+".json"), c); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "compute.json")
	if err := BenchmarkCompute(context.Background(), f.manifest, dir, 2, out); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var result ComputeCosts
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Operations) != 14 || result.Error != "" || result.Threshold != 3 || result.FixtureSizes["signed_packet_json"] == 0 {
		t.Fatalf("missing actual measurements: %+v", result)
	}
	for name, s := range result.Operations {
		if s.Samples != 2 || s.Warmups != 3 || len(s.SamplesMS) != 2 || s.MeanMS <= 0 {
			t.Fatalf("invalid %s sample: %+v", name, s)
		}
	}
	if bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(f.nodes[0]))) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(f.secrets[0].Value))) {
		t.Fatal("private benchmark fixtures escaped into output")
	}
	if err := BenchmarkCompute(context.Background(), f.manifest, dir, 2, out); err == nil {
		t.Fatal("benchmark overwrote previous evidence")
	}
	after, _ := os.ReadFile(out)
	if !bytes.Equal(raw, after) {
		t.Fatal("previous benchmark output was changed")
	}
	rejected := filepath.Join(dir, "invalid.json")
	if err := BenchmarkCompute(context.Background(), f.manifest, dir, 0, rejected); err == nil {
		t.Fatal("accepted zero samples")
	}
	if _, err := os.Stat(rejected); !os.IsNotExist(err) {
		t.Fatal("invalid sample request created a misleading report")
	}
}
