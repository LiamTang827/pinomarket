package consensus

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	"github.com/cometbft/cometbft/types"
)

func TestInitFiveIndependentValidators(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "network")
	infos, err := Init(dir, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 5 {
		t.Fatalf("got %d nodes", len(infos))
	}
	keys := map[string]bool{}
	var firstGenesis []byte
	for _, info := range infos {
		config, err := LoadConfig(info.Dir)
		if err != nil {
			t.Fatal(err)
		}
		genesis, err := os.ReadFile(config.GenesisFile())
		if err != nil {
			t.Fatal(err)
		}
		if firstGenesis == nil {
			firstGenesis = genesis
		} else if !bytes.Equal(firstGenesis, genesis) {
			t.Fatal("nodes have different genesis files")
		}
		doc, err := types.GenesisDocFromJSON(genesis)
		if err != nil {
			t.Fatal(err)
		}
		if len(doc.Validators) != 5 {
			t.Fatalf("got %d genesis validators", len(doc.Validators))
		}
		for _, v := range doc.Validators {
			if v.Power != 1 {
				t.Fatalf("unequal voting power: %d", v.Power)
			}
		}
		pv := privval.LoadFilePV(config.PrivValidatorKeyFile(), config.PrivValidatorStateFile())
		pubkey, err := pv.GetPubKey()
		if err != nil {
			t.Fatal(err)
		}
		if keys[pubkey.Address().String()] {
			t.Fatal("validator signing key reused")
		}
		keys[pubkey.Address().String()] = true
		if !bytes.Equal(info.ValidatorPublicKey, pubkey.Bytes()) {
			t.Fatal("incorrect manifest public key")
		}
		nodeKey, err := p2p.LoadNodeKey(config.NodeKeyFile())
		if err != nil {
			t.Fatal(err)
		}
		if string(nodeKey.ID()) != info.NodeID {
			t.Fatal("incorrect persistent P2P identity")
		}
		if peers := strings.Split(config.P2P.PersistentPeers, ","); len(peers) != 4 {
			t.Fatalf("got %d peers", len(peers))
		}
		if config.DBDir() == dir || !strings.HasPrefix(config.DBDir(), info.Dir+string(os.PathSeparator)) {
			t.Fatal("node database is not isolated")
		}
		if _, err := os.Stat(config.PrivValidatorStateFile()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Init(dir, 5); err == nil {
		t.Fatal("reinitialization should preserve signing keys by refusing overwrite")
	}
}
