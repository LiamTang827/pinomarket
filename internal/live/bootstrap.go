package live

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/LiamTang827/pinomarket/internal/consensus"
	"github.com/LiamTang827/pinomarket/threshold"
)

type InitOptions struct {
	Nodes, Threshold, QueueCapacity, ServiceCapacity, BasePort, APIPort int
	WindowBlocks                                                        int64
	BlockInterval                                                       time.Duration
	Ordering                                                            string
}

func InitNetwork(dir string, o InitOptions) (Manifest, error) {
	if o.Ordering != "" && o.Ordering != OrderingIdentity {
		return Manifest{}, errors.New("unsupported within-round ordering policy")
	}
	if o.Nodes < 4 || o.Nodes > 10 || o.APIPort < 1024 || o.APIPort+o.Nodes > 65535 {
		return Manifest{}, errors.New("invalid local network size/ports")
	}
	entries, err := os.ReadDir(dir)
	if err == nil && len(entries) > 0 {
		return Manifest{}, errors.New("network directory already contains files")
	}
	if err != nil && !os.IsNotExist(err) {
		return Manifest{}, err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return Manifest{}, err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return Manifest{}, err
	}
	nonce := make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		return Manifest{}, err
	}
	session := "pinocchio-" + hex.EncodeToString(nonce)
	infos, err := consensus.InitWithOptions(filepath.Join(dir, "consensus"), consensus.Options{Validators: o.Nodes, ChainID: session, BasePort: o.BasePort, BlockInterval: o.BlockInterval})
	if err != nil {
		return Manifest{}, err
	}
	// Actual per-party DKG algebra; initialization relays ceremony messages locally.
	// This provisioning utility is not a deployed authenticated DKG network.
	public, shares, err := threshold.RunLocalDKG(1, o.Nodes, o.Threshold)
	if err != nil {
		return Manifest{}, err
	}
	f := (o.Nodes - 1) / 3
	m := Manifest{Version: Domain, Session: session, Policy: Policy{Nodes: o.Nodes, Faults: f, Quorum: o.Nodes - f, Threshold: o.Threshold, QueueCapacity: o.QueueCapacity, ServiceCapacity: o.ServiceCapacity, WindowBlocks: o.WindowBlocks, Ordering: o.Ordering}, Users: map[string][]byte{}, Crypto: public}
	private := make([]ed25519.PrivateKey, o.Nodes)
	for i, info := range infos {
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return Manifest{}, e
		}
		private[i] = key
		m.Peers = append(m.Peers, Peer{ID: fmt.Sprintf("node-%d", i+1), Index: i, API: fmt.Sprintf("http://127.0.0.1:%d", o.APIPort+i), RPC: info.RPCAddress, Key: pub, ValidatorKey: info.ValidatorPublicKey})
	}
	for _, owner := range []string{"alice", "bob", "carol", "seller"} {
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return Manifest{}, e
		}
		m.Users[owner] = pub
		if e = AtomicJSON(filepath.Join(dir, "wallets", owner+".json"), []byte(key)); e != nil {
			return Manifest{}, e
		}
	}
	m.Context = m.ContextID()
	if err = m.Validate(); err != nil {
		return Manifest{}, err
	}
	if err = AtomicJSON(filepath.Join(dir, "manifest.json"), m); err != nil {
		return Manifest{}, err
	}
	for i, info := range infos {
		cfg := NodeConfig{Manifest: m, Index: i, CometDir: info.Dir, Private: private[i], Share: shares[i]}
		if err = AtomicJSON(filepath.Join(dir, fmt.Sprintf("node%d.json", i)), cfg); err != nil {
			return Manifest{}, err
		}
	}
	return m, nil
}
func ReadJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
func LoadManifest(dir string) (Manifest, error) {
	var m Manifest
	if err := ReadJSON(filepath.Join(dir, "manifest.json"), &m); err != nil {
		return m, err
	}
	return m, m.Validate()
}
