package consensus

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
	cfg "github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/node"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/privval"
	"github.com/cometbft/cometbft/proxy"
	"github.com/cometbft/cometbft/types"
	"github.com/spf13/viper"
)

// NodeInfo contains only public connection and identity information.
type NodeInfo struct {
	Index              int    `json:"index"`
	ID                 string `json:"id"`
	NodeDir            string `json:"node_dir"`
	ValidatorPublicKey []byte `json:"validator_public_key"`
	Dir                string `json:"dir"`
	NodeID             string `json:"node_id"`
	ValidatorAddress   string `json:"validator_address"`
	RPCAddress         string `json:"rpc_address"`
	P2PAddress         string `json:"p2p_address"`
}

// Options describes a local validator network. Each node receives its own
// private validator key, anti-double-sign state, P2P identity, WAL and database.
type Options struct {
	Validators    int
	ChainID       string
	BasePort      int
	BlockInterval time.Duration
}

// Init creates a local network at node0, node1, ...; five equal-power validators
// require four precommits (>2/3), and continue with one unavailable validator.
// It refuses a nonempty directory to avoid accidentally replacing signing keys.
func Init(rootDir string, validators int) ([]NodeInfo, error) {
	return InitWithOptions(rootDir, Options{Validators: validators})
}

func InitWithOptions(rootDir string, options Options) ([]NodeInfo, error) {
	if options.Validators < 1 || options.Validators > 100 {
		return nil, errors.New("validators must be between 1 and 100")
	}
	if options.BasePort == 0 {
		options.BasePort = 26656
	}
	if options.BasePort < 1024 || options.BasePort+(options.Validators-1)*10+1 > 65535 {
		return nil, errors.New("invalid local port range")
	}
	if options.BlockInterval == 0 {
		options.BlockInterval = 500 * time.Millisecond
	}
	if options.BlockInterval < 0 {
		return nil, errors.New("block interval must be positive")
	}
	if options.ChainID == "" {
		var nonce [6]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		options.ChainID = "pinocchio-" + hex.EncodeToString(nonce[:])
	}
	if len(options.ChainID) > types.MaxChainIDLen {
		return nil, errors.New("chain ID is too long")
	}
	rootDir, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(rootDir)
	if err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("network directory is not empty: %s", rootDir)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(rootDir, 0700); err != nil {
		return nil, err
	}

	infos := make([]NodeInfo, options.Validators)
	configs := make([]*cfg.Config, options.Validators)
	validators := make([]types.GenesisValidator, options.Validators)
	for i := range infos {
		dir := filepath.Join(rootDir, fmt.Sprintf("node%d", i))
		for _, subdir := range []string{"config", "data"} {
			if err := os.MkdirAll(filepath.Join(dir, subdir), 0700); err != nil {
				return nil, err
			}
		}
		config := cfg.DefaultConfig().SetRoot(dir)
		config.Moniker = fmt.Sprintf("pinocchio-validator-%d", i)
		config.LogLevel = "error"
		config.ProxyApp = "pinocchio-local"
		config.P2P.ListenAddress = fmt.Sprintf("tcp://127.0.0.1:%d", options.BasePort+i*10)
		config.P2P.ExternalAddress = fmt.Sprintf("127.0.0.1:%d", options.BasePort+i*10)
		config.RPC.ListenAddress = fmt.Sprintf("tcp://127.0.0.1:%d", options.BasePort+i*10+1)
		config.RPC.TimeoutBroadcastTxCommit = 20 * time.Second
		config.P2P.AddrBookStrict = false
		config.P2P.AllowDuplicateIP = true
		config.P2P.PexReactor = false
		config.P2P.MaxNumInboundPeers = options.Validators + 2
		config.P2P.MaxNumOutboundPeers = options.Validators + 2
		config.Consensus.TimeoutPropose = time.Second
		config.Consensus.TimeoutPrevote = 500 * time.Millisecond
		config.Consensus.TimeoutPrecommit = 500 * time.Millisecond
		config.Consensus.TimeoutCommit = options.BlockInterval
		config.Consensus.CreateEmptyBlocks = true
		config.TxIndex.Indexer = "kv"
		config.Instrumentation.Prometheus = false
		if err := config.ValidateBasic(); err != nil {
			return nil, err
		}
		pv := privval.GenFilePV(config.PrivValidatorKeyFile(), config.PrivValidatorStateFile())
		pv.Save()
		pubkey, err := pv.GetPubKey()
		if err != nil {
			return nil, err
		}
		nodeKey, err := p2p.LoadOrGenNodeKey(config.NodeKeyFile())
		if err != nil {
			return nil, err
		}
		infos[i] = NodeInfo{Index: i, ID: string(nodeKey.ID()), NodeDir: dir, ValidatorPublicKey: append([]byte(nil), pubkey.Bytes()...), Dir: dir, NodeID: string(nodeKey.ID()), ValidatorAddress: pubkey.Address().String(), RPCAddress: fmt.Sprintf("http://127.0.0.1:%d", options.BasePort+i*10+1), P2PAddress: config.P2P.ExternalAddress}
		configs[i] = config
		validators[i] = types.GenesisValidator{Address: pubkey.Address(), PubKey: pubkey, Power: 1, Name: config.Moniker}
	}
	genesis := &types.GenesisDoc{GenesisTime: time.Now().UTC(), ChainID: options.ChainID, InitialHeight: 1, ConsensusParams: types.DefaultConsensusParams(), Validators: validators}
	// Vote extensions are not used; ordinary signed precommits establish finality.
	genesis.ConsensusParams.ABCI.VoteExtensionsEnableHeight = 0
	if err := genesis.ValidateAndComplete(); err != nil {
		return nil, err
	}
	for i, config := range configs {
		peers := make([]string, 0, len(infos)-1)
		for j, info := range infos {
			if i != j {
				peers = append(peers, info.NodeID+"@"+info.P2PAddress)
			}
		}
		config.P2P.PersistentPeers = strings.Join(peers, ",")
		cfg.WriteConfigFile(filepath.Join(infos[i].Dir, "config", "config.toml"), config)
		if err := genesis.SaveAs(config.GenesisFile()); err != nil {
			return nil, err
		}
	}
	manifest, err := json.MarshalIndent(struct {
		ChainID string     `json:"chain_id"`
		Quorum  int        `json:"quorum"`
		Nodes   []NodeInfo `json:"nodes"`
	}{options.ChainID, 2*len(infos)/3 + 1, infos}, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(rootDir, "network.json"), append(manifest, '\n'), 0600); err != nil {
		return nil, err
	}
	return infos, nil
}

// LoadConfig reads the generated CometBFT configuration from an independent
// node home directory. Callers may edit that file to tune the local network.
func LoadConfig(nodeDir string) (*cfg.Config, error) {
	abs, err := filepath.Abs(nodeDir)
	if err != nil {
		return nil, err
	}
	config := cfg.DefaultConfig()
	v := viper.New()
	v.SetConfigFile(filepath.Join(abs, "config", "config.toml"))
	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}
	if err := v.Unmarshal(config); err != nil {
		return nil, err
	}
	config.SetRoot(abs)
	if err := config.ValidateBasic(); err != nil {
		return nil, err
	}
	return config, nil
}

// StartNode starts the actual CometBFT node, using on-disk block/state databases
// and anti-double-sign files. The caller must Stop and Wait before restarting it.
func StartNode(nodeDir string, app abci.Application) (*node.Node, error) {
	config, err := LoadConfig(nodeDir)
	if err != nil {
		return nil, err
	}
	for _, required := range []string{config.GenesisFile(), config.PrivValidatorKeyFile(), config.PrivValidatorStateFile(), config.NodeKeyFile()} {
		if _, err := os.Stat(required); err != nil {
			return nil, fmt.Errorf("node is not initialized (%s): %w", required, err)
		}
	}
	nodeKey, err := p2p.LoadNodeKey(config.NodeKeyFile())
	if err != nil {
		return nil, err
	}
	logger := log.NewFilter(log.NewTMLogger(log.NewSyncWriter(os.Stderr)), log.AllowError())
	n, err := node.NewNode(config, privval.LoadFilePV(config.PrivValidatorKeyFile(), config.PrivValidatorStateFile()), nodeKey, proxy.NewLocalClientCreator(app), node.DefaultGenesisDocProviderFunc(config), cfg.DefaultDBProvider, node.DefaultMetricsProvider(config.Instrumentation), logger)
	if err != nil {
		return nil, err
	}
	if err := n.Start(); err != nil {
		return nil, err
	}
	return n, nil
}

// Start blocks until ctx is cancelled or the node stops. Use signal.NotifyContext
// with SIGINT/SIGTERM in the CLI so validator signing state closes cleanly.
func Start(ctx context.Context, nodeDir string, app abci.Application) error {
	n, err := StartNode(nodeDir, app)
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		if err := n.Stop(); err != nil {
			return err
		}
		n.Wait()
		return nil
	case <-n.Quit():
		return errors.New("consensus node stopped unexpectedly")
	}
}
