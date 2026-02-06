package bwtest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb" // Register bdb walletdb driver.
	"github.com/lightninglabs/neutrino"
)

const neutrinoDBTimeout = 5 * time.Second

// NeutrinoBackend is a ChainBackend that uses an in-process neutrino chain
// service connected to the shared miner.
type NeutrinoBackend struct {
	minerAddr string
}

// NewNeutrinoBackend creates a new NeutrinoBackend.
//
// Neutrino is an in-process backend and does not write process logs into the
// passed logDir.
func NewNeutrinoBackend(t *testing.T, _ string) *NeutrinoBackend {
	t.Helper()

	return &NeutrinoBackend{}
}

// Name returns the identifier of the backend.
func (n *NeutrinoBackend) Name() string {
	return backendNeutrino
}

// Start is a no-op for neutrino.
func (n *NeutrinoBackend) Start() error {
	return nil
}

// Stop is a no-op for neutrino.
func (n *NeutrinoBackend) Stop() error {
	return nil
}

// ConnectMiner records the miner address for later use.
func (n *NeutrinoBackend) ConnectMiner(minerAddr string) error {
	n.minerAddr = minerAddr
	return nil
}

// NewChainClient creates a new neutrino-backed chain.Interface connected to
// the shared miner.
func (n *NeutrinoBackend) NewChainClient(ctx context.Context) (chain.Interface,
	func(), error) {

	if n.minerAddr == "" {
		return nil, nil, fmt.Errorf("neutrino: %w", errMissingMinerAddr)
	}

	dataDir, err := os.MkdirTemp("", "btcwallet-neutrino-")
	if err != nil {
		return nil, nil, fmt.Errorf("create neutrino temp dir: %w", err)
	}

	spvdb, err := walletdb.Create(
		"bdb", filepath.Join(dataDir, "neutrino.db"), true,
		neutrinoDBTimeout, false,
	)
	if err != nil {
		_ = os.RemoveAll(dataDir)
		return nil, nil, fmt.Errorf("create neutrino db: %w", err)
	}

	chainService, err := neutrino.NewChainService(neutrino.Config{
		DataDir:      dataDir,
		Database:     spvdb,
		ChainParams:  *harnessNetParams,
		ConnectPeers: []string{n.minerAddr},
	})
	if err != nil {
		_ = spvdb.Close()
		_ = os.RemoveAll(dataDir)

		return nil, nil, fmt.Errorf("create neutrino chain service: %w", err)
	}

	client := chain.NewNeutrinoClient(harnessNetParams, chainService)

	err = client.Start(ctx)
	if err != nil {
		_ = spvdb.Close()
		_ = os.RemoveAll(dataDir)

		return nil, nil, fmt.Errorf("start neutrino client: %w", err)
	}

	cleanup := func() {
		client.Stop()
		client.WaitForShutdown()

		_ = spvdb.Close()
		_ = os.RemoveAll(dataDir)
	}

	return client, cleanup, nil
}

// LogDir returns an empty string because neutrino has no backend daemon.
func (n *NeutrinoBackend) LogDir() string {
	// Neutrino runs in-process, so there is no backend daemon log directory.
	return ""
}

var _ ChainBackend = (*NeutrinoBackend)(nil)
