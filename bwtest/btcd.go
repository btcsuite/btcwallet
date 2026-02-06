package bwtest

import (
	"context"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/stretchr/testify/require"
)

// BtcdBackend is a ChainBackend backed by a btcd node (via rpctest).
type BtcdBackend struct {
	// harness is the underlying rpctest harness that manages the btcd process.
	harness *rpctest.Harness

	// logDir is the directory where btcd writes its logs.
	logDir string

	// minerAddr is the P2P address of the shared miner.
	minerAddr string
}

// NewBtcdBackend creates a new BtcdBackend.
func NewBtcdBackend(t *testing.T, logDir string) *BtcdBackend {
	t.Helper()

	btcdBinary, err := GetBtcdBinary()
	require.NoError(t, err, "unable to find btcd binary")

	err = ensureLogDir(logDir)
	require.NoError(t, err, "unable to create btcd backend log dir")

	// Create a separate harness for the chain backend.
	args := []string{
		"--rejectnonstd",          // Reject non-standard txs in tests.
		"--txindex",               // Required for some RPC queries.
		"--nowinservice",          // Avoid Windows service integration.
		"--nobanning",             // Avoid peer banning in local tests.
		"--debuglevel=debug",      // Provide detailed logs for debugging.
		"--logdir=" + logDir,      // Write logs into our per-run dir.
		"--trickleinterval=100ms", // Speed up inv relay in regtest.
		"--nostalldetect",         // Avoid stall detection flakiness.
	}

	handlers := &rpcclient.NotificationHandlers{}
	harness, err := rpctest.New(harnessNetParams, handlers, args, btcdBinary)
	require.NoError(t, err, "unable to create btcd backend harness")

	return &BtcdBackend{
		harness: harness,
		logDir:  logDir,
	}
}

// Name returns the identifier of the backend.
func (b *BtcdBackend) Name() string {
	return backendBtcd
}

// Start launches the backend daemon.
func (b *BtcdBackend) Start() error {
	// SetUp(false, 0) means we don't treat it as a miner and don't cache block
	// templates.
	err := b.harness.SetUp(false, 0)
	if err != nil {
		return fmt.Errorf("setup btcd harness: %w", err)
	}

	if b.minerAddr == "" {
		return fmt.Errorf("btcd: %w", errMissingMinerAddr)
	}

	// Connect the backend to the miner after the node is up.
	err = b.harness.Client.AddNode(b.minerAddr, "add")
	if err != nil {
		return fmt.Errorf("add miner node %s: %w", b.minerAddr, err)
	}

	return nil
}

// Stop shuts down the backend daemon.
func (b *BtcdBackend) Stop() error {
	err := b.harness.TearDown()
	if err != nil {
		return fmt.Errorf("teardown btcd harness: %w", err)
	}

	return nil
}

// ConnectMiner records the miner address for later use.
func (b *BtcdBackend) ConnectMiner(minerAddr string) error {
	b.minerAddr = minerAddr

	return nil
}

// NewChainClient creates a new RPC-backed chain.Interface connected to this
// backend.
func (b *BtcdBackend) NewChainClient(ctx context.Context) (chain.Interface,
	func(), error) {

	backendCfg := b.harness.RPCConfig()
	rpcCfg := backendCfg

	chainConfig := &chain.RPCClientConfig{
		Conn:              &rpcCfg,
		Chain:             harnessNetParams,
		ReconnectAttempts: defaultChainReconnectAttempts,
	}

	chainClient, err := chain.NewRPCClientWithConfig(chainConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("create chain client: %w", err)
	}

	err = chainClient.Start(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("start chain client: %w", err)
	}

	cleanup := func() {
		chainClient.Stop()
	}

	return chainClient, cleanup, nil
}

// LogDir returns the directory where btcd wrote its logs for this run.
func (b *BtcdBackend) LogDir() string {
	return b.logDir
}

var _ ChainBackend = (*BtcdBackend)(nil)
