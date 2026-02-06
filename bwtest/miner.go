package bwtest

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/stretchr/testify/require"
)

const (
	// minerSetupOutputs is the number of outputs to generate during miner
	// setup.
	minerSetupOutputs = 50

	// minMatureBlocks is the minimum number of blocks to mine to ensure
	// coinbase maturity.
	minMatureBlocks = 100

	// retryMultiplier is the multiplier for connection retries to make tests
	// more robust.
	retryMultiplier = 2

	// minerWindowMultiplier is the multiplier for the miner confirmation
	// window to ensure we mine enough blocks for activation.
	minerWindowMultiplier = 2
)

var (
	// harnessNetParams is the network parameters used for the harness.
	harnessNetParams = &chaincfg.RegressionNetParams
)

// minerHarness is a wrapper around rpctest.Harness that provides a mining node
// for integration tests.
type minerHarness struct {
	*testing.T

	*rpctest.Harness

	// logPath is the directory path of the miner's logs.
	logPath string
}

// newMiner creates a new minerHarness instance.
func newMiner(t *testing.T, logDir string) *minerHarness {
	t.Helper()

	btcdBinary, err := GetBtcdBinary()
	require.NoError(t, err, "unable to find btcd binary")

	err = ensureLogDir(logDir)
	require.NoError(t, err, "unable to create miner log dir")

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

	// We use an empty handlers struct as we don't need to handle notifications
	// directly in the miner wrapper for now.
	handlers := &rpcclient.NotificationHandlers{}

	harness, err := rpctest.New(harnessNetParams, handlers, args, btcdBinary)
	require.NoError(t, err, "unable to create rpctest harness")

	m := &minerHarness{
		T:       t,
		Harness: harness,
		logPath: logDir,
	}

	return m
}

// SetUp starts the miner node and generates initial blocks to activate SegWit.
func (m *minerHarness) SetUp() {
	m.Helper()

	// Increase connection retries to make tests more robust.
	m.MaxConnRetries = rpctest.DefaultMaxConnectionRetries * retryMultiplier
	m.ConnectionRetryTimeout = rpctest.DefaultConnectionRetryTimeout *
		retryMultiplier

	require.NoError(
		m, m.Harness.SetUp(true, minerSetupOutputs),
		"unable to setup miner",
	)

	// Mine enough blocks to activate SegWit.
	// MinerConfirmationWindow is usually 144 for mainnet, but likely smaller
	// for regtest. For rpctest, standard is often to mine ~200 blocks
	// total to ensure maturity and activation. Assuming harness params are
	// standard regtest.
	numBlocks := max(
		harnessNetParams.MinerConfirmationWindow*minerWindowMultiplier,
		minMatureBlocks,
	)

	_, err := m.Client.Generate(numBlocks)
	require.NoError(m, err, "unable to generate initial blocks")
}

// SetUpNoChain starts the miner node without generating a test chain.
//
// This is intended for scenarios where the miner will sync to an existing
// chain (for example, when spawning a temporary miner for reorg tests).
func (m *minerHarness) SetUpNoChain() {
	m.Helper()

	// Increase connection retries to make tests more robust.
	m.MaxConnRetries = rpctest.DefaultMaxConnectionRetries * retryMultiplier
	m.ConnectionRetryTimeout = rpctest.DefaultConnectionRetryTimeout *
		retryMultiplier

	// SetUp(true, 0) starts the node, sets up the in-memory wallet, and
	// registers notifications, but does not mine any blocks.
	require.NoError(
		m, m.Harness.SetUp(true, 0),
		"unable to setup miner",
	)
}

// Stop shuts down the miner.
func (m *minerHarness) Stop() {
	require.NoError(m, m.TearDown(), "tear down miner failed")
}
