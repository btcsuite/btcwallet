package bwtest

import (
	"runtime/debug"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/bwtest/wait"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

const (
	// defaultChainReconnectAttempts is the number of times the chain RPC client
	// will attempt to reconnect before failing.
	defaultChainReconnectAttempts = 5
)

// HarnessTest is the integration test harness.
type HarnessTest struct {
	*testing.T

	// miner is the shared mining node used to generate blocks.
	miner *minerHarness

	// Backend is the chain backend under test.
	Backend ChainBackend

	// ChainClient is an RPC chain client connected to the active chain backend.
	//
	// This client is created for each subtest harness and is intended to be
	// passed to wallets under test.
	ChainClient chain.Interface

	// WalletDB is a wallet database instance created for the current subtest.
	WalletDB walletdb.DB

	// dbType is the configured wallet database backend.
	dbType string

	// mu protects harness state that can be accessed across the main test and
	// subtests. This includes the wallet registry and idempotent shutdown.
	mu sync.Mutex

	// wallets is the set of wallets created by a test case.
	wallets []*wallet.Wallet

	// stopped prevents stopping shared infrastructure more than once.
	stopped bool
}

// SetupHarness creates a new HarnessTest.
func SetupHarness(t *testing.T, chainBackendType, dbType string) *HarnessTest {
	t.Helper()

	// 1. Start Miner (always btcd).
	miner := newMiner(t)
	miner.SetUp()

	// 2. Start Chain Backend.
	backend := NewBackend(t, chainBackendType)
	require.NoError(t, backend.Start(), "failed to start chain backend")

	ht := &HarnessTest{
		T:       t,
		miner:   miner,
		Backend: backend,
		dbType:  dbType,
	}

	// Ensure the harness is cleaned up when the test finishes.
	t.Cleanup(ht.Stop)

	// 3. Connect Backend to Miner.
	// Backend startup can take a moment, so we retry until it succeeds.
	err := wait.NoError(func() error {
		return backend.ConnectMiner(miner.P2PAddress())
	}, defaultTestTimeout)
	require.NoError(t, err, "failed to connect backend to miner")

	return ht
}

// Subtest creates a child harness that shares the miner and chain backend.
//
// The returned harness has its own wallet registry and per-test resources.
// Callers should not call Stop on the returned harness as it would stop shared
// infrastructure.
func (h *HarnessTest) Subtest(t *testing.T) *HarnessTest {
	h.Helper()

	st := &HarnessTest{
		T:       t,
		miner:   h.miner,
		Backend: h.Backend,
		dbType:  h.dbType,
	}

	// Use the subtest's testing context for miner assertions.
	//
	// The miner is shared across test cases, but we want failures to be
	// attributed to the active subtest.
	//
	// NOTE: The miner is shared across the whole suite and this assignment
	// mutates that shared state.
	//
	// This is safe because the integration test suite runs subtests serially
	// (no t.Parallel()). Do not enable parallel integration cases unless this
	// is refactored.
	st.miner.T = st.T

	st.setUpChainClient()
	st.setUpWalletDB()

	return st
}

// RegisterWallet registers a wallet with the harness.
//
// Registered wallets are automatically included in harness-level assertions,
// such as MineBlocks.
func (h *HarnessTest) RegisterWallet(w *wallet.Wallet) {
	h.Helper()

	if w == nil {
		h.Fatalf("cannot register nil wallet")
	}

	h.mu.Lock()
	h.wallets = append(h.wallets, w)
	h.mu.Unlock()
}

// ActiveWallets returns a snapshot of wallets registered with this harness.
func (h *HarnessTest) ActiveWallets() []*wallet.Wallet {
	h.Helper()

	h.mu.Lock()
	wallets := append([]*wallet.Wallet(nil), h.wallets...)
	h.mu.Unlock()

	return wallets
}

// RunTestCase executes a harness test case.
//
// Any panic from the test function is converted into a fatal test failure with
// a stack trace.
func (h *HarnessTest) RunTestCase(name string,
	testFunc func(t *HarnessTest)) {

	h.Helper()

	defer func() {
		r := recover()
		if r == nil {
			return
		}

		stack := debug.Stack()
		h.Fatalf("failed (%s): panic=%v\n%s", name, r, stack)
	}()

	if testFunc == nil {
		h.Fatalf("nil test func for %s", name)
	}

	// Execute the case.
	testFunc(h)
}

// NetParams returns the chain parameters used by the harness.
func (h *HarnessTest) NetParams() *chaincfg.Params {
	h.Helper()

	return harnessNetParams
}

// Stop shuts down all resources owned by the harness.
func (h *HarnessTest) Stop() {
	h.Helper()

	h.mu.Lock()

	if h.stopped {
		h.mu.Unlock()
		return
	}

	h.stopped = true
	h.mu.Unlock()

	// Stop the chain backend first to avoid it attempting to reconnect while
	// the miner is being torn down.
	require.NoError(h, h.Backend.Stop(), "failed to stop chain backend")

	// Finally, stop the miner.
	h.miner.Stop()
}

// setUpChainClient creates and starts an RPC chain client for the active
// harness backend.
func (h *HarnessTest) setUpChainClient() {
	h.Helper()

	backendCfg := h.Backend.RPCConfig()
	rpcCfg := backendCfg

	chainConfig := &chain.RPCClientConfig{
		Conn:              &rpcCfg,
		Chain:             harnessNetParams,
		ReconnectAttempts: defaultChainReconnectAttempts,
	}
	chainClient, err := chain.NewRPCClientWithConfig(chainConfig)
	require.NoError(h, err, "unable to create chain client")

	err = chainClient.Start(h.Context())
	require.NoError(h, err, "unable to start chain client")
	h.Cleanup(chainClient.Stop)

	h.ChainClient = chainClient
}

// setUpWalletDB opens a wallet database for the configured test backend.
func (h *HarnessTest) setUpWalletDB() {
	h.Helper()

	dbDir := h.TempDir()
	db, cleanup, err := OpenWalletDB(h.dbType, dbDir)
	require.NoError(h, err, "unable to create wallet db")

	h.Cleanup(func() {
		require.NoError(h, cleanup(), "failed to close database")
	})

	h.WalletDB = db
}
