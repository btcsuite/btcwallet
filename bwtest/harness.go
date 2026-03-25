package bwtest

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime/debug"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
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

	// logDir is the per-run root log directory.
	logDir string

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

	// cleaned indicates the subtest cleanup has already run.
	cleaned bool
}

// SetupHarness creates a new HarnessTest.
func SetupHarness(t *testing.T, chainBackendType, dbType string) *HarnessTest {
	t.Helper()

	logDir := createTestLogDir(t, chainBackendType, dbType)

	// 1. Start Miner (always btcd).
	minerLogDir := createOrEnsureLogSubDir(t, logDir, "miner")
	miner := newMiner(t, minerLogDir)
	miner.SetUp()
	require.NoError(t, waitForTCPListener(miner.P2PAddress(),
		defaultTestTimeout), "miner p2p listener not ready")

	// 2. Start Chain Backend.
	backendLogDir := ""

	// Neutrino runs in-process and has no separate daemon log directory. The
	// external daemon backends (btcd/bitcoind) each get a dedicated backend log
	// sub-directory.
	if chainBackendType != backendNeutrino {
		backendLogDir = createOrEnsureLogSubDir(t, logDir, "chain-backend")
	}

	backend := NewBackend(t, chainBackendType, backendLogDir)
	require.NoError(t, backend.ConnectMiner(miner.P2PAddress()))
	require.NoError(t, backend.Start(), "failed to start chain backend")

	ht := &HarnessTest{
		T:       t,
		logDir:  logDir,
		miner:   miner,
		Backend: backend,
		dbType:  dbType,
	}

	// Ensure the harness is cleaned up when the test finishes.
	t.Cleanup(ht.Stop)

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
		logDir:  h.logDir,
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

	walletLogCleanup := setUpWalletLogging(
		t, filepath.Join(st.logDir, walletLogFileName(t)),
	)
	st.Cleanup(walletLogCleanup)

	st.setUpChainClient()
	st.setUpWalletDB()

	st.Cleanup(func() {
		// If a test fails, we still try to stop wallets to avoid leaking
		// goroutines into the next test, but we skip assertions.
		if st.Failed() {
			err := st.stopActiveWallets(context.Background())
			if err != nil {
				st.Logf("failed to stop wallets during failed-test cleanup: %v",
					err)
			}

			return
		}

		if st.cleaned {
			return
		}

		err := st.stopActiveWallets(context.Background())
		require.NoError(st, err, "failed to stop wallets")

		mempool, err := st.getRawMempool()
		require.NoError(st, err, "failed to query miner mempool")
		require.Empty(st, mempool, "mempool not cleaned")

		st.cleaned = true
		h.cleaned = true
	})

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

	// Flatten logs into the per-run log dir.
	h.finalizeLogs()
}

// stopActiveWallets stops all wallets registered with the harness.
//
// This is used as part of the per-subtest cleanup to avoid leaking background
// goroutines into the next test.
func (h *HarnessTest) stopActiveWallets(ctx context.Context) error {
	h.Helper()

	for _, w := range h.ActiveWallets() {
		if w == nil {
			// Keep cleanup robust against partially initialized test state. A
			// caller could register a wallet reference and fail before the
			// assignment completes.
			continue
		}

		// The modern Wallet controller's Stop method is idempotent.
		//
		// NOTE: We intentionally don't call the deprecated WaitForShutdown/
		// ShuttingDown methods here, as modern wallets might not have the
		// legacy fields initialized.
		err := w.Stop(ctx)
		if err != nil {
			return fmt.Errorf("stop wallet: %w", err)
		}
	}

	return nil
}

// setUpChainClient creates and starts a chain client for the active harness
// backend.
func (h *HarnessTest) setUpChainClient() {
	h.Helper()

	chainClient, cleanup, err := h.Backend.NewChainClient(h.Context())
	require.NoError(h, err, "unable to create chain client")

	h.Cleanup(cleanup)
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
