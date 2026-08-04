package bwtest

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

const (
	// sqliteHeaderLen is the length of SQLite's fixed file header string.
	sqliteHeaderLen = 16

	// sqliteHeaderMagic is the header string every SQLite database starts
	// with.
	sqliteHeaderMagic = "SQLite format 3\x00"

	// bboltMagicOffset is the offset of bbolt's magic within the first page
	// header, bboltMagicLen is its width, and bboltMagic is the value
	// stored there.
	bboltMagicOffset = 16
	bboltMagicLen    = 4
	bboltMagic       = 0xED0CDAED

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

	// WalletDBPath is the wallet database path created for the current
	// subtest.
	WalletDBPath string

	// dbType is the configured wallet database backend.
	dbType string

	// managers holds the wallet managers created for this subtest. They are
	// closed after every registered wallet has stopped.
	managers []*wallet.Manager

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
			err := st.teardownWallets(context.Background())
			if err != nil {
				st.Logf("failed to stop wallets during failed-test cleanup: %v",
					err)
			}

			return
		}

		if st.cleaned {
			return
		}

		err := st.teardownWallets(context.Background())
		require.NoError(st, err, "failed to stop wallets")

		mempool, err := st.getRawMempool()
		require.NoError(st, err, "failed to query miner mempool")
		require.Empty(st, mempool, "mempool not cleaned")

		st.cleaned = true
		h.cleaned = true
	})

	return st
}

// NewWalletManager builds a Manager for the backend the harness was started
// with and registers it for teardown.
//
// The Manager is registered before any wallet is created, so a failed Create
// still releases the database it opened. Cleanup stops every wallet first and
// then closes every Manager.
func (h *HarnessTest) NewWalletManager() *wallet.Manager {
	h.Helper()

	// Switch explicitly: mapping every unknown -db value onto kvdb would let
	// `db=postgres` pass while exercising kvdb, and the PostgreSQL Manager is
	// not part of this milestone.
	var backend wallet.DBBackend

	switch h.dbType {
	case dbNameKvdb:
		//nolint:staticcheck // This case intentionally exercises legacy kvdb.
		backend = wallet.DBBackendKVDB

	case dbNameSQLite:
		backend = wallet.DBBackendSQLite

	default:
		h.Fatalf("unsupported -db value %q: the wallet Manager serves "+
			"kvdb and sqlite", h.dbType)
	}

	manager, err := wallet.NewManager(h.Context(), wallet.ManagerConfig{
		Backend:     backend,
		DataSource:  h.WalletDBPath,
		ChainParams: h.NetParams(),
	})
	require.NoError(h, err, "failed to create wallet manager")

	h.managers = append(h.managers, manager)

	// Verify the Manager opened the backend requested by the -db flag without
	// adding a production accessor solely for the test.
	h.Cleanup(h.assertBackendArtifact)

	return manager
}

// teardownWallets stops registered wallets and then closes their Managers.
func (h *HarnessTest) teardownWallets(ctx context.Context) error {
	err := h.stopActiveWallets(ctx)

	for _, manager := range h.managers {
		err = errors.Join(err, manager.Close())
	}

	h.managers = nil

	return err
}

// assertBackendArtifact verifies the Manager created the requested database.
func (h *HarnessTest) assertBackendArtifact() {
	h.Helper()

	err := validateBackendArtifact(h.dbType, h.WalletDBPath)
	require.NoError(h, err)
}

// validateBackendArtifact verifies that a database file has the requested
// backend's header.
func validateBackendArtifact(dbType, dbPath string) error {
	switch dbType {
	case dbNameKvdb, dbNameSQLite:

	default:
		return fmt.Errorf("%w: %s", ErrUnknownDBBackend, dbType)
	}

	// The path is created and owned by the test harness.
	f, err := os.Open(dbPath) //nolint:gosec
	if err != nil {
		return fmt.Errorf("open wallet database artifact: %w", err)
	}

	defer func() { _ = f.Close() }()

	// Read enough for both signatures: SQLite's header string, and bbolt's
	// magic at offset 16 of the first page.
	header := make([]byte, bboltMagicOffset+bboltMagicLen)

	_, err = io.ReadFull(f, header)
	if err != nil {
		return fmt.Errorf("read wallet database header: %w", err)
	}

	sqlite := string(header[:sqliteHeaderLen]) == sqliteHeaderMagic
	bbolt := binary.LittleEndian.Uint32(
		header[bboltMagicOffset:bboltMagicOffset+bboltMagicLen],
	) == bboltMagic

	var detected string
	switch {
	case sqlite:
		detected = dbNameSQLite

	case bbolt:
		detected = dbNameKvdb

	default:
		return fmt.Errorf("unrecognized wallet database artifact: %s",
			dbPath)
	}

	if detected != dbType {
		return fmt.Errorf("db=%s requested but %s is a %s database",
			dbType, dbPath, detected)
	}

	return nil
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

	var stopErr error

	for i, w := range h.ActiveWallets() {
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
			stopErr = errors.Join(stopErr, fmt.Errorf(
				"stop wallet %d: %w", i, err,
			))
		}
	}

	return stopErr
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

// setUpWalletDB prepares a wallet database path for the configured test
// backend.
func (h *HarnessTest) setUpWalletDB() {
	h.Helper()

	dbDir := h.TempDir()
	h.WalletDBPath = filepath.Join(dbDir, wallet.WalletDBName)
}
