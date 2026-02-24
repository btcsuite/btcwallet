package wallet

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	errDBMock         = errors.New("db error")
	errMock           = errors.New("mock error")
	errChainMock      = errors.New("chain error")
	errPutMock        = errors.New("put error")
	errLockMock       = errors.New("lock fail")
	errDBFail         = errors.New("db fail")
	errDeriveFail     = errors.New("derive fail")
	errLoadStateFail  = errors.New("load state fail")
	errRollbackFail   = errors.New("rollback fail")
	errFetchFail      = errors.New("fetch fail")
	errCFilterFail    = errors.New("cfilter fail")
	errActiveMgrsFail = errors.New("active managers fail")

	errSetFail   = errors.New("set fail")
	errOther     = errors.New("other error")
	errBroadcast = errors.New("broadcast fail")
	errScan      = errors.New("scan fail")
	errBlocks    = errors.New("blocks fail")
	errDBInsert  = errors.New("db insert fail")
	errBestBlock = errors.New("best block fail")
	errAddr      = errors.New("addr fail")
	errInsert    = errors.New("insert fail")
	errManager   = errors.New("manager fail")
	errUtxo      = errors.New("utxo fail")
	errGetBlocks = errors.New("get blocks fail")
	errBlockHash = errors.New("block hash fail")
	errSetSync   = errors.New("set sync fail")
	errRemote    = errors.New("remote fail")
	errNotify    = errors.New("notify fail")
	errHashes    = errors.New("hashes fail")
	errHeaders   = errors.New("headers fail")
	errHeader    = errors.New("header fail")
)

var (
	// chainParams are the chain parameters used throughout the wallet
	// tests.
	chainParams = chaincfg.RegressionNetParams
)

// setupTestDB creates a temporary database for testing.
func setupTestDB(t *testing.T) (walletdb.DB, func()) {
	t.Helper()

	f, err := os.CreateTemp(t.TempDir(), "wallet-test-*.db")
	require.NoError(t, err)

	dbPath := f.Name()
	require.NoError(t, f.Close())
	require.NoError(t, os.Remove(dbPath))

	db, err := walletdb.Create("bdb", dbPath, true, time.Second*10, false)
	require.NoError(t, err)

	cleanup := func() {
		_ = db.Close()
		_ = os.Remove(dbPath)
	}

	// Create buckets.
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		_, err := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if err != nil {
			return err
		}

		_, err = tx.CreateTopLevelBucket(wtxmgrNamespaceKey)

		return err
	})
	require.NoError(t, err)

	return db, cleanup
}

// mockWalletDeps holds the mocked dependencies for the Wallet.
type mockWalletDeps struct {
	addrStore      *mockAddrStore
	store          *mockStore
	txStore        *mockTxStore
	syncer         *mockChainSyncer
	chain          *mockChain
	addr           *mockManagedAddress
	accountManager *mockAccountStore
	pubKeyAddr     *mockManagedPubKeyAddr
	taprootAddr    *mockManagedTaprootScriptAddress
}

// createTestWalletWithMocks creates a Wallet instance with mocked
// dependencies. It returns the wallet and the struct holding the mocks for
// assertion.
func createTestWalletWithMocks(t *testing.T) (*Wallet, *mockWalletDeps) {
	t.Helper()

	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)

	mockAddrStore := &mockAddrStore{}
	mockStore := &mockStore{}
	mockTxStore := &mockTxStore{}
	mockSyncer := &mockChainSyncer{}
	mockChain := &mockChain{}
	mockAddr := &mockManagedAddress{}
	mockAccountManager := &mockAccountStore{}
	mockPubKeyAddr := &mockManagedPubKeyAddr{}
	mockTaprootAddr := &mockManagedTaprootScriptAddress{}

	ctx, cancel := context.WithCancel(t.Context())

	w := &Wallet{
		addrStore:   mockAddrStore,
		store:       mockStore,
		txStore:     mockTxStore,
		sync:        mockSyncer,
		state:       newWalletState(mockSyncer),
		lifetimeCtx: ctx,
		cancel:      cancel,
		requestChan: make(chan any, 1),
		lockTimer:   time.NewTimer(time.Hour),
		birthdayBlock: waddrmgr.BlockStamp{
			Height: 100,
		},
		cfg: Config{
			DB:          db,
			Chain:       mockChain,
			ChainParams: &chainParams,
		},
	}

	// Stop the timer immediately to avoid leaks.
	w.lockTimer.Stop()

	deps := &mockWalletDeps{
		addrStore:      mockAddrStore,
		store:          mockStore,
		txStore:        mockTxStore,
		syncer:         mockSyncer,
		chain:          mockChain,
		addr:           mockAddr,
		accountManager: mockAccountManager,
		pubKeyAddr:     mockPubKeyAddr,
		taprootAddr:    mockTaprootAddr,
	}

	t.Cleanup(func() {
		mockAddrStore.AssertExpectations(t)
		mockStore.AssertExpectations(t)
		mockTxStore.AssertExpectations(t)
		mockSyncer.AssertExpectations(t)
		mockChain.AssertExpectations(t)
		mockAddr.AssertExpectations(t)
		mockAccountManager.AssertExpectations(t)
		mockPubKeyAddr.AssertExpectations(t)
		mockTaprootAddr.AssertExpectations(t)
	})

	return w, deps
}

// createStartedWalletWithMocks creates a fully started and unlocked Wallet
// instance with mocked dependencies.
func createStartedWalletWithMocks(t *testing.T) (*Wallet, *mockWalletDeps) {
	t.Helper()

	w, deps := createTestWalletWithMocks(t)

	// Mock the birthday block to be present.
	deps.addrStore.On("BirthdayBlock", mock.Anything).
		Return(waddrmgr.BlockStamp{}, true, nil).
		Once()

	// Allow SyncedTo to be called any number of times (background sync).
	deps.addrStore.On("SyncedTo").
		Return(waddrmgr.BlockStamp{Height: 1}).
		Maybe()

	// Mock account loading.
	deps.addrStore.On("ActiveScopedKeyManagers").
		Return([]waddrmgr.AccountStore{deps.accountManager}).
		Once()

	deps.accountManager.On("LastAccount", mock.Anything).
		Return(uint32(0), nil).
		Once()

	deps.accountManager.On("AccountProperties", mock.Anything, uint32(0)).
		Return(&waddrmgr.AccountProperties{
			AccountNumber: 0,
			AccountName:   "default",
		}, nil).
		Once()

	// Mock expired lock deletion.
	deps.txStore.On("DeleteExpiredLockedOutputs", mock.Anything).
		Return(nil).
		Once()

	// Mock the syncer run.
	deps.syncer.On("run", mock.Anything).Return(nil).Once()

	// Start the wallet.
	require.NoError(t, w.Start(t.Context()))

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(
			context.Background(), 5*time.Second,
		)
		defer cancel()

		require.NoError(t, w.Stop(ctx))
	})

	return w, deps
}

// createUnlockedWalletWithMocks creates a fully started and unlocked Wallet
// instance with mocked dependencies.
func createUnlockedWalletWithMocks(t *testing.T) (*Wallet, *mockWalletDeps) {
	t.Helper()

	w, deps := createStartedWalletWithMocks(t)

	// Transition to Unlocked.
	w.state.toUnlocked()

	return w, deps
}

func init() {
	// Use fast scrypt options for tests to avoid CPU exhaustion and
	// timeouts, especially when running with -race.
	waddrmgr.DefaultScryptOptions = waddrmgr.FastScryptOptions
}
