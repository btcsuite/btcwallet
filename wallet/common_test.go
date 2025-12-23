package wallet

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/stretchr/testify/require"
)

var (
	errDBMock = errors.New("db error")
	errMock   = errors.New("mock error")
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
	addrStore *mockAddrStore
	txStore   *mockTxStore
	syncer    *mockChainSyncer
	chain     *mockChain
}

// createTestWalletWithMocks creates a Wallet instance with mocked
// dependencies. It returns the wallet and the struct holding the mocks for
// assertion.
func createTestWalletWithMocks(t *testing.T) (*Wallet, *mockWalletDeps) {
	t.Helper()

	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)

	mockAddrStore := &mockAddrStore{}
	mockTxStore := &mockTxStore{}
	mockSyncer := &mockChainSyncer{}
	mockChain := &mockChain{}

	w := &Wallet{
		addrStore: mockAddrStore,
		txStore:   mockTxStore,
		sync:      mockSyncer,
		state:     newWalletState(mockSyncer),
		cfg: Config{
			DB:          db,
			Chain:       mockChain,
			ChainParams: &chaincfg.MainNetParams,
		},
	}

	deps := &mockWalletDeps{
		addrStore: mockAddrStore,
		txStore:   mockTxStore,
		syncer:    mockSyncer,
		chain:     mockChain,
	}

	t.Cleanup(func() {
		mockAddrStore.AssertExpectations(t)
		mockTxStore.AssertExpectations(t)
		mockSyncer.AssertExpectations(t)
		mockChain.AssertExpectations(t)
	})

	return w, deps
}
