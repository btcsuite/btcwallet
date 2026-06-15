package wallet

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	walletmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	kvdb "github.com/btcsuite/btcwallet/wallet/internal/db/kvdb"
	"github.com/stretchr/testify/require"
)

// errFakeStoreClose is a static test error for runtime store close failures.
var errFakeStoreClose = errors.New("fake runtime store close error")

// createRuntimeStoreTestWallet creates one legacy walletdb wallet and returns a
// load config for it.
func createRuntimeStoreTestWallet(t *testing.T) Config {
	t.Helper()

	cfg := Config{
		DB:             testKVDBConfig(t),
		Chain:          &bwmock.Chain{},
		ChainParams:    &chainParams,
		Name:           "test-wallet",
		PubPassphrase:  []byte("public"),
		RecoveryWindow: MinRecoveryWindow,
	}
	params := CreateWalletParams{
		Mode:              ModeGenSeed,
		PubPassphrase:     []byte("public"),
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	}

	w, err := NewManager().Create(cfg, params)
	require.NoError(t, err)
	require.NotNil(t, w)
	require.NoError(t, w.closeRuntimeStore())

	return cfg
}

// TestManagerLoadUsesRuntimeStoreFactory verifies Manager.Load wires the
// selected runtime store and wallet metadata into the constructed wallet.
//
//nolint:paralleltest // Mutates the package-level runtimeStoreFactory.
func TestManagerLoadUsesRuntimeStoreFactory(t *testing.T) {
	cfg := createRuntimeStoreTestWallet(t)
	cfg.DB = DBConfig{
		KVDB:    cfg.DB.KVDB,
		Backend: DBBackendSQLite,
		SQLite: SQLiteDBConfig{
			DBPath: "unused.sqlite",
		},
	}

	oldFactory := runtimeStoreFactory
	t.Cleanup(func() {
		runtimeStoreFactory = oldFactory
	})

	store := &walletmock.Store{}
	called := false
	runtimeStoreFactory = func(_ context.Context, gotCfg Config,
		legacyStore *kvdb.StoreHandle) (*runtimeStoreHandle, error) {

		called = true

		require.Equal(t, cfg.Name, gotCfg.Name)
		require.NotNil(t, legacyStore.TxStore)
		require.NotNil(t, legacyStore.AddrStore)

		return &runtimeStoreHandle{
			store: store,
			walletInfo: &db.WalletInfo{
				ID:          42,
				IsWatchOnly: true,
			},
		}, nil
	}

	w, err := NewManager().Load(cfg)
	require.NoError(t, err)
	require.True(t, called)
	require.Same(t, store, w.store)
	require.Equal(t, uint32(42), w.ID())
	require.True(t, w.IsWatchOnly())

	cache, ok := w.cache.(*storeRuntimeCache)
	require.True(t, ok)
	require.Same(t, store, cache.store)

	syncer, ok := w.sync.(*syncer)
	require.True(t, ok)
	require.Same(t, store, syncer.store)
	require.Equal(t, uint32(42), syncer.walletID)
}

// TestManagerLoadClosesRuntimeStoreOnMetadataError verifies that a constructed
// SQL runtime store is closed if wallet metadata parsing fails.
//
//nolint:paralleltest // Mutates the package-level runtimeStoreFactory.
func TestManagerLoadClosesRuntimeStoreOnMetadataError(t *testing.T) {
	cfg := createRuntimeStoreTestWallet(t)
	cfg.DB = DBConfig{
		KVDB:    cfg.DB.KVDB,
		Backend: DBBackendSQLite,
		SQLite: SQLiteDBConfig{
			DBPath: "unused.sqlite",
		},
	}

	oldFactory := runtimeStoreFactory
	t.Cleanup(func() {
		runtimeStoreFactory = oldFactory
	})

	closed := 0
	runtimeStoreFactory = func(context.Context, Config,
		*kvdb.StoreHandle) (*runtimeStoreHandle, error) {

		return &runtimeStoreHandle{
			store: &walletmock.Store{},
			walletInfo: &db.WalletInfo{
				ID:           42,
				MasterPubKey: []byte("not-an-xpub"),
			},
			closeFn: func() error {
				closed++
				return nil
			},
		}, nil
	}

	w, err := NewManager().Load(cfg)
	require.ErrorContains(t, err, "cache master fingerprint")
	require.Nil(t, w)
	require.Equal(t, 1, closed)
}

// TestOpenRuntimeStoreSQLiteRequiresWalletRow verifies the real SQLite factory
// fails closed instead of treating an empty SQL side database as authoritative.
func TestOpenRuntimeStoreSQLiteRequiresWalletRow(t *testing.T) {
	t.Parallel()

	cfg := createRuntimeStoreTestWallet(t)
	cfg.DB = DBConfig{
		KVDB:    cfg.DB.KVDB,
		Backend: DBBackendSQLite,
		SQLite: SQLiteDBConfig{
			DBPath: filepath.Join(t.TempDir(), "runtime.sqlite"),
		},
	}

	legacyStore, err := openLegacyStore(cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, legacyStore.Close())
	})

	handle, err := openRuntimeStore(t.Context(), cfg, legacyStore)
	require.ErrorIs(t, err, db.ErrWalletNotFound)
	require.Nil(t, handle)
}

// TestCloseRuntimeStore verifies the wallet-owned runtime store closer is
// idempotent.
func TestCloseRuntimeStore(t *testing.T) {
	t.Parallel()

	closed := 0
	w := &Wallet{
		runtimeStoreClose: func() error {
			closed++
			return nil
		},
	}

	require.NoError(t, w.closeRuntimeStore())
	require.NoError(t, w.closeRuntimeStore())
	require.Equal(t, 1, closed)
}

// TestCloseRuntimeStoreError verifies close errors are returned to callers.
func TestCloseRuntimeStoreError(t *testing.T) {
	t.Parallel()

	w := &Wallet{
		runtimeStoreClose: func() error {
			return errFakeStoreClose
		},
	}

	err := w.closeRuntimeStore()
	require.ErrorIs(t, err, errFakeStoreClose)
	require.NoError(t, w.closeRuntimeStore())
}

// sqliteCreateConfig returns a SQLite-backed create config and a spendable
// seed-import params pair sharing fresh temp paths, for tests that exercise
// the SQL create path end to end.
func sqliteCreateConfig(t *testing.T) (Config, CreateWalletParams) {
	t.Helper()

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(t, err)

	dir := t.TempDir()
	cfg := Config{
		DB: DBConfig{
			KVDB:    KVDBConfig{DBPath: filepath.Join(dir, "wallet.db")},
			Backend: DBBackendSQLite,
			SQLite: SQLiteDBConfig{
				DBPath: filepath.Join(dir, "runtime.sqlite"),
			},
		},
		Chain:          &bwmock.Chain{},
		ChainParams:    &chainParams,
		Name:           "test-wallet",
		PubPassphrase:  []byte("public"),
		RecoveryWindow: MinRecoveryWindow,
	}
	params := CreateWalletParams{
		Mode:              ModeImportSeed,
		Seed:              seed,
		PubPassphrase:     []byte("public"),
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	}

	return cfg, params
}

// TestCreateRuntimeWalletSpendableRequiresSeed verifies that a spendable SQL
// wallet create fails fast when the encrypted master HD key is missing, rather
// than committing a wallet row whose later GetEncryptedHDSeed would fail and
// break account/key derivation.
func TestCreateRuntimeWalletSpendableRequiresSeed(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	rootKey, err := hdkeychain.NewMaster(params.Seed, &chainParams)
	require.NoError(t, err)

	// Act: create the runtime row for a spendable wallet with a nil seed,
	// the state a retry-after-partial-create previously produced.
	err = createRuntimeWallet(
		context.Background(), cfg, params, rootKey, nil,
	)

	// Assert: the create is rejected before the row is written.
	require.ErrorIs(t, err, db.ErrSpendableWalletNeedsMasterPrivKey)
}

// TestCreateRecoversSeedAfterPartialCreate verifies that when a prior Create
// left the legacy wallet behind but no SQL runtime row, a retry reopens the
// legacy store, recovers its encrypted master HD key, and commits it to the
// SQL runtime row so GetEncryptedHDSeed succeeds.
func TestCreateRecoversSeedAfterPartialCreate(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	rootKey, err := hdkeychain.NewMaster(params.Seed, &chainParams)
	require.NoError(t, err)

	// Arrange: simulate the partial-create state by creating only the
	// legacy store, capturing the encrypted master HD key it persisted.
	encSeed, err := createLegacyStore(
		context.Background(), cfg, params, rootKey,
	)
	require.NoError(t, err)
	require.NotEmpty(t, encSeed)

	// Act: retry the full create. It must tolerate the existing legacy
	// wallet and recover its seed rather than committing a nil one.
	w, err := NewManager().Create(cfg, params)
	require.NoError(t, err)
	require.NotNil(t, w)
	t.Cleanup(func() {
		require.NoError(t, w.closeRuntimeStore())
	})

	// Assert: the SQL runtime row holds the same encrypted master HD key,
	// so SQL-backed key derivation can read it back.
	got, err := w.store.GetEncryptedHDSeed(t.Context(), w.id)
	require.NoError(t, err)
	require.Equal(t, encSeed, got)
}
