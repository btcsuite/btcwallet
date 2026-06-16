package wallet

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/waddrmgr"
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
	_, err = createRuntimeWallet(
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
	encSeed, legacyExisted, err := createLegacyStore(
		context.Background(), cfg, params, rootKey,
	)
	require.NoError(t, err)
	require.NotEmpty(t, encSeed)
	require.False(t, legacyExisted)

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

// TestRuntimeCreateWalletParamsBirthdaySafetyMargin verifies that the SQL
// runtime create params back a requested birthday off by the legacy address
// manager's safety margin, matching the kvdb backend, while leaving a zero
// "no birthday" untouched so it is still persisted as NULL.
func TestRuntimeCreateWalletParamsBirthdaySafetyMargin(t *testing.T) {
	t.Parallel()

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(t, err)

	rootKey, err := hdkeychain.NewMaster(seed, &chainParams)
	require.NoError(t, err)

	requested := time.Date(2026, time.June, 16, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		birthday time.Time
		want     time.Time
	}{
		{
			name:     "non-zero birthday is backed off by the margin",
			birthday: requested,
			want:     requested.Add(-waddrmgr.BirthdaySafetyMargin),
		},
		{
			name:     "zero birthday is left untouched",
			birthday: time.Time{},
			want:     time.Time{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a spendable seed-import create carrying the
			// requested birthday.
			cfg := Config{Name: "test-wallet"}
			params := CreateWalletParams{
				Mode:     ModeImportSeed,
				Birthday: tc.birthday,
			}

			// Act: build the SQL runtime create params.
			got, err := runtimeCreateWalletParams(
				cfg, params, rootKey, []byte("enc-seed"),
			)
			require.NoError(t, err)

			// Assert: the stored birthday carries the safety
			// margin (or stays zero), matching legacy behavior.
			require.Equal(t, tc.want, got.Birthday)
		})
	}
}

// TestBirthdayWithSafetyMargin verifies the helper subtracts exactly the legacy
// safety margin from a real birthday and passes a zero birthday through.
func TestBirthdayWithSafetyMargin(t *testing.T) {
	t.Parallel()

	birthday := time.Date(2026, time.June, 16, 0, 0, 0, 0, time.UTC)

	require.Equal(
		t, birthday.Add(-waddrmgr.BirthdaySafetyMargin),
		birthdayWithSafetyMargin(birthday),
	)
	require.True(t, birthdayWithSafetyMargin(time.Time{}).IsZero())
}

// TestSeedDefaultAccountsIdempotent verifies that re-running default-account
// seeding on a wallet whose default accounts already exist is a no-op rather
// than an error. A Create that failed after seeding only some scopes is
// retried against the same wallet, so replaying the seed for an already-seeded
// scope must not wedge on the unique (wallet, scope, name) constraint.
func TestSeedDefaultAccountsIdempotent(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	rootKey, err := hdkeychain.NewMaster(params.Seed, &chainParams)
	require.NoError(t, err)

	// Create the spendable SQL wallet; this seeds the default accounts once.
	w, err := NewManager().Create(cfg, params)
	require.NoError(t, err)
	require.NotNil(t, w)
	t.Cleanup(func() {
		require.NoError(t, w.closeRuntimeStore())
	})

	// Re-running the seed (the retry path) must succeed without recreating
	// the already-present default accounts.
	err = seedDefaultAccounts(
		t.Context(), w, rootKey, params.PrivatePassphrase,
	)
	require.NoError(t, err)

	// Each default scope must still hold exactly one default account, so
	// the idempotent re-run did not duplicate or renumber anything.
	for _, scope := range waddrmgr.DefaultKeyScopes {
		name := waddrmgr.DefaultAccountName
		info, err := w.store.GetAccount(t.Context(), db.GetAccountQuery{
			WalletID:    w.id,
			Scope:       db.KeyScope(scope),
			Name:        &name,
			SkipBalance: true,
		})
		require.NoError(t, err)
		require.Equal(t, waddrmgr.DefaultAccountName, info.AccountName)
		require.NotNil(t, info.AccountNumber)
		require.Equal(t, uint32(0), *info.AccountNumber)
	}
}

// TestManagerCreateRejectsExistingSQLWallet verifies that Create returns
// ErrWalletExists, rather than silently returning the existing wallet, when
// both the legacy wallet and the SQL runtime row are already present. The
// recoverable partial-create path (legacy present, runtime row missing) stays
// tolerated and is covered separately.
func TestManagerCreateRejectsExistingSQLWallet(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	// Create the wallet end to end, then release its store handles so a
	// fresh manager can reopen the same on-disk databases.
	w, err := NewManager().Create(cfg, params)
	require.NoError(t, err)
	require.NotNil(t, w)
	require.NoError(t, w.closeRuntimeStore())

	// Act: a second create against the now fully created wallet.
	w2, err := NewManager().Create(cfg, params)

	// Assert: it is rejected as an existing wallet, not silently returned.
	require.ErrorIs(t, err, ErrWalletExists)
	require.Nil(t, w2)
}
