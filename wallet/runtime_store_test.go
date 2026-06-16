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

// writeLegacyOnlyWallet arranges a partial create that left only the legacy
// kvdb wallet behind (no SQL runtime row), as an earlier attempt that failed
// before committing the runtime row would. It exists so the retry tests can
// assert just the resulting error without discarding createLegacyStore's data
// returns at every call site. It checks the encrypted seed was captured so a
// spendable legacy wallet is genuinely persisted before the retry runs.
func writeLegacyOnlyWallet(t *testing.T, cfg Config,
	params CreateWalletParams, rootKey *hdkeychain.ExtendedKey) {

	t.Helper()

	encSeed, _, _, err := createLegacyStore(
		context.Background(), cfg, params, rootKey,
	)
	require.NoError(t, err)
	require.NotEmpty(t, encSeed)
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
		birthdayWithSafetyMargin(params.Birthday),
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
	encSeed, legacyExisted, _, err := createLegacyStore(
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

// TestRuntimeCreateWalletParamsBirthdayVerbatim verifies that the SQL runtime
// create params persist the resolved birthday they are handed verbatim. The
// caller owns the margin decision (a fresh create supplies the requested
// birthday with the safety margin applied; a partial-create retry supplies the
// existing legacy wallet's original birthday), so this helper must not apply
// it a second time. A zero "no birthday" must pass through so it is persisted
// as NULL.
func TestRuntimeCreateWalletParamsBirthdayVerbatim(t *testing.T) {
	t.Parallel()

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(t, err)

	rootKey, err := hdkeychain.NewMaster(seed, &chainParams)
	require.NoError(t, err)

	requested := time.Date(2026, time.June, 16, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		birthday time.Time
	}{
		{
			name:     "resolved birthday is stored verbatim",
			birthday: requested.Add(-waddrmgr.BirthdaySafetyMargin),
		},
		{
			name:     "zero birthday is left untouched",
			birthday: time.Time{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a spendable seed-import create.
			cfg := Config{Name: "test-wallet"}
			params := CreateWalletParams{Mode: ModeImportSeed}

			// Act: build the SQL runtime create params with the
			// already-resolved birthday.
			got, err := runtimeCreateWalletParams(
				cfg, params, rootKey, []byte("enc-seed"),
				tc.birthday,
			)
			require.NoError(t, err)

			// Assert: the stored birthday is exactly what was
			// passed in, with no further margin applied.
			require.Equal(t, tc.birthday, got.Birthday)
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
	// the already-present default accounts, reporting zero newly created.
	seeded, err := seedDefaultAccounts(
		t.Context(), w, rootKey, params.PrivatePassphrase,
	)
	require.NoError(t, err)
	require.Zero(t, seeded)

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
// ErrWalletExists, rather than silently returning the existing wallet, only
// when the wallet is fully created: the legacy wallet and the SQL runtime row
// are present AND its post-load init (default-account seeding) is complete, so
// the idempotent replay has nothing left to do. A partial create whose rows
// exist but whose init the retry still completes is covered by
// TestManagerCreateRetryCompletesUnseededWallet, and the recoverable
// legacy-present/runtime-missing path by
// TestCreateRecoversSeedAfterPartialCreate.
func TestManagerCreateRejectsExistingSQLWallet(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	// Create the wallet end to end (rows plus seeded default accounts),
	// then release its store handles so a fresh manager can reopen the same
	// on-disk databases.
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

// TestManagerCreateRetryCompletesUnseededWallet verifies the create-retry
// wedge fix (#1): a prior create that committed both the legacy wallet and the
// SQL runtime row but failed before seeding the default accounts must be
// completable by a retry. Because discardUnstarted only cleans in-memory state
// and never the durable rows, classifying such a wallet as fully created would
// permanently wedge it (ErrWalletExists with no usable accounts). The retry
// must instead replay the idempotent seeding and return the finished wallet.
func TestManagerCreateRetryCompletesUnseededWallet(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	rootKey, err := hdkeychain.NewMaster(params.Seed, &chainParams)
	require.NoError(t, err)

	// Arrange: reproduce the partial-create state by committing both
	// durable rows but skipping the post-load default-account seeding, the
	// exact point an earlier attempt could have failed.
	encSeed, _, _, err := createLegacyStore(
		context.Background(), cfg, params, rootKey,
	)
	require.NoError(t, err)

	runtimeExisted, err := createRuntimeWallet(
		context.Background(), cfg, params, rootKey, encSeed,
		birthdayWithSafetyMargin(params.Birthday),
	)
	require.NoError(t, err)
	require.False(t, runtimeExisted)

	// Sanity check the seam: the default accounts are not yet present, so a
	// wedge-classifying create would reject this recoverable wallet.
	defaultName := waddrmgr.DefaultAccountName
	_, err = openSeededAccount(t, cfg, defaultName)
	require.ErrorIs(t, err, db.ErrAccountNotFound)

	// Act: retry the full create.
	w, err := NewManager().Create(cfg, params)

	// Assert: the retry completes the wallet rather than rejecting it, and
	// the default accounts the earlier attempt missed are now seeded.
	require.NoError(t, err)
	require.NotNil(t, w)
	t.Cleanup(func() {
		require.NoError(t, w.closeRuntimeStore())
	})

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
	}
}

// openSeededAccount opens the SQL runtime store for cfg and reads the default
// account in the BIP0084 scope, used to probe whether default-account seeding
// has run. It opens and closes its own stores before returning so the bbolt
// legacy file is released for a subsequent Manager.Create on the same path.
func openSeededAccount(t *testing.T, cfg Config,
	name string) (*db.AccountInfo, error) {

	t.Helper()

	legacyStore, err := openLegacyStore(cfg)
	require.NoError(t, err)

	handle, err := openRuntimeStore(t.Context(), cfg, legacyStore)
	require.NoError(t, err)

	info, accErr := handle.store.GetAccount(t.Context(), db.GetAccountQuery{
		WalletID:    handle.walletInfo.ID,
		Scope:       db.KeyScope(waddrmgr.KeyScopeBIP0084),
		Name:        &name,
		SkipBalance: true,
	})

	// Release both stores before returning: the caller reopens the same
	// bbolt file via Manager.Create, which would otherwise time out waiting
	// for the lock this helper still held. handle owns only the SQLite
	// store, so the legacy bbolt store is closed separately.
	require.NoError(t, handle.close())
	require.NoError(t, legacyStore.Close())

	return info, accErr
}

// TestManagerCreateRetryRejectsNilRootForSpendableLegacy verifies fix (#2): a
// retry that supplies no root key (a rootless shell or xpub-only mode) must be
// rejected when the existing legacy wallet holds master key material, rather
// than recording the SQL runtime row watch-only for a wallet that can in fact
// sign. The earlier attempt created a spendable legacy wallet; reusing it from
// a rootless retry would mislabel a spendable wallet as watch-only.
func TestManagerCreateRetryRejectsNilRootForSpendableLegacy(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	spendableRoot, err := hdkeychain.NewMaster(params.Seed, &chainParams)
	require.NoError(t, err)
	require.True(t, spendableRoot.IsPrivate())

	// Arrange: a partial create that left only a spendable legacy wallet
	// behind (it persists a master public key), with no SQL runtime row.
	writeLegacyOnlyWallet(t, cfg, params, spendableRoot)

	// Build a shell retry against the same name: shell mode derives no root
	// key, the nil-root case the fix guards.
	retryParams := CreateWalletParams{
		Mode:          ModeShell,
		PubPassphrase: params.PubPassphrase,
	}

	// Act: retry the create with no root key.
	w, err := NewManager().Create(cfg, retryParams)

	// Assert: the downgrade is rejected and no watch-only SQL row was
	// committed for the spendable legacy wallet.
	require.ErrorIs(t, err, ErrWalletParams)
	require.Nil(t, w)
}

// TestManagerCreateRetryReusesLegacyBirthday verifies fix (#3): a partial
// create reused on retry must persist the existing legacy wallet's original
// birthday in the SQL runtime row, not the retry's. Callers commonly pass a
// fresh time.Now() per attempt and the runtime birthday drives the initial
// SyncedTo tip, so persisting a later retry birthday would make the wallet
// skip deposits made before it.
func TestManagerCreateRetryReusesLegacyBirthday(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	original := time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)
	params.Birthday = original

	rootKey, err := hdkeychain.NewMaster(params.Seed, &chainParams)
	require.NoError(t, err)

	// Arrange: a partial create that left only the legacy wallet behind,
	// carrying the original birthday.
	writeLegacyOnlyWallet(t, cfg, params, rootKey)

	// Build a retry that supplies a strictly later birthday, the regression
	// that would otherwise skip funds received before it.
	later := original.AddDate(2, 0, 0)
	require.True(t, later.After(original))

	retryParams := params
	retryParams.Birthday = later

	// Act: retry the full create with the later birthday.
	w, err := NewManager().Create(cfg, retryParams)
	require.NoError(t, err)
	require.NotNil(t, w)
	t.Cleanup(func() {
		require.NoError(t, w.closeRuntimeStore())
	})

	// Assert: the SQL runtime row kept the original birthday (with the
	// safety margin applied), not the later retry birthday.
	info, err := w.store.GetWallet(t.Context(), cfg.Name)
	require.NoError(t, err)
	require.True(t, info.Birthday.Equal(birthdayWithSafetyMargin(original)),
		"got %v want %v", info.Birthday,
		birthdayWithSafetyMargin(original))
	require.False(t, info.Birthday.Equal(birthdayWithSafetyMargin(later)))
}

// TestManagerCreateRetryRejectsSeedMismatch verifies that retrying a partial
// create (legacy wallet present, SQL runtime row missing) with a different
// seed is rejected, rather than committing a SQL runtime row whose master
// pubkey and default accounts are derived from the retry seed while the legacy
// store and encrypted master key belong to the original seed.
func TestManagerCreateRetryRejectsSeedMismatch(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	originalRoot, err := hdkeychain.NewMaster(params.Seed, &chainParams)
	require.NoError(t, err)

	// Arrange: simulate a partial create by writing only the legacy store
	// from the original seed; no SQL runtime row exists yet.
	writeLegacyOnlyWallet(t, cfg, params, originalRoot)

	// Build a retry that reuses the same name but supplies a different
	// seed, hence a different master key.
	mismatchedSeed, err := hdkeychain.GenerateSeed(
		hdkeychain.RecommendedSeedLen,
	)
	require.NoError(t, err)
	require.NotEqual(t, params.Seed, mismatchedSeed)

	retryParams := params
	retryParams.Seed = mismatchedSeed

	// Act: retry the full create with the mismatched seed.
	w, err := NewManager().Create(cfg, retryParams)

	// Assert: the mismatch is rejected and no SQL runtime row was created
	// from the wrong key material, so a correct retry can still proceed.
	require.ErrorIs(t, err, ErrWalletParams)
	require.Nil(t, w)

	w, err = NewManager().Create(cfg, params)
	require.NoError(t, err)
	require.NotNil(t, w)
	t.Cleanup(func() {
		require.NoError(t, w.closeRuntimeStore())
	})
}
