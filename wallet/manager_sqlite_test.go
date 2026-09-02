package wallet

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestManagerCreateUsesCommittedWalletRow verifies that Create assembles the
// Wallet from the row Store.CreateWallet returned and never reads it back. A
// post-create GetWallet would be a failure with no recovery: the row is already
// durable, so surfacing the read error would strand a wallet a retry could no
// longer create. The store mock is strict, so an unexpected GetWallet fails the
// test.
func TestManagerCreateUsesCommittedWalletRow(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	store := &walletmock.Store{}
	t.Cleanup(func() { store.AssertExpectations(t) })

	rootKey, err := hdkeychain.NewMaster(params.Seed, &chainParams)
	require.NoError(t, err)

	masterPubKey, err := rootKey.Neuter()
	require.NoError(t, err)

	store.On("CreateWallet", mock.Anything,
		mock.AnythingOfType("db.CreateWalletParams")).
		Return(&db.WalletInfo{
			ID:           7,
			Name:         cfg.Name,
			MasterPubKey: []byte(masterPubKey.String()),
		}, nil).Once()

	w, err := testSQLManager(t, store).Create(cfg, params)
	require.NoError(t, err)
	require.Equal(t, uint32(7), w.ID())
}

// TestManagerLoadPreservesBackendFailure verifies that a non-not-found SQL
// backend failure is not reclassified as a missing wallet.
func TestManagerLoadPreservesBackendFailure(t *testing.T) {
	t.Parallel()

	// Arrange a SQL manager whose wallet lookup returns an unrelated
	// backend sentinel instead of the database not-found classification.
	cfg, _ := sqliteCreateConfig(t)
	store := &walletmock.Store{}
	t.Cleanup(func() { store.AssertExpectations(t) })

	store.On("GetWallet", mock.Anything, cfg.Name).
		Return(nil, errDBMock).Once()

	// Act by loading the wallet through the public Manager boundary.
	w, err := testSQLManager(t, store).Load(cfg)

	// Assert that the original backend failure remains discoverable and is
	// not replaced with the public missing-wallet sentinel.
	require.ErrorIs(t, err, errDBMock)
	require.NotErrorIs(t, err, ErrWalletNotFound)
	require.Nil(t, w)
}

// sqliteCreateConfig returns a SQLite-backed create config and a spendable
// seed-import params pair sharing fresh temp paths, for tests that exercise
// the SQL create path end to end.
func sqliteCreateConfig(t *testing.T) (Config, CreateWalletParams) {
	t.Helper()

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(t, err)

	cfg := Config{
		Chain:       &bwmock.Chain{},
		ChainParams: &chainParams,
		Name:        testWalletName,
	}
	params := CreateWalletParams{
		Mode:              ModeImportSeed,
		Seed:              seed,
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	}

	return cfg, params
}

// TestSQLiteCreateWalletParamsCreatesSpendableSecrets verifies that SQL wallet
// creation parameters carry real encrypted secret material for spendable
// wallets.
func TestSQLiteCreateWalletParamsCreatesSpendableSecrets(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)

	rootKey, err := hdkeychain.NewMaster(params.Seed, &chainParams)
	require.NoError(t, err)

	got, err := sqlCreateWalletParams(
		cfg, params, rootKey, birthdayWithSafetyMargin(params.Birthday),
	)
	require.NoError(t, err)

	require.NoError(t, got.Validate())
	require.NotEmpty(t, got.MasterKeyPrivParams)
	require.NotEmpty(t, got.EncryptedCryptoPrivKey)
	require.NotEmpty(t, got.EncryptedCryptoScriptKey)
	require.NotEmpty(t, got.EncryptedMasterPrivKey)
}

// TestManagerSQLiteCreateLoadCached verifies that a SQLite wallet created
// through the Manager is published under its name, so a same-Manager Load
// returns that very Wallet rather than building a second one.
func TestManagerSQLiteCreateLoadCached(t *testing.T) {
	t.Parallel()

	cfg, params := sqliteCreateConfig(t)
	m := testSQLiteManager(t)

	w, err := m.Create(cfg, params)
	require.NoError(t, err)
	require.NotNil(t, w)

	// Create publishes the wallet, so Load returns the same pointer over the
	// Manager-owned store.
	loaded, err := m.Load(cfg)
	require.NoError(t, err)
	require.Same(t, w, loaded)
}

// TestSQLiteCreateWalletParamsBirthdayVerbatim verifies that the SQLite
// create params persist the birthday they are handed verbatim. The caller owns
// the margin decision — Create applies waddrmgr's safety margin — so this
// helper must not apply it a second time. A zero "no birthday" must pass
// through so it is persisted as NULL.
func TestSQLiteCreateWalletParamsBirthdayVerbatim(t *testing.T) {
	t.Parallel()

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(t, err)

	rootKey, err := hdkeychain.NewMaster(seed, &chainParams)
	require.NoError(t, err)

	// Warm the extended key's lazily-cached public key so the parallel
	// subtests below only read it; hdkeychain populates it on first use, which
	// would otherwise race across concurrent Neuter calls.
	_, err = rootKey.Neuter()
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

			// Arrange: a spendable seed-import create. A
			// non-empty private passphrase is required because
			// the store-backed key vault rejects an empty
			// passphrase for a spendable wallet.
			cfg := Config{Name: testWalletName}
			params := CreateWalletParams{
				Mode:              ModeImportSeed,
				PrivatePassphrase: []byte("private"),
			}

			// Act: build the SQL runtime create params with the
			// already-resolved birthday.
			got, err := sqlCreateWalletParams(
				cfg, params, rootKey, tc.birthday,
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

// TestManagerSQLiteReopenDerivesAddress verifies the two SQLite requirements a
// same-Manager Create/Load cannot: that a *fresh* Manager over the same file
// serves the storage Load path, and that NewManager installed
// sqlite.Config.DeriveAddress — proven by calling the public
// AddressManager.NewAddress, which is the only caller that needs the deriver.
func TestManagerSQLiteReopenDerivesAddress(t *testing.T) {
	t.Parallel()

	// Arrange: Prepare a shared strict chain mock with one required address
	// notification, then create and close the durable SQLite Wallet so no
	// runtime instance remains cached.
	dbPath := filepath.Join(t.TempDir(), "runtime.sqlite")
	chainMock := &bwmock.Chain{}

	newManager := func() *Manager {
		m, err := NewManager(t.Context(), ManagerConfig{
			Backend:     DBBackendSQLite,
			DataSource:  dbPath,
			ChainParams: chainParams,
			ChainSource: chainMock,
		})
		require.NoError(t, err)

		return m
	}

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(t, err)

	cfg := Config{Name: testWalletName}
	privPass := []byte("private")

	chainMock.On("NotifyReceived", mock.Anything).Return(nil).Once()

	creator := newManager()
	_, err = creator.Create(cfg, CreateWalletParams{
		Mode:              ModeImportSeed,
		Seed:              seed,
		PrivatePassphrase: privPass,
		Birthday:          time.Now(),
	})
	require.NoError(t, err)
	require.NoError(t, creator.Close())

	// Act: Have a fresh Manager load the Wallet, unlock its vault, and derive
	// an address through the Store callback installed during construction.
	m := newManager()
	t.Cleanup(func() { _ = m.Close() })

	w, err := m.Load(cfg)
	require.NoError(t, err)

	startLoadedWalletForTest(t, w)
	require.NoError(t, w.keyVault.Unlock(t.Context(), privPass))
	w.state.toUnlocked()

	_, err = w.NewAccount(
		t.Context(), waddrmgr.KeyScopeBIP0084,
		waddrmgr.DefaultAccountName,
	)
	require.NoError(t, err)

	addr, err := w.NewAddress(
		t.Context(), waddrmgr.DefaultAccountName,
		waddrmgr.WitnessPubKey, false,
	)

	// Assert: The public derivation succeeds and its required notification
	// proves the loaded Wallet received the Manager-owned chain source.
	require.NoError(t, err, "NewAddress requires the installed deriver")
	require.NotNil(t, addr)
	chainMock.AssertExpectations(t)
}
