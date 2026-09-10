package wallet

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
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

	// Arrange: Build one durable create request and require exactly one Store
	// mutation returning the committed row used for Wallet assembly.
	params := sqliteCreateParams(t)
	store := &walletmock.Store{}
	rootKey, err := hdkeychain.NewMaster(params.Seed, &chainParams)
	require.NoError(t, err)

	masterPubKey, err := rootKey.Neuter()
	require.NoError(t, err)

	store.On("CreateWallet", mock.Anything,
		mock.AnythingOfType("db.CreateWalletParams")).
		Return(&db.WalletInfo{
			ID:           7,
			Name:         params.Name,
			MasterPubKey: []byte(masterPubKey.String()),
		}, nil).Once()

	// Act: Create through Manager so a forbidden readback would reach the
	// strict Store mock as an unexpected call.
	w, err := testSQLManager(t, store).Create(params)

	// Assert: Verify the returned Wallet uses the committed row ID and the
	// required Store call was consumed exactly once.
	require.NoError(t, err)
	require.Equal(t, uint32(7), w.ID())
	store.AssertExpectations(t)
}

// sqliteCreateParams returns a spendable seed-import request with a durable
// identity for tests that exercise the maintained SQL Manager create path.
func sqliteCreateParams(t *testing.T) CreateWalletParams {
	t.Helper()

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(t, err)

	params := CreateWalletParams{
		Name:              testWalletName,
		Mode:              ModeImportSeed,
		Seed:              seed,
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	}

	return params
}

// TestSQLiteCreateWalletParamsCreatesSpendableSecrets verifies that SQL wallet
// creation parameters carry real encrypted secret material for spendable
// wallets.
func TestSQLiteCreateWalletParamsCreatesSpendableSecrets(t *testing.T) {
	t.Parallel()

	params := sqliteCreateParams(t)

	rootKey, err := hdkeychain.NewMaster(params.Seed, &chainParams)
	require.NoError(t, err)

	got, err := sqlCreateWalletParams(
		params, rootKey, birthdayWithSafetyMargin(params.Birthday),
	)
	require.NoError(t, err)

	require.NoError(t, got.Validate())
	require.NotEmpty(t, got.MasterKeyPrivParams)
	require.NotEmpty(t, got.EncryptedCryptoPrivKey)
	require.NotEmpty(t, got.EncryptedCryptoScriptKey)
	require.NotEmpty(t, got.EncryptedMasterPrivKey)
}

// TestNewManagerClassifiesDatabaseIdentityMismatch proves public callers can
// distinguish a persisted network mismatch without importing internal/db.
func TestNewManagerClassifiesDatabaseIdentityMismatch(t *testing.T) {
	t.Parallel()

	// Arrange: Initialize one SQLite file with the regression-test identity.
	dbPath := filepath.Join(t.TempDir(), "identity.sqlite")
	manager, err := NewManager(t.Context(), ManagerConfig{
		Backend:     DBBackendSQLite,
		DataSource:  dbPath,
		ChainParams: chainParams,
		ChainSource: &bwmock.Chain{},
	})
	require.NoError(t, err)
	require.NoError(t, manager.Stop())

	// Act: Reopen the same file through the public API with testnet identity.
	rejected, err := NewManager(t.Context(), ManagerConfig{
		Backend:     DBBackendSQLite,
		DataSource:  dbPath,
		ChainParams: chaincfg.TestNet3Params,
		ChainSource: &bwmock.Chain{},
	})

	// Assert: The wallet-owned sentinel identifies the rejected Manager.
	require.ErrorIs(t, err, ErrDatabaseIdentityMismatch)
	require.Nil(t, rejected)
}

// TestManagerSQLiteCreateWatchOnlyRejectsEmptyPrivatePassphrase verifies the
// SQL Manager surfaces the public empty-passphrase sentinel and no Wallet when
// watch-only creation omits the passphrase protecting its script key.
func TestManagerSQLiteCreateWatchOnlyRejectsEmptyPrivatePassphrase(
	t *testing.T) {

	t.Parallel()

	m := testSQLiteManager(t)
	w, err := m.Create(CreateWalletParams{
		Name:      testWalletName,
		Mode:      ModeShell,
		WatchOnly: true,
	})
	require.ErrorIs(t, err, ErrEmptyPassphrase)
	require.Nil(t, w)
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

			// Arrange: a spendable seed-import create. The
			// store-backed key vault requires a non-empty private
			// passphrase for every wallet.
			params := CreateWalletParams{
				Name:              testWalletName,
				Mode:              ModeImportSeed,
				PrivatePassphrase: []byte("private"),
			}

			// Act: build the SQL runtime create params with the
			// already-resolved birthday.
			got, err := sqlCreateWalletParams(
				params, rootKey, tc.birthday,
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

// TestManagerSQLiteReopenDerivesAddress verifies two SQLite requirements that
// same-Manager creation cannot: a fresh Manager assembles the durable Wallet
// from the same file during aggregate Start, and NewManager installs
// sqlite.Config.DeriveAddress. Calling public AddressManager.NewAddress proves
// the deriver is available on that reconstructed Wallet.
func TestManagerSQLiteReopenDerivesAddress(t *testing.T) {
	t.Parallel()

	// Arrange: Create a durable Wallet through the existing SQLite fixture.
	// Its strict chain dependency observes the later public derivation, while
	// Stop releases this Manager's original runtime and database connection.
	m := testSQLiteManager(t)
	chainMock, ok := m.config.ChainSource.(*bwmock.Chain)
	require.True(t, ok)
	chainMock.On("NotifyReceived", mock.Anything).Return(nil).Once()

	params := sqliteCreateParams(t)
	original, err := m.Create(params)
	require.NoError(t, err)
	require.NoError(t, m.Stop())

	// Act: Construct a fresh Manager over the same database after shutdown,
	// then derive through its runtime's installed Store callback. Register
	// cleanup before startup so the original chain fixture outlives its work.
	reopened, err := NewManager(t.Context(), m.config)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = reopened.Stop()
	})

	wallets, err := reopened.Start(t.Context())
	require.NoError(t, err)
	require.Len(t, wallets, 1)
	w := wallets[0]
	require.NoError(t, w.Unlock(t.Context(), UnlockRequest{
		Passphrase: params.PrivatePassphrase,
		Timeout:    -1,
	}))

	_, err = w.NewAccount(t.Context(), NewAccountParams{
		Scope: waddrmgr.KeyScopeBIP0084,
		Name:  waddrmgr.DefaultAccountName,
	})
	require.NoError(t, err)

	addr, err := w.NewAddress(
		t.Context(), waddrmgr.DefaultAccountName,
		waddrmgr.WitnessPubKey, false,
	)

	// Assert: The public derivation succeeds and its required notification
	// proves the loaded Wallet received the Manager-owned chain source.
	require.NotSame(t, original, w)
	require.NoError(t, err, "NewAddress requires the installed deriver")
	require.NotNil(t, addr)
}
