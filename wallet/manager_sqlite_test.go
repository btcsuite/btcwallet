package wallet

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestChangeAllocationSQLiteNoChainSync verifies fresh change remains available
// on excluded accounts without registering their scripts for live tracking.
func TestChangeAllocationSQLiteNoChainSync(t *testing.T) {
	t.Parallel()

	// Arrange: create an excluded account in a real SQLite wallet.
	m := testSQLiteManager(t)
	params := sqliteCreateParams(t)
	w, err := m.Create(params)
	require.NoError(t, err)

	chainMock, ok := w.cfg.Chain.(*bwmock.Chain)
	require.True(t, ok)
	require.NoError(t, w.Unlock(t.Context(), UnlockRequest{
		Passphrase: params.PrivatePassphrase, Timeout: -1,
	}))

	number := AccountNumber(7)
	scope := waddrmgr.KeyScopeBIP0084
	account, err := w.NewAccount(t.Context(), NewAccountParams{
		Scope: scope, Name: "excluded-change",
		AccountNumber: &number, NoChainSync: true,
	})
	require.NoError(t, err)
	changeAccount, _, err := w.resolveChangeAccount(
		t.Context(), &ScopedAccount{
			KeyScope: scope, AccountName: account.AccountName,
		},
	)
	require.NoError(t, err)

	// Act: allocate fresh change on the excluded account and register it as
	// kept change.
	change, err := w.allocateChangeAddress(t.Context(), scope, changeAccount)
	require.NoError(t, err)
	require.NoError(t, w.watchAuthoredChange(
		t.Context(), 0, changeAccount, change,
	))

	script := change.ScriptPubKey

	// Assert: the fresh child persists without live script registration.
	stored, err := w.store.GetAddress(t.Context(), db.GetAddressQuery{
		WalletID: w.id, ScriptPubKey: script,
	})
	require.NoError(t, err)
	require.Equal(t, uint32(1), stored.Branch)
	require.Zero(t, stored.Index)

	_, addrs, _, err := txscript.ExtractPkScriptAddrs(script, &chainParams)
	require.NoError(t, err)
	chainMock.AssertNotCalled(t, "WatchAddrsFromTip", mock.Anything, addrs)
}

// TestChangeWatchFailureSQLiteKeepsChange verifies that a failed change
// registration leaves the exact committed change child in a real SQLite Store.
func TestChangeWatchFailureSQLiteKeepsChange(t *testing.T) {
	t.Parallel()

	// Arrange: Keep the backend non-current so only the change watch
	// registers, then allocate change on a chain-synchronized account.
	m := testSQLiteManager(t)
	params := sqliteCreateParams(t)
	w, err := m.Create(params)
	require.NoError(t, err)

	chainMock, ok := w.cfg.Chain.(*bwmock.Chain)
	require.True(t, ok)
	chainMock.On("WatchAddrsFromTip", mock.Anything, mock.Anything).Unset()
	require.NoError(t, w.Unlock(t.Context(), UnlockRequest{
		Passphrase: params.PrivatePassphrase, Timeout: -1,
	}))

	scope := waddrmgr.KeyScopeBIP0084
	_, err = w.NewAccount(t.Context(), NewAccountParams{
		Scope: scope, Name: "synced-change",
	})
	require.NoError(t, err)

	changeAccount, _, err := w.resolveChangeAccount(
		t.Context(), &ScopedAccount{
			KeyScope: scope, AccountName: "synced-change",
		},
	)
	require.NoError(t, err)

	change, err := w.allocateChangeAddress(t.Context(), scope, changeAccount)
	require.NoError(t, err)

	script := change.ScriptPubKey

	_, addrs, _, err := txscript.ExtractPkScriptAddrs(script, &chainParams)
	require.NoError(t, err)
	chainMock.On("WatchAddrsFromTip", w.lifetimeCtx, addrs).
		Return(errChainMock).Once()

	// Act: Register the kept change and fail the backend registration.
	err = w.watchAuthoredChange(t.Context(), 0, changeAccount, change)

	// Assert: The failure is returned and the committed child remains.
	require.ErrorIs(t, err, errChainMock)
	stored, err := w.store.GetAddress(t.Context(), db.GetAddressQuery{
		WalletID: w.id, ScriptPubKey: script,
	})
	require.NoError(t, err)
	require.Equal(t, uint32(1), stored.Branch)
	require.Zero(t, stored.Index)
}

// TestFundPsbtReservationSQLite verifies the public FundPsbt reservation
// against a real SQLite Store: a funded attempt owns every packet input for
// the fixed duration, an attempt whose authoring fails leaves no lease, a
// leased input cannot be funded again until released, and after an early
// release a fresh attempt owns it.
func TestFundPsbtReservationSQLite(t *testing.T) {
	t.Parallel()

	// Arrange: Create a real SQLite wallet over a current chain so the
	// real syncer reaches synced at genesis, and store two pending credits
	// to a committed wallet script.
	chain := newTestChain(t, true)
	chain.On("BlockStamp").Return(&waddrmgr.BlockStamp{
		Hash: *chainParams.GenesisHash,
	}, nil).Maybe()

	w := createSQLiteWallet(t, chain)
	// Manager opens the shared stream before Wallet startup. Observe the
	// Wallet's own sync status before funding, rather than source readiness.
	require.Eventually(
		t, func() bool {
			info, err := w.Info(t.Context())
			return err == nil && info.Synced
		}, 5*time.Second, time.Millisecond,
	)

	script, first, second := storeFundingCredits(t, w)
	fund := func(value int64, input wire.OutPoint) (*FundResult, error) {
		return w.FundPsbt(t.Context(), &FundIntent{
			Packet:  newFundingPacket(t, script, value, input),
			FeeRate: defaultFeeRate,
			ChangeSource: &ScopedAccount{
				KeyScope:    waddrmgr.KeyScopeBIP0084,
				AccountName: "funding",
			},
		})
	}

	// Act: Fund one input, fail authoring on the other by overspending
	// it, try to fund the leased input again, then release it early under
	// the returned lease ID and fund it again.
	before := time.Now()
	owned, ownErr := fund(10_000, first)
	ownedLeases, err := w.ListLeasedOutputs(t.Context())
	require.NoError(t, err)

	overspent, overspendErr := fund(1_000_000, second)
	afterOverspend, err := w.ListLeasedOutputs(t.Context())
	require.NoError(t, err)

	leased, leasedErr := fund(10_000, first)

	require.NoError(t, ownErr)
	require.NoError(t, w.ReleaseOutput(t.Context(), owned.LeaseID, first))
	retried, retryErr := fund(10_000, first)
	finalLeases, err := w.ListLeasedOutputs(t.Context())
	require.NoError(t, err)

	// Assert: The funded attempt owns its only input under the lease ID
	// it returned for about ten minutes, the failed authoring left that
	// single lease untouched, the leased input was refused before
	// reservation, and after the release the retry owns it under a
	// different, freshly generated ID.
	funded := owned.Packet
	require.Len(t, funded.UnsignedTx.TxIn, 1)
	require.Equal(t, first, funded.UnsignedTx.TxIn[0].PreviousOutPoint)
	require.NotEqual(t, wtxmgr.LockID{}, owned.LeaseID)
	require.Len(t, ownedLeases, 1)
	require.Equal(t, first, ownedLeases[0].OutPoint)
	require.Equal(t, owned.LeaseID, ownedLeases[0].LockID)
	require.WithinDuration(
		t, before.Add(fundLeaseDuration), ownedLeases[0].Expiration,
		time.Minute,
	)

	require.ErrorIs(t, overspendErr, insufficientFundsError(t))
	require.Nil(t, overspent)
	require.Equal(t, ownedLeases, afterOverspend)

	require.ErrorIs(t, leasedErr, ErrUtxoNotEligible)
	require.Nil(t, leased)

	require.NoError(t, retryErr)
	require.NotEqual(t, owned.LeaseID, retried.LeaseID)
	require.Len(t, finalLeases, 1)
	require.Equal(t, first, finalLeases[0].OutPoint)
	require.Equal(t, retried.LeaseID, finalLeases[0].LockID)
}

// createSQLiteWallet creates and unlocks a real SQLite wallet over the
// supplied chain and adds the BIP84 "funding" account used by funding tests.
func createSQLiteWallet(t *testing.T, chain *bwmock.Chain) *Wallet {
	t.Helper()

	m := testSQLiteManagerWithChain(t, chain)
	params := sqliteCreateParams(t)
	w, err := m.Create(params)
	require.NoError(t, err)
	require.NoError(t, w.Unlock(t.Context(), UnlockRequest{
		Passphrase: params.PrivatePassphrase, Timeout: -1,
	}))

	_, err = w.NewAccount(t.Context(), NewAccountParams{
		Scope: waddrmgr.KeyScopeBIP0084, Name: "funding",
	})
	require.NoError(t, err)

	return w
}

// storeFundingCredits stores one pending transaction paying 20,000 and 30,000
// sats to a fresh "funding" account script, and returns that script and the
// two credited outpoints.
func storeFundingCredits(t *testing.T, w *Wallet) ([]byte, wire.OutPoint,
	wire.OutPoint) {

	t.Helper()

	changeAccount, _, err := w.resolveChangeAccount(
		t.Context(), &ScopedAccount{
			KeyScope: waddrmgr.KeyScopeBIP0084, AccountName: "funding",
		},
	)
	require.NoError(t, err)
	change, err := w.allocateChangeAddress(
		t.Context(), waddrmgr.KeyScopeBIP0084, changeAccount,
	)
	require.NoError(t, err)

	script := change.ScriptPubKey

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 1}})
	tx.AddTxOut(wire.NewTxOut(20_000, script))
	tx.AddTxOut(wire.NewTxOut(30_000, script))
	err = w.store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: w.id,
		Tx:       tx,
		Received: time.Now(),
		Status:   db.TxStatusPending,
		Credits:  map[uint32]address.Address{0: nil, 1: nil},
	})
	require.NoError(t, err)

	return script, wire.OutPoint{Hash: tx.TxHash(), Index: 0},
		wire.OutPoint{Hash: tx.TxHash(), Index: 1}
}

// newFundingPacket builds a PSBT spending the given inputs to one output of
// value sats paying script.
func newFundingPacket(t *testing.T, script []byte, value int64,
	inputs ...wire.OutPoint) *psbt.Packet {

	t.Helper()

	spend := wire.NewMsgTx(wire.TxVersion)
	for _, input := range inputs {
		spend.AddTxIn(&wire.TxIn{PreviousOutPoint: input})
	}

	spend.AddTxOut(wire.NewTxOut(value, script))

	packet, err := psbt.NewFromUnsignedTx(spend)
	require.NoError(t, err)

	return packet
}

// TestManagerCreateUsesCommittedWalletRow verifies that Create assembles the
// Wallet identity from the row Store.CreateWallet returned. The later runtime
// birthday read must not replace the committed identity during assembly.
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

	// Runtime startup reads the birthday after assembly; the committed ID
	// remains authoritative even if this later read carries no identity.
	store.On("GetWallet", mock.Anything, params.Name).Return(
		&db.WalletInfo{BirthdayBlock: &db.Block{}}, nil,
	).Once()
	store.On("ListAccounts", mock.Anything, db.ListAccountsQuery{
		WalletID: 7,
	}).
		Return([]db.AccountInfo{}, nil).Once()
	store.On("DeleteExpiredLeases", mock.Anything, uint32(7)).Return(nil).Once()

	// Act: Create through Manager, including its mandatory runtime startup,
	// with a birthday row that cannot supply the committed identity.
	w, err := testSQLManager(t, store).Create(params)

	// Assert: Verify the returned Wallet uses the committed row ID and the
	// required Store call was consumed exactly once.
	require.NoError(t, err)
	require.Equal(t, uint32(7), w.ID())
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

// TestManagerSQLiteCreatePublishes verifies that Create returns an active
// Wallet while another Start correctly rejects the already running Manager.
func TestManagerSQLiteCreatePublishes(t *testing.T) {
	t.Parallel()

	params := sqliteCreateParams(t)
	m := testSQLiteManager(t)

	w, err := m.Create(params)
	repeated, startErr := m.Start(t.Context())

	require.NoError(t, err)
	require.NotNil(t, w)
	require.ErrorIs(t, startErr, ErrStateForbidden)
	require.Nil(t, repeated)

	// A successful public operation proves the returned pointer is active.
	require.NoError(t, w.Lock(t.Context()))
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

	info, err := w.NewAddress(
		t.Context(), NewAccountSelectorByName(
			waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountName,
		), false,
	)

	// Assert: The public derivation succeeds and its required registration
	// proves the loaded Wallet received the Manager-owned chain source.
	require.NotSame(t, original, w)
	require.NoError(t, err, "NewAddress requires the installed deriver")
	require.NotNil(t, info.Addr)
	chainMock.AssertCalled(
		t, "WatchAddrsFromTip", w.lifetimeCtx,
		[]address.Address{info.Addr},
	)
}
