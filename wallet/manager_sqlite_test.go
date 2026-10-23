package wallet

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// rollbackStoreMock injects only the rollback outcome while delegating every
// other operation to the real SQL Store shared by Manager and its Wallets.
type rollbackStoreMock struct {
	mock.Mock
	db.Store
}

// rollbackStoreMock retains the complete real Store contract by embedding it.
var _ db.Store = (*rollbackStoreMock)(nil)

// RollbackToBlock reports the arranged outcome; a Run hook may commit through
// the embedded Store first to model an ambiguous successful transaction.
func (s *rollbackStoreMock) RollbackToBlock(ctx context.Context,
	height uint32) error {

	args := s.Called(ctx, height)
	return args.Error(0)
}

// TestManagerRollbackSQLite exercises coordinated durable state and terminal
// rollback outcomes on SQLite without requiring the Docker-only test tag.
func TestManagerRollbackSQLite(t *testing.T) {
	t.Parallel()

	// Arrange: Supply a fresh SQLite database for each outcome, using the
	// shared scenario's real Wallet workers and strict rollback-only mock.
	// Act: The scenario submits each disconnect through prepared admission.
	// Assert: It checks affected/lower checkpoints, effects, continuation, and
	// terminal errors against durable state and the running Wallet handles.
	testManagerRollbackStore(t, DBBackendSQLite, func(t *testing.T) string {
		t.Helper()

		return filepath.Join(t.TempDir(), "rollback.sqlite")
	})
}

// testManagerRollbackStore applies the same explicit success and terminal
// failure scenarios to both SQL backends, reusing existing Store proofs.
func testManagerRollbackStore(t *testing.T, backend DBBackend,
	dataSource func(*testing.T) string) {

	t.Helper()

	// Success has additional continuation calls, so it owns a separate
	// scenario rather than changing the error table's mock arrangement.
	t.Run("success", func(t *testing.T) {
		t.Parallel()

		testManagerRollbackSuccess(t, backend, dataSource(t))
	})

	// Both errors use identical mock calls; only the reported commit outcome
	// differs. The ambiguous scenario commits its real Store before returning.
	tests := []struct {
		name    string
		failure error
	}{
		{
			name:    "definite failure",
			failure: errDBMock,
		},
		{
			name: "committed but ambiguous",
			failure: &dbruntime.AmbiguousTxCommitError{
				Err: errDBMock,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			testManagerRollbackFailure(t, backend, dataSource(t), test.failure)
		})
	}
}

// seedManagerRollback creates the same three real Wallets and seeds the
// affected pair after worker readiness. Outcome-specific mocks and assertions
// stay in each scenario; both SQL backends reuse this deterministic work.
func seedManagerRollback(t *testing.T, m *Manager, store db.Store,
	ready <-chan struct{}) ([]*Wallet, db.Block, db.Block, *wire.MsgTx) {

	t.Helper()

	// Start all three real workers before seeding persistence. The third Wallet
	// stays below the fork while the first two share the removed block.
	_, err := m.Start(t.Context())
	require.NoError(t, err)

	wallets := make([]*Wallet, 0, 3)
	for _, name := range []string{"first", "second", "below"} {
		w, createErr := m.Create(managerLifecycleCreateParams(name))
		require.NoError(t, createErr)

		wallets = append(wallets, w)
	}

	// Each receipt marks one worker reaching its initial notification wait,
	// so all three can service the subsequent prepared pause.
	<-ready
	<-ready
	<-ready

	// Height 1 is the retained fork; height 2 holds a confirmed payment in
	// each affected Wallet. The third Wallet retains its genesis checkpoint.
	fork := db.Block{
		Height: 1, Hash: chainhash.Hash{1}, Timestamp: time.Unix(1, 0),
	}
	old := db.Block{
		Height: 2, Hash: chainhash.Hash{2}, Timestamp: time.Unix(2, 0),
	}

	tx := subscriptionTx([]byte{txscript.OP_TRUE}, 2)
	for _, w := range wallets[:2] {
		require.NoError(t, store.ApplyScanBatch(t.Context(),
			db.ScanBatchParams{
				WalletID: w.ID(), SyncedBlocks: []db.Block{fork, old},
				Transactions: []db.CreateTxParams{
					{
						WalletID: w.ID(), Tx: tx, Block: &old,
						Received: old.Timestamp,
						Status:   db.TxStatusPublished,
					},
				},
			}))
	}

	return wallets, fork, old, tx
}

// testManagerRollbackSuccess rewinds affected durable checkpoints and effects,
// preserves a lower Wallet, and verifies subsequent prepared delivery resumes.
func testManagerRollbackSuccess(t *testing.T, backend DBBackend,
	dataSource string) {

	t.Helper()

	// Arrange: A fresh current Chain has no inherited non-current
	// expectation. Each real worker signals its notification wait.
	source := &bwmock.Chain{}
	t.Cleanup(func() { source.AssertExpectations(t) })
	m, err := NewManager(t.Context(), ManagerConfig{
		Backend: backend, DataSource: dataSource,
		ChainParams: chainParams, ChainSource: source,
	})
	require.NoError(t, err)

	storage, ok := m.backend.(*sqlManagerBackend)
	require.True(t, ok)

	store := &rollbackStoreMock{Store: storage.store}
	t.Cleanup(func() { store.AssertExpectations(t) })
	t.Cleanup(func() { require.NoError(t, m.Stop()) })

	storage.store = store

	// Three readiness receipts are required for startup, three after rollback,
	// and three after replacement delivery. Already-known unmined payments
	// need no maintenance write when each affected worker resumes twice.
	source.On("TestMempoolAccept", mock.Anything, float64(0)).
		Return(nil, chain.ErrTxAlreadyInMempool).Times(4)

	ready := make(chan struct{}, 9)
	expectChainEventSource(source, 3, 9, ready, nil)
	// Birthday verification precedes each worker's normal tip read.
	source.On("GetBestBlock").
		Return(chainParams.GenesisHash, int32(0), nil).Times(3)
	source.On("GetBlockHash", int64(0)).
		Return(chainParams.GenesisHash, nil).Times(3)
	source.On("GetBlockHeader", chainParams.GenesisHash).
		Return(&chainParams.GenesisBlock.Header, nil).Times(3)

	store.On("RollbackToBlock", mock.Anything, uint32(2)).
		Run(func(args mock.Arguments) {
			// Fault injection delegates the one accepted rollback to real
			// persistence; only its completion allows worker continuation.
			ctx, valid := args.Get(0).(context.Context)
			require.True(t, valid)
			require.NoError(t, store.Store.RollbackToBlock(ctx, 2))
		}).Return(nil).Once()

	wallets, fork, old, tx := seedManagerRollback(t, m, store, ready)

	// Capture the unaffected Wallet's exact checkpoint before rollback,
	// rather than assuming every active Wallet shares the affected height.
	below, err := store.GetWallet(t.Context(), "below")
	require.NoError(t, err)

	// Act: Submit one disconnect through Manager; the SQL Store receives it
	// only after the complete published Wallet set acknowledges its pause.
	err = m.dispatchChainEvent(t.Context(), chain.BlockDisconnected{
		Block: wtxmgr.Block{Height: 2, Hash: old.Hash},
	})

	// Assert: Wait for all three resumed workers to reach notification receipt
	// before reading rewound tips and the payment's unmined status.
	require.NoError(t, err)
	<-ready
	<-ready
	<-ready

	for _, w := range wallets[:2] {
		info, readErr := store.GetWallet(t.Context(), w.cfg.Name)
		require.NoError(t, readErr)
		require.Equal(t, fork, *info.SyncedTo)
		stored, readErr := store.GetTx(t.Context(), db.GetTxQuery{
			WalletID: w.ID(), Txid: tx.TxHash(),
		})
		require.NoError(t, readErr)
		require.Nil(t, stored.Block)
	}

	lower, err := store.GetWallet(t.Context(), "below")
	require.NoError(t, err)
	require.Equal(t, below.SyncedTo, lower.SyncedTo)

	// Act: Deliver a replacement at the removed height after all workers have
	// resumed; this proves prepared admission continues after rollback.
	next := wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Height: 2, Hash: chainhash.Hash{3}},
		Time:  time.Unix(3, 0),
	}
	require.NoError(t, m.dispatchChainEvent(t.Context(),
		chain.BlockConnected(next)))

	// Assert: Each receipt follows the replacement delivery. Check the two
	// rewound Wallets now expose the replacement hash through durable state.
	<-ready
	<-ready
	<-ready

	for _, w := range wallets[:2] {
		info, readErr := store.GetWallet(t.Context(), w.cfg.Name)
		require.NoError(t, readErr)
		require.Equal(t, next.Hash, info.SyncedTo.Hash)
	}
}

// testManagerRollbackFailure terminates every real Wallet for either error
// outcome without retrying or automatically reading back the rollback result.
func testManagerRollbackFailure(t *testing.T, backend DBBackend,
	dataSource string, failure error) {

	t.Helper()

	// Arrange: A fresh current Chain has no inherited non-current
	// expectation. Each real worker signals its notification wait.
	source := &bwmock.Chain{}
	t.Cleanup(func() { source.AssertExpectations(t) })
	m, err := NewManager(t.Context(), ManagerConfig{
		Backend: backend, DataSource: dataSource,
		ChainParams: chainParams, ChainSource: source,
	})
	require.NoError(t, err)

	storage, ok := m.backend.(*sqlManagerBackend)
	require.True(t, ok)

	store := &rollbackStoreMock{Store: storage.store}
	t.Cleanup(func() { store.AssertExpectations(t) })
	t.Cleanup(func() { require.NoError(t, m.Stop()) })

	storage.store = store

	// Only startup reaches notification receipt: an error must cancel and
	// join workers instead of allowing the successful continuation calls.
	ready := make(chan struct{}, 3)
	expectChainEventSource(source, 3, 3, ready, nil)
	// Birthday verification precedes each worker's normal tip read.
	source.On("GetBestBlock").
		Return(chainParams.GenesisHash, int32(0), nil).Times(3)
	source.On("GetBlockHash", int64(0)).
		Return(chainParams.GenesisHash, nil).Times(3)
	source.On("GetBlockHeader", chainParams.GenesisHash).
		Return(&chainParams.GenesisBlock.Header, nil).Times(3)

	store.On("RollbackToBlock", mock.Anything, uint32(2)).
		Run(func(args mock.Arguments) {
			// Keep the same mock expectation for both errors. Commit only
			// the ambiguous fault's real transaction before reporting it.
			if errors.Is(failure, dbruntime.ErrAmbiguousTxCommit) {
				ctx, valid := args.Get(0).(context.Context)
				require.True(t, valid)
				require.NoError(t, store.Store.RollbackToBlock(ctx, 2))
			}
		}).Return(failure).Once()

	wallets, _, old, _ := seedManagerRollback(t, m, store, ready)

	// Act: Report the arranged failure from the one coordinated disconnect,
	// including a transaction that really committed before ambiguity arose.
	err = m.dispatchChainEvent(t.Context(), chain.BlockDisconnected{
		Block: wtxmgr.Block{Height: 2, Hash: old.Hash},
	})

	// Assert: The exact error survives terminal cleanup, every retained Wallet
	// is inert, and later prepared work performs no retry or Store readback.
	require.ErrorIs(t, err, failure)

	for _, w := range wallets {
		_, infoErr := w.Info(t.Context())
		require.ErrorIs(t, infoErr, ErrWalletStopped)
	}

	require.ErrorIs(t, m.dispatchChainEvent(t.Context(),
		chain.BlockDisconnected{}), ErrStateForbidden)
}

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
