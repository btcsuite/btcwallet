package wallet

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestDBCreateWallet verifies that the wallet database is correctly
// initialized with the address and transaction manager buckets.
func TestDBCreateWallet(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet with a fresh database.
	// Note: createTestWalletWithMocks creates the top-level buckets, but
	// they are empty. DBCreateWallet will populate them.
	w, _ := createTestWalletWithMocks(t)

	params := CreateWalletParams{
		PubPassphrase:     []byte("public"),
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	}

	// Act: Initialize the wallet database.
	err := DBCreateWallet(w.cfg, params, nil)

	// Assert: Verify initialization success.
	require.NoError(t, err)

	// Verify that the address manager and transaction manager can be
	// opened, indicating successful initialization.
	err = walletdb.View(w.cfg.DB, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		require.NotNil(t, addrmgrNs)

		_, err := waddrmgr.Open(
			addrmgrNs, params.PubPassphrase, w.cfg.ChainParams,
		)
		if err != nil {
			return err
		}

		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, txmgrNs)

		_, err = wtxmgr.Open(txmgrNs, w.cfg.ChainParams)

		return err
	})
	require.NoError(t, err)
}

// TestDBLoadWallet verifies that the wallet database can be successfully loaded
// and the address and transaction managers retrieved.
func TestDBLoadWallet(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet and initialize it.
	w, _ := createTestWalletWithMocks(t)

	pubPass := []byte("public")
	w.cfg.PubPassphrase = pubPass

	params := CreateWalletParams{
		PubPassphrase:     pubPass,
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	}

	err := DBCreateWallet(w.cfg, params, nil)
	require.NoError(t, err)

	// Act: Load the wallet database.
	addrMgr, txMgr, err := DBLoadWallet(w.cfg)

	// Assert: Verify that both managers were loaded successfully.
	require.NoError(t, err)
	require.NotNil(t, addrMgr)
	require.NotNil(t, txMgr)
}

// TestDBBirthdayBlock verifies that the wallet can successfully persist and
// retrieve its birthday block information.
func TestDBBirthdayBlock(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet with mocked underlying stores.
	w, mocks := createTestWalletWithMocks(t)

	block := waddrmgr.BlockStamp{
		Height:    100,
		Hash:      chainhash.Hash{0x01},
		Timestamp: time.Unix(1000, 0),
	}

	// 1. Test DBPutBirthdayBlock.
	//
	// Arrange: Setup the expected mock calls for updating the birthday
	// block and the sync tip in the address manager.
	mocks.addrStore.On(
		"SetBirthdayBlock", mock.Anything, block, true,
	).Return(nil).Once()
	mocks.addrStore.On(
		"SetSyncedTo", mock.Anything, &block,
	).Return(nil).Once()

	// Act: Persist the birthday block to the database.
	err := w.DBPutBirthdayBlock(t.Context(), block)

	// Assert: Ensure the update completed without error.
	require.NoError(t, err)

	// 2. Test DBGetBirthdayBlock.
	//
	// Arrange: Setup the expected mock call for retrieving the birthday
	// block from the address manager.
	mocks.addrStore.On(
		"BirthdayBlock", mock.Anything,
	).Return(block, true, nil).Once()

	// Act: Retrieve the persisted birthday block from the database.
	retBlock, verified, err := w.DBGetBirthdayBlock(t.Context())

	// Assert: Verify the retrieved block data and verification status
	// matches what was persisted.
	require.NoError(t, err)
	require.True(t, verified)
	require.Equal(t, block, retBlock)
}

// TestDBUnlock verifies that the wallet can successfully unlock its address
// manager using the provided passphrase.
func TestDBUnlock(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet and setup the expected mock call for
	// unlocking the address manager.
	w, mocks := createTestWalletWithMocks(t)
	pass := []byte("password")

	mocks.addrStore.On("Unlock", mock.Anything, pass).Return(nil).Once()

	// Act: Attempt to unlock the wallet with the passphrase.
	err := w.DBUnlock(t.Context(), pass)

	// Assert: Verify that the unlock operation succeeded.
	require.NoError(t, err)
}

// TestDBDeleteExpiredLockedOutputs verifies that the wallet successfully
// invokes the transaction store to remove any expired output locks.
func TestDBDeleteExpiredLockedOutputs(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet and setup the expected mock call for
	// deleting expired locked outputs.
	w, mocks := createTestWalletWithMocks(t)

	mocks.txStore.On(
		"DeleteExpiredLockedOutputs", mock.Anything,
	).Return(nil).Once()

	// Act: Trigger the cleanup of expired locked outputs in the database.
	err := w.DBDeleteExpiredLockedOutputs(t.Context())

	// Assert: Verify that the cleanup operation finished without error.
	require.NoError(t, err)
}

// TestDBPutPassphrase verifies that the wallet can successfully update both
// its public and private passphrases in the address manager.
func TestDBPutPassphrase(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet and a request to change both
	// passphrases.
	w, mocks := createTestWalletWithMocks(t)

	req := ChangePassphraseRequest{
		ChangePublic:  true,
		PublicOld:     []byte("old"),
		PublicNew:     []byte("new"),
		ChangePrivate: true,
		PrivateOld:    []byte("old_priv"),
		PrivateNew:    []byte("new_priv"),
	}

	// Setup mock calls for both passphrase changes.
	mocks.addrStore.On(
		"ChangePassphrase", mock.Anything, []byte("old"), []byte("new"),
		false, mock.Anything,
	).Return(nil).Once()

	mocks.addrStore.On(
		"ChangePassphrase", mock.Anything, req.PrivateOld,
		req.PrivateNew, true,
		mock.MatchedBy(func(opts *waddrmgr.ScryptOptions) bool {
			return opts.N == 16 && opts.R == 8 && opts.P == 1
		}),
	).Return(nil).Once()

	// Act: Commit the passphrase changes to the database.
	err := w.DBPutPassphrase(t.Context(), req)

	// Assert: Verify that both passphrases were updated successfully.
	require.NoError(t, err)
}

// TestDBPutPassphrase_Error verifies that DBPutPassphrase correctly handles
// and returns errors encountered during the passphrase update process.
func TestDBPutPassphrase_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet and setup a mock call that simulates
	// a database error during a private passphrase change.
	w, mocks := createTestWalletWithMocks(t)

	req := ChangePassphraseRequest{
		ChangePrivate: true,
	}

	mocks.addrStore.On(
		"ChangePassphrase", mock.Anything, mock.Anything,
		mock.Anything, true, mock.Anything,
	).Return(errDBMock).Once()

	// Act: Attempt to change the passphrase, expecting a failure.
	err := w.DBPutPassphrase(t.Context(), req)

	// Assert: Verify that the expected database error is returned.
	require.ErrorContains(t, err, "db error")
}

// TestDBPutBlocks_Error verifies that DBPutBlocks correctly handles errors
// that occur during the transaction matching resolution phase.
func TestDBPutBlocks_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Create a syncer with mocked stores and setup a scenario
	// where address lookup fails during transaction resolution.
	w, mocks := createTestWalletWithMocks(t)
	s := newSyncer(w.cfg, w.addrStore, w.txStore, nil, &walletmock.Store{}, 0)

	addr, _ := address.NewAddressPubKeyHash(
		make([]byte, 20), &chaincfg.MainNetParams,
	)
	matches := TxEntries{{Entries: []AddrEntry{{Address: addr}}}}

	mocks.addrStore.On("Address", mock.Anything, addr).Return(
		nil, errDBMock,
	).Once()

	// Act: Attempt to process a block with relevant transactions.
	err := s.DBPutBlocks(t.Context(), matches, nil)

	// Assert: Verify that the address lookup error is correctly
	// propagated.
	require.ErrorContains(t, err, "db error")
}

// TestDBPutSyncBatch_Error verifies that DBPutSyncBatch correctly propagates
// errors encountered when fetching scoped key managers for horizon updates.
func TestDBPutSyncBatch_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Create a syncer and a scan result that requires updating an
	// address manager's horizon.
	w, mocks := createTestWalletWithMocks(t)
	s := newSyncer(w.cfg, w.addrStore, w.txStore, nil, &walletmock.Store{}, 0)

	res := scanResult{
		meta: &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Height: 100},
		},
		BlockProcessResult: &BlockProcessResult{
			FoundHorizons: map[waddrmgr.BranchScope]uint32{
				{
					Scope: waddrmgr.KeyScopeBIP0084,
				}: 5,
			},
		},
	}

	// Simulate a failure when fetching the scoped key manager.
	mocks.addrStore.On(
		"FetchScopedKeyManager", waddrmgr.KeyScopeBIP0084,
	).Return(nil, errMock).Once()

	// Act: Attempt to commit a batch of scan results to the database.
	err := s.DBPutSyncBatch(t.Context(), []scanResult{res})

	// Assert: Verify that the expected error is returned.
	require.ErrorIs(t, err, errMock)
}

// TestDBPutBlocks verifies the full lifecycle of DBPutBlocks, including
// resolving transaction scopes, marking addresses as used, inserting confirmed
// transactions, and updating the sync tip.
func TestDBPutBlocks(t *testing.T) {
	t.Parallel()

	// Arrange: Create a syncer and setup test data for a confirmed
	// transaction.
	w, mocks := createTestWalletWithMocks(t)
	s := newSyncer(w.cfg, w.addrStore, w.txStore, nil, &walletmock.Store{}, 0)

	tx := wire.NewMsgTx(1)
	rec, _ := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
	addr, _ := address.NewAddressPubKeyHash(
		make([]byte, 20), &chaincfg.MainNetParams,
	)

	matches := TxEntries{{
		Rec: rec,
		Entries: []AddrEntry{{
			Address: addr,
		}},
	}}

	block := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Height: 100},
	}

	// 1. Transaction Resolution.
	//
	// Setup mocks to resolve the address scope for the transaction output.
	mockAddr := &bwmock.ManagedPubKeyAddr{}
	mockAddr.On("Internal").Return(false).Once()
	mocks.addrStore.On("Address", mock.Anything, addr).Return(
		mockAddr, nil,
	).Once()

	scopedMgr := &bwmock.AccountStore{}
	scopedMgr.On("Scope").Return(waddrmgr.KeyScopeBIP0084).Once()
	mocks.addrStore.On("AddrAccount", mock.Anything, addr).Return(
		scopedMgr, uint32(0), nil,
	).Once()

	// 2. Transaction Insertion.
	//
	// Expect the address to be marked as used and the transaction to be
	// inserted as confirmed.
	mocks.addrStore.On("MarkUsed", mock.Anything, addr).Return(nil).Once()
	mocks.txStore.On("InsertConfirmedTx", mock.Anything, rec, block,
		mock.Anything,
	).Return(nil).Once()

	// 3. Sync Tip Update.
	//
	// Expect the wallet's sync tip to be updated to the new block.
	mocks.addrStore.On("SetSyncedTo", mock.Anything, mock.Anything).Return(
		nil,
	).Once()

	// Act: Process the block and its relevant transactions.
	err := s.DBPutBlocks(t.Context(), matches, block)

	// Assert: Verify that all operations completed successfully.
	require.NoError(t, err)
}

// TestDBPutTxns verifies that DBPutTxns can successfully resolve and persist
// unconfirmed transactions in the wallet's transaction store.
func TestDBPutTxns(t *testing.T) {
	t.Parallel()

	// Arrange: Create a syncer and setup test data for an unconfirmed
	// transaction.
	w, mocks := createTestWalletWithMocks(t)
	s := newSyncer(w.cfg, w.addrStore, w.txStore, nil, &walletmock.Store{}, 0)

	tx := wire.NewMsgTx(1)
	rec, _ := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
	addr, _ := address.NewAddressPubKeyHash(
		make([]byte, 20), &chaincfg.MainNetParams,
	)

	matches := TxEntries{{
		Rec: rec,
		Entries: []AddrEntry{{
			Address: addr,
		}},
	}}

	// Setup mock calls to resolve the address scope and persist the
	// unconfirmed transaction.
	mockAddr := &bwmock.ManagedPubKeyAddr{}
	mockAddr.On("Internal").Return(false).Once()
	mocks.addrStore.On("Address", mock.Anything, addr).Return(
		mockAddr, nil,
	).Once()

	scopedMgr := &bwmock.AccountStore{}
	scopedMgr.On("Scope").Return(waddrmgr.KeyScopeBIP0084).Once()
	mocks.addrStore.On("AddrAccount", mock.Anything, addr).Return(
		scopedMgr, uint32(0), nil,
	).Once()

	mocks.addrStore.On("MarkUsed", mock.Anything, addr).Return(nil).Once()
	mocks.txStore.On("InsertUnconfirmedTx", mock.Anything, rec,
		mock.Anything,
	).Return(nil).Once()

	// Act: Attempt to persist the unconfirmed transaction.
	err := s.DBPutTxns(t.Context(), matches, nil)

	// Assert: Verify that the transaction was persisted successfully.
	require.NoError(t, err)
}

// TestPutAddrHorizons verifies that address horizons are correctly extended
// in the database based on scan results.
func TestPutAddrHorizons(t *testing.T) {
	t.Parallel()

	// Arrange: Create a syncer and setup a scan result that indicates a
	// horizon expansion is needed for a specific BIP84 account.
	w, mocks := createTestWalletWithMocks(t)
	s := newSyncer(w.cfg, w.addrStore, w.txStore, nil, &walletmock.Store{}, 0)

	bs := waddrmgr.BranchScope{
		Scope:   waddrmgr.KeyScopeBIP0084,
		Account: 0,
		Branch:  waddrmgr.ExternalBranch,
	}

	res := []scanResult{{
		BlockProcessResult: &BlockProcessResult{
			FoundHorizons: map[waddrmgr.BranchScope]uint32{
				bs: 10,
			},
		},
	}}

	// Setup mock calls for fetching the manager and extending the
	// addresses.
	scopedMgr := &bwmock.AccountStore{}
	mocks.addrStore.On("FetchScopedKeyManager", bs.Scope).Return(
		scopedMgr, nil,
	).Once()
	scopedMgr.On("AccountProperties", mock.Anything, bs.Account).Return(
		&waddrmgr.AccountProperties{ExternalKeyCount: 4}, nil,
	).Once()

	scopedMgr.On("ExtendAddresses", mock.Anything, bs.Account, uint32(10),
		bs.Branch,
	).Return(nil).Once()
	scopedMgr.On("AccountProperties", mock.Anything, bs.Account).Return(
		&waddrmgr.AccountProperties{ExternalKeyCount: 11}, nil,
	).Once()

	// Act: Trigger the horizon expansion within a database transaction.
	var rollback addrHorizonRollback

	err := walletdb.Update(w.cfg.DB, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		var err error

		rollback, err = s.putAddrHorizons(t.Context(), ns, res)

		return err
	})

	// Assert: Verify that the horizons were extended without error.
	require.NoError(t, err)
	require.Len(t, rollback, 1)
}

// TestDBGetScanData verifies that the wallet can successfully retrieve all
// necessary state (horizons, active addresses, and UTXOs) to initialize a
// chain rescan.
func TestDBGetScanData(t *testing.T) {
	t.Parallel()

	// Arrange: Create a syncer and setup mock expectations for all data
	// required during rescan initialization.
	w, mocks := createTestWalletWithMocks(t)
	s := newSyncer(w.cfg, w.addrStore, w.txStore, nil, &walletmock.Store{}, 0)

	targets := []waddrmgr.AccountScope{{
		Scope:   waddrmgr.KeyScopeBIP0084,
		Account: 0,
	}}

	// 1. Horizons lookup.
	scopedMgr := &bwmock.AccountStore{}
	mocks.addrStore.On("FetchScopedKeyManager",
		waddrmgr.KeyScopeBIP0084,
	).Return(scopedMgr, nil).Once()

	props := &waddrmgr.AccountProperties{AccountNumber: 0}
	scopedMgr.On("AccountProperties", mock.Anything, uint32(0)).Return(
		props, nil,
	).Once()

	// 2. Active addresses lookup.
	mocks.addrStore.On("ForEachRelevantActiveAddress", mock.Anything,
		mock.Anything,
	).Return(nil).Once()

	// 3. UTXO lookup.
	mocks.txStore.On("OutputsToWatch", mock.Anything).Return(
		[]wtxmgr.Credit(nil), nil,
	).Once()

	// Act: Retrieve the initial scan data from the database.
	horizonData, initialAddrs, initialUnspent, err := s.DBGetScanData(
		t.Context(), targets,
	)

	// Assert: Verify that the retrieved data matches our expectations and
	// that no error occurred.
	require.NoError(t, err)
	require.Len(t, horizonData, 1)
	require.Equal(t, props, horizonData[0])
	require.Empty(t, initialAddrs)
	require.Empty(t, initialUnspent)
}

// TestLoadWalletScanDataKeepsImportedXpubHorizons verifies that full-scan setup
// builds its horizon targets from the legacy address manager's active accounts.
// Imported xpub accounts have real waddrmgr account numbers that must remain in
// the lookahead set even though SQL account metadata may not expose a BIP44
// account number for them.
func TestLoadWalletScanDataKeepsImportedXpubHorizons(t *testing.T) {
	t.Parallel()

	w, mocks := createTestWalletWithMocks(t)
	s := newSyncer(w.cfg, w.addrStore, w.txStore, nil, &walletmock.Store{}, 0)

	const importedAccount = uint32(9)

	scope := waddrmgr.KeyScopeBIP0084
	props := &waddrmgr.AccountProperties{
		AccountNumber:    importedAccount,
		AccountName:      "imported-xpub",
		ExternalKeyCount: 5,
		InternalKeyCount: 2,
		KeyScope:         scope,
		IsWatchOnly:      true,
	}

	scopedMgr := &bwmock.AccountStore{}
	mocks.addrStore.On("ActiveScopedKeyManagers").Return(
		[]waddrmgr.AccountStore{scopedMgr},
	).Once()

	scopedMgr.On("ActiveAccounts").Return([]uint32{importedAccount}).Once()
	scopedMgr.On("Scope").Return(scope).Once()

	mocks.addrStore.On("FetchScopedKeyManager", scope).Return(
		scopedMgr, nil,
	).Once()

	scopedMgr.On("AccountProperties", mock.Anything, importedAccount).Return(
		props, nil,
	).Once()

	mocks.addrStore.On("ForEachRelevantActiveAddress", mock.Anything,
		mock.Anything,
	).Return(nil).Once()

	mocks.txStore.On("OutputsToWatch", mock.Anything).Return(
		[]wtxmgr.Credit(nil), nil,
	).Once()

	horizonData, initialAddrs, initialUnspent, err := s.loadWalletScanData(
		t.Context(),
	)

	require.NoError(t, err)
	require.Len(t, horizonData, 1)
	require.Equal(t, props, horizonData[0])
	require.Equal(t, importedAccount, horizonData[0].AccountNumber)
	require.Empty(t, initialAddrs)
	require.Empty(t, initialUnspent)

	mocks.addrStore.AssertExpectations(t)
	scopedMgr.AssertExpectations(t)
}

// TestDBGetSyncedBlocks verifies that the wallet can successfully retrieve a
// range of block hashes from its internal index.
func TestDBGetSyncedBlocks(t *testing.T) {
	t.Parallel()

	// Arrange: Create a syncer and setup a mock expectation for fetching a
	// block hash from the address manager.
	w, mocks := createTestWalletWithMocks(t)
	s := newSyncer(w.cfg, w.addrStore, w.txStore, nil, &walletmock.Store{}, 0)

	hash := chainhash.Hash{0x01}
	mocks.addrStore.On("BlockHash", mock.Anything, int32(100)).Return(
		&hash, nil,
	).Once()

	// Act: Fetch the block hashes for the requested range.
	hashes, err := s.DBGetSyncedBlocks(t.Context(), 100, 100)

	// Assert: Verify that the retrieved hash is correct.
	require.NoError(t, err)
	require.Len(t, hashes, 1)
	require.Equal(t, &hash, hashes[0])
}

// TestDBPutRewind verifies that the wallet can successfully rewind its
// synchronized state and transaction history to a specific point.
func TestDBPutRewind(t *testing.T) {
	t.Parallel()

	// Arrange: Create a syncer and setup mock expectations for updating
	// the sync tip and rolling back the transaction store.
	w, mocks := createTestWalletWithMocks(t)
	s := newSyncer(w.cfg, w.addrStore, w.txStore, nil, &walletmock.Store{}, 0)

	bs := waddrmgr.BlockStamp{Height: 100, Hash: chainhash.Hash{0x01}}

	// DBPutRewind snapshots the synced tip inside the update so it can
	// restore it on failure; the successful path never restores.
	preRewindTip := waddrmgr.BlockStamp{Height: 50, Hash: chainhash.Hash{0x09}}
	mocks.addrStore.On("SyncedTo").Return(preRewindTip).Once()
	mocks.addrStore.On("SetSyncedTo", mock.Anything, &bs).Return(nil).Once()
	mocks.txStore.On("Rollback",
		mock.Anything, int32(101),
	).Return(nil).Once()

	// Act: Rewind the wallet state to the specified block height.
	err := s.DBPutRewind(t.Context(), bs)

	// Assert: Verify that the rewind operation succeeded. The mock's
	// AssertExpectations confirms RestoreSyncedTo was not called.
	require.NoError(t, err)
}

// TestDBPutRewind_RollbackFailureRestoresTip verifies that when SetSyncedTo
// succeeds and advances the in-memory synced tip but the subsequent
// txStore.Rollback fails, DBPutRewind conditionally restores the in-memory tip
// to the pre-rewind value. SetSyncedTo writes the bucket and advances the live
// manager's tip immediately, so a rolled-back update would otherwise leave the
// tip rewound to a fork point that was never persisted.
func TestDBPutRewind_RollbackFailureRestoresTip(t *testing.T) {
	t.Parallel()

	// Arrange: SetSyncedTo succeeds (advancing the in-memory tip) and then
	// Rollback fails, forcing the restore path.
	w, mocks := createTestWalletWithMocks(t)
	s := newSyncer(w.cfg, w.addrStore, w.txStore, nil, &walletmock.Store{}, 0)

	bs := waddrmgr.BlockStamp{Height: 100, Hash: chainhash.Hash{0x01}}

	preRewindTip := waddrmgr.BlockStamp{
		Height: 150, Hash: chainhash.Hash{0x42},
	}
	mocks.addrStore.On("SyncedTo").Return(preRewindTip).Once()
	mocks.addrStore.On("SetSyncedTo", mock.Anything, &bs).Return(nil).Once()
	mocks.txStore.On("Rollback",
		mock.Anything, int32(101),
	).Return(errRollbackFail).Once()
	mocks.addrStore.On("RestoreSyncedToIfCurrent", preRewindTip, bs).
		Return(true).Once()

	// Act: Rewind the wallet state, expecting the rollback to fail.
	err := s.DBPutRewind(t.Context(), bs)

	// Assert: The error propagates and the pre-rewind tip is restored if the
	// live tip still points at the rewound fork point. The mock's
	// AssertExpectations confirms the conditional restore was called with the
	// snapshotted pre-rewind tip and the rewind target.
	require.ErrorIs(t, err, errRollbackFail)
	mocks.addrStore.AssertExpectations(t)
}

// TestDBPutBirthdayBlock_Error verifies that DBPutBirthdayBlock correctly
// handles and returns database errors during persistence.
func TestDBPutBirthdayBlock_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet and setup a mock call that simulates a
	// failure when setting the birthday block.
	w, mocks := createTestWalletWithMocks(t)

	bs := waddrmgr.BlockStamp{Height: 100}

	mocks.addrStore.On("SetBirthdayBlock", mock.Anything, bs, true).Return(
		errDBMock,
	).Once()

	// Act: Attempt to persist the birthday block, expecting a failure.
	err := w.DBPutBirthdayBlock(t.Context(), bs)

	// Assert: Verify that the database error is correctly propagated.
	require.ErrorContains(t, err, "db error")
}

// TestDBGetAllAccounts_Error verifies that DBGetAllAccounts correctly
// handles and returns database errors encountered while iterating over
// accounts.
func TestDBGetAllAccounts_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Create a test wallet and setup a mock call that simulates a
	// failure while querying for the last account index.
	w, mocks := createTestWalletWithMocks(t)
	scopedMgr := &bwmock.AccountStore{}

	mocks.addrStore.On("ActiveScopedKeyManagers").Return(
		[]waddrmgr.AccountStore{scopedMgr},
	).Once()

	scopedMgr.On("LastAccount", mock.Anything).Return(
		uint32(0), errDBMock,
	).Once()

	// Act: Attempt to load all account properties.
	err := w.DBGetAllAccounts(t.Context())

	// Assert: Verify that the expected error is returned.
	require.ErrorContains(t, err, "db error")
}

// TestDBGetScanData_MultipleTargets verifies that DBGetScanData correctly
// aggregates horizon data when multiple account scopes are requested.
func TestDBGetScanData_MultipleTargets(t *testing.T) {
	t.Parallel()

	// Arrange: Create a syncer and setup test data for multiple accounts
	// across different scopes.
	w, mocks := createTestWalletWithMocks(t)
	s := newSyncer(w.cfg, w.addrStore, w.txStore, nil, &walletmock.Store{}, 0)

	targets := []waddrmgr.AccountScope{
		{Scope: waddrmgr.KeyScopeBIP0084, Account: 0},
		{Scope: waddrmgr.KeyScopeBIP0049Plus, Account: 1},
	}

	// Setup mock calls to handle property retrieval for both targets.
	scopedMgr := &bwmock.AccountStore{}
	mocks.addrStore.On("FetchScopedKeyManager", mock.Anything).Return(
		scopedMgr, nil,
	).Twice()

	scopedMgr.On("AccountProperties", mock.Anything, mock.Anything).Return(
		&waddrmgr.AccountProperties{}, nil,
	).Twice()

	mocks.addrStore.On("ForEachRelevantActiveAddress", mock.Anything,
		mock.Anything,
	).Return(nil).Once()

	mocks.txStore.On("OutputsToWatch", mock.Anything).Return(
		[]wtxmgr.Credit(nil), nil,
	).Once()

	// Act: Retrieve initial scan data for all requested targets.
	horizons, _, _, err := s.DBGetScanData(t.Context(), targets)

	// Assert: Verify that data for both targets was successfully
	// collected.
	require.NoError(t, err)
	require.Len(t, horizons, 2)
}

// TestDBGetScanData_Error verifies that DBGetScanData correctly handles
// and returns database errors during horizon lookup, ensuring no stale
// data is returned.
func TestDBGetScanData_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Create a syncer and setup a mock expectation for a failure
	// while fetching a scoped key manager.
	w, mocks := createTestWalletWithMocks(t)
	s := newSyncer(w.cfg, w.addrStore, w.txStore, nil, &walletmock.Store{}, 0)

	targets := []waddrmgr.AccountScope{{
		Scope:   waddrmgr.KeyScopeBIP0084,
		Account: 0,
	}}

	mocks.addrStore.On("FetchScopedKeyManager",
		waddrmgr.KeyScopeBIP0084,
	).Return(nil, errDBMock).Once()

	// Act: Attempt to retrieve scan data, which is expected to fail.
	horizons, addrs, unspent, err := s.DBGetScanData(t.Context(), targets)

	// Assert: Verify that the database error is returned and all returned
	// data slices are nil.
	require.ErrorContains(t, err, "db error")
	require.Nil(t, horizons)
	require.Nil(t, addrs)
	require.Nil(t, unspent)
}

// TestDBPutTargetedBatch_WithTxns verifies that DBPutTargetedBatch processes
// relevant outputs.
func TestDBPutTargetedBatch_WithTxns(t *testing.T) {
	t.Parallel()

	// Arrange: Create a syncer and mock dependencies for processing a
	// targeted batch.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &bwmock.AddrStore{}
	mockTxStore := &bwmock.TxStore{}

	s := newSyncer(
		Config{DB: db}, mockAddrStore, mockTxStore, nil,
		&walletmock.Store{}, 0,
	)

	rec, err := wtxmgr.NewTxRecordFromMsgTx(wire.NewMsgTx(1), time.Now())
	require.NoError(t, err)

	results := []scanResult{
		{
			meta: &wtxmgr.BlockMeta{
				Block: wtxmgr.Block{Height: 100},
				Time:  time.Now(),
			},
			BlockProcessResult: &BlockProcessResult{
				RelevantOutputs: TxEntries{
					{Rec: rec, Entries: []AddrEntry{}},
				},
			},
		},
	}

	mockTxStore.On("InsertConfirmedTx", mock.Anything, mock.Anything,
		mock.Anything, mock.Anything).Return(nil).Once()

	// Act: Execute the targeted batch update.
	err = s.DBPutTargetedBatch(t.Context(), results)

	// Assert: Verify success.
	require.NoError(t, err)
}

// TestDBPutSyncTip_Error verifies error propagation in DBPutSyncTip.
func TestDBPutSyncTip_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where SetSyncedTo fails during
	// DBPutSyncTip.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &bwmock.AddrStore{}
	s := newSyncer(
		Config{DB: db}, mockAddrStore, nil, nil,
		&walletmock.Store{}, 0,
	)

	mockAddrStore.On("SetSyncedTo", mock.Anything,
		mock.Anything).Return(errSetFail).Once()

	// Act: Attempt to update the sync tip.
	err := s.DBPutSyncTip(t.Context(), wtxmgr.BlockMeta{})

	// Assert: Verify failure.
	require.ErrorIs(t, err, errSetFail)
}

// TestDBPutTargetedBatch_Errors verifies error paths.
func TestDBPutTargetedBatch_Errors(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where transaction insertion fails
	// during a targeted batch update.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &bwmock.AddrStore{}
	mockTxStore := &bwmock.TxStore{}
	s := newSyncer(
		Config{DB: db}, mockAddrStore, mockTxStore, nil,
		&walletmock.Store{}, 0,
	)

	rec, err := wtxmgr.NewTxRecordFromMsgTx(wire.NewMsgTx(1), time.Now())
	require.NoError(t, err)

	results := []scanResult{
		{
			meta: &wtxmgr.BlockMeta{
				Block: wtxmgr.Block{Height: 100},
				Time:  time.Now(),
			},
			BlockProcessResult: &BlockProcessResult{
				RelevantOutputs: TxEntries{
					{Rec: rec, Entries: []AddrEntry{}},
				},
			},
		},
	}

	mockTxStore.On("InsertConfirmedTx", mock.Anything, mock.Anything,
		mock.Anything, mock.Anything).Return(errDBInsert).Once()

	// Act: Execute the targeted batch update.
	err = s.DBPutTargetedBatch(t.Context(), results)

	// Assert: Verify failure.
	require.ErrorIs(t, err, errDBInsert)
}

// expectHorizonExtension sets the mock expectations for one successful horizon
// extension over a branch key range.
func expectHorizonExtension(scopedMgr *bwmock.AccountStore,
	bs waddrmgr.BranchScope, fromIndex, maxFoundIndex, toIndex uint32) {

	before := &waddrmgr.AccountProperties{}
	after := &waddrmgr.AccountProperties{}

	if bs.Branch == waddrmgr.InternalBranch {
		before.InternalKeyCount = fromIndex
		after.InternalKeyCount = toIndex
	} else {
		before.ExternalKeyCount = fromIndex
		after.ExternalKeyCount = toIndex
	}

	scopedMgr.On("AccountProperties", mock.Anything, bs.Account).Return(
		before, nil,
	).Once()
	scopedMgr.On("ExtendAddresses", mock.Anything, bs.Account, maxFoundIndex,
		bs.Branch).Return(nil).Once()
	scopedMgr.On("AccountProperties", mock.Anything, bs.Account).Return(
		after, nil,
	).Once()
}

// TestDBPutSyncBatchEvictsHorizonsOnSyncTipError verifies that a failed batch
// sync-tip update evicts addresses derived by the rolled-back horizon update.
func TestDBPutSyncBatchEvictsHorizonsOnSyncTipError(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &bwmock.AddrStore{}
	s := newSyncer(
		Config{DB: db}, mockAddrStore, nil, nil, &walletmock.Store{}, 0,
	)

	bs := waddrmgr.BranchScope{
		Scope:   waddrmgr.KeyScopeBIP0084,
		Account: 0,
		Branch:  waddrmgr.ExternalBranch,
	}
	result := scanResult{
		meta: &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Height: 100},
			Time:  time.Unix(1710005000, 0),
		},
		BlockProcessResult: &BlockProcessResult{
			FoundHorizons: map[waddrmgr.BranchScope]uint32{
				bs: 10,
			},
		},
	}

	scopedMgr := &bwmock.AccountStore{}
	mockAddrStore.On("FetchScopedKeyManager", bs.Scope).Return(
		scopedMgr, nil,
	).Once()
	expectHorizonExtension(scopedMgr, bs, 4, 10, 11)
	scopedMgr.On(
		"EvictDerivedAddresses", bs.Account, bs.Branch, uint32(4),
		uint32(11),
	).Once()
	mockAddrStore.On("SetSyncedTo", mock.Anything, mock.Anything).Return(
		errSetFail,
	).Once()

	err := s.DBPutSyncBatch(t.Context(), []scanResult{result})
	require.ErrorIs(t, err, errSetFail)
}

// TestDBPutTargetedBatchEvictsHorizonsOnTxError verifies that a failed targeted
// transaction write evicts addresses derived by the rolled-back horizon update.
func TestDBPutTargetedBatchEvictsHorizonsOnTxError(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &bwmock.AddrStore{}
	mockTxStore := &bwmock.TxStore{}
	s := newSyncer(
		Config{DB: db}, mockAddrStore, mockTxStore, nil,
		&walletmock.Store{}, 0,
	)

	bs := waddrmgr.BranchScope{
		Scope:   waddrmgr.KeyScopeBIP0084,
		Account: 0,
		Branch:  waddrmgr.ExternalBranch,
	}
	rec, err := wtxmgr.NewTxRecordFromMsgTx(wire.NewMsgTx(1), time.Now())
	require.NoError(t, err)

	result := scanResult{
		meta: &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Height: 100},
			Time:  time.Unix(1710005100, 0),
		},
		BlockProcessResult: &BlockProcessResult{
			FoundHorizons: map[waddrmgr.BranchScope]uint32{
				bs: 10,
			},
			RelevantOutputs: TxEntries{{
				Rec:     rec,
				Entries: []AddrEntry{},
			}},
		},
	}

	scopedMgr := &bwmock.AccountStore{}
	mockAddrStore.On("FetchScopedKeyManager", bs.Scope).Return(
		scopedMgr, nil,
	).Once()
	expectHorizonExtension(scopedMgr, bs, 4, 10, 11)
	scopedMgr.On(
		"EvictDerivedAddresses", bs.Account, bs.Branch, uint32(4),
		uint32(11),
	).Once()
	mockTxStore.On("InsertConfirmedTx", mock.Anything, mock.Anything,
		mock.Anything, mock.Anything).Return(errDBInsert).Once()

	err = s.DBPutTargetedBatch(t.Context(), []scanResult{result})
	require.ErrorIs(t, err, errDBInsert)
}

// TestDBPutTxns_Error verifies error propagation in DBPutTxns.
func TestDBPutTxns_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where address lookup fails during
	// transaction persistence.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &bwmock.AddrStore{}
	s := newSyncer(
		Config{DB: db}, mockAddrStore, nil, nil,
		&walletmock.Store{}, 0,
	)

	addr, err := address.NewAddressPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)

	matches := TxEntries{
		{
			Rec:     &wtxmgr.TxRecord{},
			Entries: []AddrEntry{{Address: addr}},
		},
	}

	mockAddrStore.On("Address",
		mock.Anything, mock.Anything).Return(nil, errAddr).Once()

	// Act: Attempt to persist transactions.
	err = s.DBPutTxns(t.Context(), matches, nil)

	// Assert: Verify failure.
	require.ErrorIs(t, err, errAddr)
}

// TestDBPutTxns_UnconfirmedError verifies error propagation for unconfirmed tx.
func TestDBPutTxns_UnconfirmedError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where unconfirmed transaction
	// insertion fails.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &bwmock.AddrStore{}
	mockTxStore := &bwmock.TxStore{}

	s := newSyncer(
		Config{DB: db}, mockAddrStore, mockTxStore, nil,
		&walletmock.Store{}, 0,
	)

	addr, err := address.NewAddressPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)

	matches := TxEntries{
		{
			Rec:     &wtxmgr.TxRecord{},
			Entries: []AddrEntry{{Address: addr}},
		},
	}

	maddr := &bwmock.ManagedAddress{}
	maddr.On("Internal").Return(false).Maybe()
	mockAddrStore.On("Address", mock.Anything, mock.Anything).Return(maddr,
		nil).Once()

	mgr := &bwmock.AccountStore{}
	mgr.On("Scope").Return(waddrmgr.KeyScopeBIP0084).Once()
	mockAddrStore.On("AddrAccount", mock.Anything, mock.Anything).Return(
		mgr,
		uint32(0), nil).Once()
	mockAddrStore.On("MarkUsed", mock.Anything,
		mock.Anything).Return(nil).Once()
	mockTxStore.On("InsertUnconfirmedTx", mock.Anything, mock.Anything,
		mock.Anything).Return(errInsert).Once()

	// Act: Attempt to persist unconfirmed transactions.
	err = s.DBPutTxns(t.Context(), matches, nil)

	// Assert: Verify failure.
	require.ErrorIs(t, err, errInsert)
}

// TestPutSyncTip_Error verifies error propagation.
func TestPutSyncTip_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where sync tip update fails within
	// a database transaction.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &bwmock.AddrStore{}
	s := newSyncer(
		Config{DB: db}, mockAddrStore, nil, nil,
		&walletmock.Store{}, 0,
	)

	// Act: Execute sync tip update within a database transaction.
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		mockAddrStore.On("SetSyncedTo", mock.Anything,
			mock.Anything).Return(errSetFail).Once()

		return s.putSyncTip(t.Context(), tx, wtxmgr.BlockMeta{})
	})

	// Assert: Verify failure.
	require.ErrorIs(t, err, errSetFail)
}

// TestDBGetScanData_ManagerError verifies account not found is handled.
func TestDBGetScanData_ManagerError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where key manager lookup fails
	// during scan data retrieval.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &bwmock.AddrStore{}
	s := newSyncer(
		Config{DB: db}, mockAddrStore, nil, nil,
		&walletmock.Store{}, 0,
	)

	targets := []waddrmgr.AccountScope{
		{Scope: waddrmgr.KeyScopeBIP0084, Account: 0},
	}

	mockAddrStore.On("FetchScopedKeyManager",
		mock.Anything).Return(nil, errManager).Once()

	// Act: Attempt to retrieve scan data.
	horizons, addrs, unspent, err := s.DBGetScanData(t.Context(), targets)

	// Assert: Verify failure.
	require.Nil(t, horizons)
	require.Nil(t, addrs)
	require.Nil(t, unspent)
	require.ErrorIs(t, err, errManager)
}

// TestDBGetScanData_UTXOError verifies UTXO loading failure.
func TestDBGetScanData_UTXOError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where UTXO lookup fails during scan
	// data retrieval.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &bwmock.AddrStore{}
	mockTxStore := &bwmock.TxStore{}
	s := newSyncer(
		Config{DB: db}, mockAddrStore, mockTxStore, nil,
		&walletmock.Store{}, 0,
	)

	mockAddrStore.On("ForEachRelevantActiveAddress", mock.Anything,
		mock.AnythingOfType("func(address.Address) error"),
	).Return(nil).Once()
	mockTxStore.On("OutputsToWatch",
		mock.Anything).Return(([]wtxmgr.Credit)(nil), errUtxo).Once()

	// Act: Attempt to retrieve scan data.
	horizons, addrs, unspent, err := s.DBGetScanData(t.Context(), nil)

	// Assert: Verify failure.
	require.Nil(t, horizons)
	require.Nil(t, addrs)
	require.Nil(t, unspent)
	require.ErrorIs(t, err, errUtxo)
}

// TestPutAddrHorizons_Error verifies error propagation.
func TestPutAddrHorizons_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where key manager lookup fails
	// during horizon persistence.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &bwmock.AddrStore{}
	s := newSyncer(
		Config{DB: db}, mockAddrStore, nil, nil,
		&walletmock.Store{}, 0,
	)

	results := []scanResult{
		{
			BlockProcessResult: &BlockProcessResult{
				FoundHorizons: map[waddrmgr.BranchScope]uint32{
					{}: 1,
				},
			},
		},
	}

	mockAddrStore.On("FetchScopedKeyManager",
		mock.Anything).Return(nil, errManager).Once()

	// Act: Attempt to persist address horizons.
	_, err := s.putAddrHorizons(t.Context(), nil, results)

	// Assert: Verify failure.
	require.ErrorIs(t, err, errManager)
}

// TestPutAddrHorizonsEvictsOnPostExtensionReadError verifies that a failed
// branch state read after horizon extension evicts the in-memory derivation
// range before returning the error.
func TestPutAddrHorizonsEvictsOnPostExtensionReadError(t *testing.T) {
	t.Parallel()

	mockAddrStore := &bwmock.AddrStore{}
	s := newSyncer(
		Config{}, mockAddrStore, nil, nil, &walletmock.Store{}, 0,
	)

	bs := waddrmgr.BranchScope{
		Scope:   waddrmgr.KeyScopeBIP0084,
		Account: 0,
		Branch:  waddrmgr.ExternalBranch,
	}
	results := []scanResult{{
		BlockProcessResult: &BlockProcessResult{
			FoundHorizons: map[waddrmgr.BranchScope]uint32{
				bs: 10,
			},
		},
	}}

	scopedMgr := &bwmock.AccountStore{}
	mockAddrStore.On("FetchScopedKeyManager", bs.Scope).Return(
		scopedMgr, nil,
	).Once()
	scopedMgr.On("AccountProperties", mock.Anything, bs.Account).Return(
		&waddrmgr.AccountProperties{ExternalKeyCount: 4}, nil,
	).Once()
	scopedMgr.On("ExtendAddresses", mock.Anything, bs.Account, uint32(10),
		bs.Branch).Return(nil).Once()
	scopedMgr.On("AccountProperties", mock.Anything, bs.Account).Return(
		(*waddrmgr.AccountProperties)(nil), errManager,
	).Once()
	scopedMgr.On(
		"EvictDerivedAddresses", bs.Account, bs.Branch, uint32(4),
		uint32(waddrmgr.MaxAddressesPerAccount+1),
	).Once()

	rollback, err := s.putAddrHorizons(t.Context(), nil, results)
	require.ErrorIs(t, err, errManager)
	require.Empty(t, rollback)

	mockAddrStore.AssertExpectations(t)
	scopedMgr.AssertExpectations(t)
}

// TestDBGetScanData_AddressError verifies active address loading failure.
func TestDBGetScanData_AddressError(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where address iteration fails
	// during scan data retrieval.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &bwmock.AddrStore{}
	s := newSyncer(
		Config{DB: db}, mockAddrStore, nil, nil,
		&walletmock.Store{}, 0,
	)

	mockAddrStore.On("ForEachRelevantActiveAddress", mock.Anything,
		mock.Anything).Return(errAddr).Once()

	// Act: Attempt to retrieve scan data.
	horizons, addrs, unspent, err := s.DBGetScanData(t.Context(), nil)

	// Assert: Verify failure.
	require.Nil(t, horizons)
	require.Nil(t, addrs)
	require.Nil(t, unspent)
	require.ErrorIs(t, err, errAddr)
}

// TestDBPutTxns_InternalAddressAsChange verifies internal branch handling.
func TestDBPutTxns_InternalAddressAsChange(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations for a transaction match where the
	// address is internal, requiring it to be marked as change.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &bwmock.AddrStore{}
	mockTxStore := &bwmock.TxStore{}
	s := newSyncer(
		Config{DB: db}, mockAddrStore, mockTxStore, nil,
		&walletmock.Store{}, 0,
	)

	addr, err := address.NewAddressPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)

	matches := TxEntries{
		{
			Rec:     &wtxmgr.TxRecord{},
			Entries: []AddrEntry{{Address: addr}},
		},
	}

	maddr := &bwmock.ManagedAddress{}
	maddr.On("Internal").Return(true).Once()
	mockAddrStore.On("Address",
		mock.Anything, mock.Anything).Return(maddr, nil).Once()

	mgr := &bwmock.AccountStore{}
	mgr.On("Scope").Return(waddrmgr.KeyScopeBIP0084).Once()
	mockAddrStore.On("AddrAccount",
		mock.Anything, mock.Anything).Return(mgr, uint32(0), nil).Once()

	mockAddrStore.On("MarkUsed", mock.Anything,
		mock.Anything).Return(nil).Once()

	mockTxStore.On("InsertUnconfirmedTx", mock.Anything, mock.Anything,
		mock.Anything).Return(nil).Once()

	// Act: Persist transactions and filter branch scopes.
	err = s.DBPutTxns(t.Context(), matches, nil)

	// Assert: Verify that the output was correctly identified as change.
	require.NoError(t, err)
	require.True(t, matches[0].Entries[0].Credit.Change)
}

// TestDBPutTxns_AddressNotFound verifies ignoring not-found addresses.
func TestDBPutTxns_AddressNotFound(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where an address lookup returns a
	// "not found" error, which should lead to the entry being filtered out.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &bwmock.AddrStore{}
	mockTxStore := &bwmock.TxStore{}
	s := newSyncer(
		Config{DB: db}, mockAddrStore, mockTxStore, nil,
		&walletmock.Store{}, 0,
	)

	addr, err := address.NewAddressPubKeyHash(
		make([]byte, 20), &chainParams,
	)
	require.NoError(t, err)

	matches := TxEntries{
		{
			Rec:     &wtxmgr.TxRecord{},
			Entries: []AddrEntry{{Address: addr}},
		},
	}

	mockAddrStore.On("Address",
		mock.Anything, mock.Anything,
	).Return(nil, waddrmgr.ManagerError{
		ErrorCode: waddrmgr.ErrAddressNotFound}).Once()

	mockTxStore.On("InsertUnconfirmedTx", mock.Anything, mock.Anything,
		mock.Anything).Return(nil).Once()

	// Act: Persist transactions.
	err = s.DBPutTxns(t.Context(), matches, nil)

	// Assert: Verify that the unknown address entry was filtered.
	require.NoError(t, err)
	require.Empty(t, matches[0].Entries)
}

// TestDBPutRewind_Error verifies error propagation.
func TestDBPutRewind_Error(t *testing.T) {
	t.Parallel()

	// Arrange: Setup mock expectations where SetSyncedTo fails during
	// DBPutRewind.
	db, cleanup := setupTestDB(t)
	defer cleanup()

	mockAddrStore := &bwmock.AddrStore{}
	s := newSyncer(
		Config{DB: db}, mockAddrStore, nil, nil,
		&walletmock.Store{}, 0,
	)

	// The synced tip is snapshotted before the update and conditionally
	// restored after the update fails so the in-memory tip is not left at
	// the never-persisted fork point.
	preRewindTip := waddrmgr.BlockStamp{Height: 50, Hash: chainhash.Hash{0x09}}
	rewindTip := waddrmgr.BlockStamp{}

	mockAddrStore.On("SyncedTo").Return(preRewindTip).Once()
	mockAddrStore.On("SetSyncedTo",
		mock.Anything, mock.Anything).Return(errSetSync).Once()
	mockAddrStore.On(
		"RestoreSyncedToIfCurrent", preRewindTip, rewindTip,
	).Return(false).Once()

	// Act: Perform DBPutRewind.
	err := s.DBPutRewind(t.Context(), rewindTip)

	// Assert: Verify failure and that the pre-rewind tip was restored.
	require.ErrorIs(t, err, errSetSync)
	mockAddrStore.AssertExpectations(t)
}
