package kvdb

import (
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestCreateTxUnminedWithCreditSuccess verifies that kvdb.Store records an
// unmined transaction, label, credit, and address-used state through wtxmgr.
func TestCreateTxUnminedWithCreditSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)

	addr, script := newTestAddressScript(t)
	managedAddr := &bwmock.ManagedAddress{}
	managedAddr.On("Internal").Return(true).Maybe()
	managedAddr.On("Address").Return(addr).Maybe()
	managedAddr.On("AddrType").Return(waddrmgr.WitnessPubKey).Maybe()
	managedAddr.On("Imported").Return(false).Maybe()
	managedAddr.On("InternalAccount").Return(uint32(0)).Maybe()
	managedAddr.On("Compressed").Return(true).Maybe()
	managedAddr.On("AddrHash").Return([]byte(nil)).Maybe()
	managedAddr.On("Used", mock.Anything).Return(false).Maybe()

	addrStore := &bwmock.AddrStore{}
	addrStore.On("ChainParams").Return(&chaincfg.RegressionNetParams)
	addrStore.On("Address", mock.Anything, mock.Anything).
		Return(managedAddr, nil)
	addrStore.On("MarkUsed", mock.Anything, mock.Anything).Return(nil)
	store := NewStore(dbConn, txStore, addrStore)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{60},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 7_000, PkScript: script})

	label := "published"
	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: 0,
		Tx:       txMsg,
		Received: time.Unix(1710003000, 0),
		Status:   db.TxStatusPublished,
		Label:    label,
		Credits:  map[uint32]address.Address{0: addr},
	})
	require.NoError(t, err)

	txid := txMsg.TxHash()
	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		details, err := txStore.TxDetails(ns, &txid)
		require.NoError(t, err)
		require.NotNil(t, details)
		require.Equal(t, label, details.Label)
		require.Len(t, details.Credits, 1)
		require.Equal(t, uint32(0), details.Credits[0].Index)
		require.True(t, details.Credits[0].Change)

		return nil
	})
	require.NoError(t, err)
	addrStore.AssertCalled(t, "MarkUsed", mock.Anything, mock.Anything)
}

// TestCreateTxDuplicateReturnsStoreError verifies that duplicate unmined tx
// inserts are translated to db.ErrTxAlreadyExists.
func TestCreateTxDuplicateReturnsStoreError(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{61},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 8_000, PkScript: []byte{0x51}})

	params := db.CreateTxParams{
		WalletID: 0,
		Tx:       txMsg,
		Received: time.Unix(1710003100, 0),
		Status:   db.TxStatusPublished,
	}
	err := store.CreateTx(t.Context(), params)
	require.NoError(t, err)

	err = store.CreateTx(t.Context(), params)
	require.ErrorIs(t, err, db.ErrTxAlreadyExists)
}

// TestCreateTxCreditAddrMismatch verifies that crediting an output with an
// address that the output script does not pay to is rejected, so a caller
// cannot corrupt UTXO ownership by mislabeling a credit.
func TestCreateTxCreditAddrMismatch(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)

	// The output pays to one address, but the credit claims otherAddr,
	// which the output script does not contain.
	_, script := newTestAddressScript(t)
	otherAddr, _ := newTestAddressScript(t)

	addrStore := &bwmock.AddrStore{}
	addrStore.On("ChainParams").Return(&chaincfg.RegressionNetParams)
	store := NewStore(dbConn, txStore, addrStore)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{63},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 7_000, PkScript: script})

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: 0,
		Tx:       txMsg,
		Received: time.Unix(1710003200, 0),
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: otherAddr},
	})
	require.ErrorIs(t, err, db.ErrInvalidParam)
}

// TestCreateTxCreditBareMultisigMember verifies that crediting a bare-multisig
// output with one of its member pubkeys is accepted. Membership, not equality,
// is required so a wallet that owns one key in a multisig script still records
// the credit.
func TestCreateTxCreditBareMultisigMember(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)

	// Build a 1-of-2 bare-multisig script and credit it with the first
	// member's pubkey address.
	memberAddr, multiSigScript := newMultisigScript(t)

	managedAddr := &bwmock.ManagedAddress{}
	managedAddr.On("Internal").Return(false).Maybe()

	addrStore := &bwmock.AddrStore{}
	addrStore.On("ChainParams").Return(&chaincfg.RegressionNetParams)
	addrStore.On("Address", mock.Anything, mock.Anything).
		Return(managedAddr, nil)
	addrStore.On("MarkUsed", mock.Anything, mock.Anything).Return(nil)
	store := NewStore(dbConn, txStore, addrStore)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{65},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 5_000, PkScript: multiSigScript})

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: 0,
		Tx:       txMsg,
		Received: time.Unix(1710003400, 0),
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: memberAddr},
	})
	require.NoError(t, err)

	addrStore.AssertCalled(t, "MarkUsed", mock.Anything, mock.Anything)
}

// TestCreateTxCreditlessSucceeds verifies that a credit-less (sweep) tx is
// recorded even without the address-manager namespace, since the namespace is
// only consulted when recording credits.
func TestCreateTxCreditlessSucceeds(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	// Deliberately omit newAddrmgrNamespace: a credit-less tx must not
	// require the address-manager bucket.
	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{64},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 6_000, PkScript: []byte{0x51}})

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: 0,
		Tx:       txMsg,
		Received: time.Unix(1710003300, 0),
		Status:   db.TxStatusPublished,
	})
	require.NoError(t, err)

	txid := txMsg.TxHash()
	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		details, err := txStore.TxDetails(ns, &txid)
		require.NoError(t, err)
		require.NotNil(t, details)
		require.Empty(t, details.Credits)

		return nil
	})
	require.NoError(t, err)
}

// TestCreateTxCreditMissingAddrStore verifies credited transactions fail with a
// domain error instead of panicking when the address manager is unavailable.
func TestCreateTxCreditMissingAddrStore(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	addr, script := newTestAddressScript(t)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{74},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 6_000, PkScript: script})

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: 0,
		Tx:       txMsg,
		Received: time.Unix(1710003900, 0),
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: addr},
	})
	require.ErrorIs(t, err, errMissingAddrStore)
}

// TestCreateTxCreditNilFallback verifies that a nil credit address records the
// credit via the output's own script, matching the documented
// CreateTxParams.Credits fallback and the SQL backends. The nil path must not
// consult the address manager (no Address/MarkUsed lookup) and must not panic.
func TestCreateTxCreditNilFallback(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	// The addrmgr namespace is still required because the credit set is
	// non-empty, even though the nil credit itself never reads an address.
	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)

	_, script := newTestAddressScript(t)

	// A non-nil addrStore is required by CreateTx whenever there are
	// credits, but the nil-credit path must only read ChainParams and never
	// resolve or mark an address. Register no Address/MarkUsed expectations
	// so a regression that consults the address manager surfaces here.
	addrStore := &bwmock.AddrStore{}
	addrStore.On("ChainParams").Return(&chaincfg.RegressionNetParams)
	store := NewStore(dbConn, txStore, addrStore)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{66},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 4_000, PkScript: script})

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: 0,
		Tx:       txMsg,
		Received: time.Unix(1710003500, 0),
		Status:   db.TxStatusPublished,
		Credits:  map[uint32]address.Address{0: nil},
	})
	require.NoError(t, err)

	// The credit is recorded from the output index alone, with change
	// cleared because there is no resolved derivation branch.
	txid := txMsg.TxHash()
	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		details, err := txStore.TxDetails(ns, &txid)
		require.NoError(t, err)
		require.NotNil(t, details)
		require.Len(t, details.Credits, 1)
		require.Equal(t, uint32(0), details.Credits[0].Index)
		require.False(t, details.Credits[0].Change)

		return nil
	})
	require.NoError(t, err)

	// The address manager must not have been consulted for a nil credit.
	addrStore.AssertNotCalled(t, "Address", mock.Anything, mock.Anything)
	addrStore.AssertNotCalled(t, "MarkUsed", mock.Anything, mock.Anything)
}

// TestInvalidateUnminedTxSuccess verifies that kvdb.Store removes one unmined
// transaction through the legacy transaction store.
func TestInvalidateUnminedTxSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{62},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 9_000, PkScript: []byte{0x51}})
	rec, err := wtxmgr.NewTxRecordFromMsgTx(txMsg, time.Now())
	require.NoError(t, err)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		return txStore.InsertTx(ns, rec, nil)
	})
	require.NoError(t, err)

	err = store.InvalidateUnminedTx(
		t.Context(), db.InvalidateUnminedTxParams{
			WalletID: 0,
			Txid:     rec.Hash,
		},
	)
	require.NoError(t, err)

	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		details, err := txStore.TxDetails(ns, &rec.Hash)
		require.NoError(t, err)
		require.Nil(t, details)

		return nil
	})
	require.NoError(t, err)
}

// TestInvalidateUnminedTxRejectsConfirmed verifies that confirmed transactions
// cannot be invalidated through the unmined-only kvdb path.
func TestInvalidateUnminedTxRejectsConfirmed(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	rec := insertConfirmedTx(t, dbConn, txStore, 144)

	err := store.InvalidateUnminedTx(
		t.Context(), db.InvalidateUnminedTxParams{
			WalletID: 0,
			Txid:     rec.Hash,
		},
	)
	require.ErrorIs(t, err, db.ErrInvalidateTx)
}

// TestRollbackToBlockMovesConfirmedTxToUnmined verifies that kvdb.Store rolls
// back legacy transaction records from the requested height.
func TestRollbackToBlockMovesConfirmedTxToUnmined(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	rec := insertConfirmedTx(t, dbConn, txStore, 144)

	err := store.RollbackToBlock(t.Context(), 144)
	require.NoError(t, err)

	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		details, err := txStore.TxDetails(ns, &rec.Hash)
		require.NoError(t, err)
		require.NotNil(t, details)
		require.Equal(t, int32(-1), details.Block.Height)

		return nil
	})
	require.NoError(t, err)
}

// TestRollbackToBlockHeightZeroResetsSyncTip verifies that a rollback to height
// zero resets the wallet sync tip back to the stored start block instead of
// leaving a stale tip after the transaction block records are removed. There
// is no fork block at height-1 to rewind to, so the store must call
// SetSyncedTo(nil), matching the SQL backends, which clamp the synced height to
// NULL for a rollback to zero.
func TestRollbackToBlockHeightZeroResetsSyncTip(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)

	// The address manager reports a synced tip above genesis so the rollback
	// to zero has a stale tip to clear. SetSyncedTo(nil) is the reset to the
	// start block; the rollback must invoke it rather than skip the rewind.
	addrStore := &bwmock.AddrStore{}
	mockNoBirthdayBlock(addrStore)
	addrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{10},
		Height:    10,
		Timestamp: time.Unix(1710004100, 0),
	})
	addrStore.On("SetSyncedTo", mock.Anything, (*waddrmgr.BlockStamp)(nil)).
		Return(nil)
	store := NewStore(dbConn, txStore, addrStore)

	err := store.RollbackToBlock(t.Context(), 0)
	require.NoError(t, err)

	// The reset to the start block ran with a nil blockstamp, so no stale
	// live sync tip survives the rollback.
	addrStore.AssertCalled(
		t, "SetSyncedTo", mock.Anything, (*waddrmgr.BlockStamp)(nil),
	)
}

// TestRollbackToBlockRewindsSyncTipWithForkTimestamp verifies non-zero
// rollbacks use the surviving fork block's timestamp when wtxmgr has metadata
// for that block.
func TestRollbackToBlockRewindsSyncTipWithForkTimestamp(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)

	forkHeight := int32(9)
	forkHash := chainhash.Hash{31, byte(forkHeight)}
	forkTimestamp := time.Unix(1710002000, 0)

	insertConfirmedTx(t, dbConn, txStore, forkHeight)

	currentTimestamp := time.Unix(1710004100, 0)
	addrStore := &bwmock.AddrStore{}
	mockNoBirthdayBlock(addrStore)
	addrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{10},
		Height:    10,
		Timestamp: currentTimestamp,
	})
	addrStore.On("BlockHash", mock.Anything, int32(9)).Return(
		&forkHash, nil,
	)
	addrStore.On(
		"SetSyncedTo", mock.Anything,
		mock.MatchedBy(func(bs *waddrmgr.BlockStamp) bool {
			return bs != nil && bs.Height == 9 &&
				bs.Hash == forkHash &&
				bs.Timestamp.Equal(forkTimestamp)
		}),
	).Return(nil)
	store := NewStore(dbConn, txStore, addrStore)

	err := store.RollbackToBlock(t.Context(), 10)
	require.NoError(t, err)
}

// TestRollbackToBlockRewindsSyncTipToSparseFork verifies that rollback finds
// the greatest retained block below the rollback boundary for sync metadata
// without lowering the transaction rollback boundary.
func TestRollbackToBlockRewindsSyncTipToSparseFork(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)

	forkHeight := int32(7)
	forkHash := chainhash.Hash{31, byte(forkHeight)}
	forkTimestamp := time.Unix(1710002000, 0)

	insertConfirmedTx(t, dbConn, txStore, forkHeight)
	retainedRec := insertConfirmedTxWithSeed(t, dbConn, txStore, 8, 80)
	rolledBackRec := insertConfirmedTxWithSeed(t, dbConn, txStore, 10, 100)

	currentTimestamp := time.Unix(1710004100, 0)
	addrStore := &bwmock.AddrStore{}
	mockNoBirthdayBlock(addrStore)
	t.Cleanup(func() {
		addrStore.AssertExpectations(t)
	})

	addrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{10},
		Height:    10,
		Timestamp: currentTimestamp,
	}).Once()

	missingHash := &chainhash.Hash{}
	missingErr := waddrmgr.ManagerError{
		ErrorCode:   waddrmgr.ErrBlockNotFound,
		Description: "block not found",
	}
	addrStore.On("BlockHash", mock.Anything, int32(9)).Return(
		missingHash, missingErr,
	).Once()
	addrStore.On("BlockHash", mock.Anything, int32(8)).Return(
		missingHash, missingErr,
	).Once()
	addrStore.On("BlockHash", mock.Anything, forkHeight).Return(
		&forkHash, nil,
	).Once()
	addrStore.On(
		"SetSyncedTo", mock.Anything,
		mock.MatchedBy(func(bs *waddrmgr.BlockStamp) bool {
			return bs != nil && bs.Height == forkHeight &&
				bs.Hash == forkHash &&
				bs.Timestamp.Equal(forkTimestamp)
		}),
	).Return(nil).Once()
	store := NewStore(dbConn, txStore, addrStore)

	err := store.RollbackToBlock(t.Context(), 10)
	require.NoError(t, err)

	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		details, err := txStore.TxDetails(ns, &retainedRec.Hash)
		require.NoError(t, err)
		require.NotNil(t, details)
		require.Equal(t, int32(8), details.Block.Height)

		details, err = txStore.TxDetails(ns, &rolledBackRec.Hash)
		require.NoError(t, err)
		require.NotNil(t, details)
		require.Equal(t, int32(-1), details.Block.Height)

		return nil
	})
	require.NoError(t, err)
}

// TestRollbackToBlockRewindsSyncTipWithoutForkTimestamp verifies that a sparse
// fork block with no tx-store metadata does not inherit the disconnected tip's
// timestamp.
func TestRollbackToBlockRewindsSyncTipWithoutForkTimestamp(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)

	forkHeight := int32(9)
	forkHash := chainhash.Hash{90}
	currentTimestamp := time.Unix(1710004100, 0)
	addrStore := &bwmock.AddrStore{}
	mockNoBirthdayBlock(addrStore)
	addrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{10},
		Height:    10,
		Timestamp: currentTimestamp,
	})
	addrStore.On("BlockHash", mock.Anything, forkHeight).Return(
		&forkHash, nil,
	)
	addrStore.On(
		"SetSyncedTo", mock.Anything,
		mock.MatchedBy(func(bs *waddrmgr.BlockStamp) bool {
			return bs != nil && bs.Height == forkHeight &&
				bs.Hash == forkHash &&
				bs.Timestamp.Equal(time.Unix(0, 0).UTC())
		}),
	).Return(nil)
	store := NewStore(dbConn, txStore, addrStore)

	err := store.RollbackToBlock(t.Context(), 10)
	require.NoError(t, err)
}

// TestRollbackToBlockRewindsBirthdayBlock verifies that rollback rewrites a
// birthday block at the disconnected height to the retained fork block.
func TestRollbackToBlockRewindsBirthdayBlock(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	t.Cleanup(addrStore.Close)
	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, addrStore)

	forkHeight := int32(9)
	forkHash := chainhash.Hash{31, byte(forkHeight)}
	forkTimestamp := time.Unix(1710002000, 0)

	insertConfirmedTx(t, dbConn, txStore, forkHeight)

	currentTip := waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{10},
		Height:    10,
		Timestamp: time.Unix(1710004100, 0),
	}
	birthdayBlock := waddrmgr.BlockStamp{
		Hash:      currentTip.Hash,
		Height:    currentTip.Height,
		Timestamp: currentTip.Timestamp,
	}
	writeSyncedTo(t, dbConn, addrStore, waddrmgr.BlockStamp{
		Hash:      forkHash,
		Height:    forkHeight,
		Timestamp: forkTimestamp,
	})
	writeSyncedTo(t, dbConn, addrStore, currentTip)
	writeBirthdayBlock(t, dbConn, addrStore, birthdayBlock, true)

	err := store.RollbackToBlock(t.Context(), 10)
	require.NoError(t, err)

	rewoundBlock, verified := readBirthdayBlock(t, dbConn, addrStore)
	require.True(t, verified)
	require.Equal(t, forkHeight, rewoundBlock.Height)
	require.Equal(t, forkHash, rewoundBlock.Hash)
	require.True(t, rewoundBlock.Timestamp.Equal(forkTimestamp))
}

// TestRollbackToBlockHeightZeroClearsBirthdayBlock verifies that a full
// rollback clears a birthday block that would otherwise reference a
// disconnected block.
func TestRollbackToBlockHeightZeroClearsBirthdayBlock(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	t.Cleanup(addrStore.Close)
	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, addrStore)

	birthdayBlock := waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{10},
		Height:    10,
		Timestamp: time.Unix(1710004100, 0),
	}
	writeSyncedTo(t, dbConn, addrStore, birthdayBlock)
	writeBirthdayBlock(t, dbConn, addrStore, birthdayBlock, true)

	err := store.RollbackToBlock(t.Context(), 0)
	require.NoError(t, err)

	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgr.NamespaceKey)
		require.NotNil(t, addrmgrNs)

		_, _, err := addrStore.BirthdayBlock(addrmgrNs)
		require.True(t, waddrmgr.IsError(
			err, waddrmgr.ErrBirthdayBlockNotSet,
		))

		return nil
	})
	require.NoError(t, err)
}

// TestRollbackToBlockRestoresBirthdayBlockOnCommitFailure verifies that a
// failed rollback commit leaves the previous birthday block visible.
func TestRollbackToBlockRestoresBirthdayBlockOnCommitFailure(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	t.Cleanup(addrStore.Close)
	txStore := newTxStore(t, dbConn)

	currentTip := waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{10},
		Height:    10,
		Timestamp: time.Unix(1710004100, 0),
	}
	birthdayBlock := currentTip
	// Store the birthday block after the synced tip so the sparse history has
	// no predecessor hash for height 9. The failed walletdb transaction should
	// roll this DB-only state back without a second write transaction.
	writeSyncedTo(t, dbConn, addrStore, currentTip)
	writeBirthdayBlock(t, dbConn, addrStore, birthdayBlock, true)

	failDB := &commitFailDB{DB: dbConn, failNext: true}
	store := NewStore(failDB, txStore, addrStore)

	err := store.RollbackToBlock(t.Context(), 10)
	require.ErrorIs(t, err, errInjectedCommit)

	restoredBlock, verified := readBirthdayBlock(t, dbConn, addrStore)
	require.True(t, verified)
	require.Equal(t, birthdayBlock.Height, restoredBlock.Height)
	require.Equal(t, birthdayBlock.Hash, restoredBlock.Hash)
	require.True(t, restoredBlock.Timestamp.Equal(birthdayBlock.Timestamp))

	restoredTip := addrStore.SyncedTo()
	require.Equal(t, currentTip.Height, restoredTip.Height)
	require.Equal(t, currentTip.Hash, restoredTip.Hash)
	require.True(t, restoredTip.Timestamp.Equal(currentTip.Timestamp))
}

// TestRollbackToBlockRestoresSyncTipOnCommitFailure verifies that a failed
// rollback commit restores the live address-manager tip that SetSyncedTo
// changed before walletdb rejected the transaction.
func TestRollbackToBlockRestoresSyncTipOnCommitFailure(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)

	forkHeight := int32(9)
	forkHash := chainhash.Hash{31, byte(forkHeight)}
	forkTimestamp := time.Unix(1710002000, 0)

	insertConfirmedTx(t, dbConn, txStore, forkHeight)
	rolledBackRec := insertConfirmedTxWithSeed(t, dbConn, txStore, 10, 90)

	currentTip := waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{10},
		Height:    10,
		Timestamp: time.Unix(1710004100, 0),
	}
	addrStore := &bwmock.AddrStore{}
	mockNoBirthdayBlock(addrStore)
	t.Cleanup(func() {
		addrStore.AssertExpectations(t)
	})

	addrStore.On("SyncedTo").Return(currentTip).Once()
	addrStore.On("BlockHash", mock.Anything, forkHeight).Return(
		&forkHash, nil,
	).Once()
	addrStore.On(
		"SetSyncedTo", mock.Anything,
		mock.MatchedBy(func(bs *waddrmgr.BlockStamp) bool {
			return bs != nil && bs.Height == forkHeight &&
				bs.Hash == forkHash &&
				bs.Timestamp.Equal(forkTimestamp)
		}),
	).Return(nil).Once()
	addrStore.On("RestoreSyncedToIfCurrent", currentTip,
		waddrmgr.BlockStamp{
			Hash:      forkHash,
			Height:    forkHeight,
			Timestamp: forkTimestamp,
		},
	).Return(true).Once()

	failDB := &commitFailDB{DB: dbConn, failNext: true}
	store := NewStore(failDB, txStore, addrStore)

	err := store.RollbackToBlock(t.Context(), 10)
	require.ErrorIs(t, err, errInjectedCommit)

	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		details, err := txStore.TxDetails(ns, &rolledBackRec.Hash)
		require.NoError(t, err)
		require.NotNil(t, details)
		require.Equal(t, int32(10), details.Block.Height)

		return nil
	})
	require.NoError(t, err)
}

// TestRollbackToBlockRestoresResetSyncTipOnCommitFailure verifies that a failed
// height-zero rollback restores the live tip after SetSyncedTo(nil) resets it.
func TestRollbackToBlockRestoresResetSyncTipOnCommitFailure(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)

	currentTip := waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{10},
		Height:    10,
		Timestamp: time.Unix(1710004100, 0),
	}
	startTip := waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{1},
		Height:    1,
		Timestamp: time.Unix(1710000000, 0),
	}
	addrStore := &bwmock.AddrStore{}
	mockNoBirthdayBlock(addrStore)
	t.Cleanup(func() {
		addrStore.AssertExpectations(t)
	})

	addrStore.On("SyncedTo").Return(currentTip).Once()
	addrStore.On("SetSyncedTo", mock.Anything,
		(*waddrmgr.BlockStamp)(nil)).Return(nil).Once()
	addrStore.On("SyncedTo").Return(startTip).Once()
	addrStore.On("RestoreSyncedToIfCurrent", currentTip,
		startTip).Return(true).Once()

	failDB := &commitFailDB{DB: dbConn, failNext: true}
	store := NewStore(failDB, txStore, addrStore)

	err := store.RollbackToBlock(t.Context(), 0)
	require.ErrorIs(t, err, errInjectedCommit)
}

// TestUpdateTxLabelOnlySuccess verifies that kvdb.Store can apply a label-only
// UpdateTx patch through the legacy label path.
func TestUpdateTxLabelOnlySuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{10},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})
	rec, err := wtxmgr.NewTxRecordFromMsgTx(txMsg, time.Now())
	require.NoError(t, err)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		return txStore.InsertTx(ns, rec, nil)
	})
	require.NoError(t, err)

	label := "new label"
	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: 0,
		Txid:     rec.Hash,
		Label:    &label,
	})
	require.NoError(t, err)

	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		details, err := txStore.TxDetails(ns, &rec.Hash)
		require.NoError(t, err)
		require.NotNil(t, details)
		require.Equal(t, label, details.Label)

		return nil
	})
	require.NoError(t, err)
}

// TestUpdateTxLabelOnlyNotFound verifies not-found propagation for label-only
// UpdateTx patches.
func TestUpdateTxLabelOnlyNotFound(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	label := "missing"
	err := store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: 0,
		Txid:     chainhash.Hash{99},
		Label:    &label,
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestUpdateTxRejectsUnsupportedPatches verifies that unsupported kvdb update
// paths fail explicitly.
func TestUpdateTxRejectsUnsupportedPatches(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	state := &db.UpdateTxState{Status: db.TxStatusPublished}
	err := store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: 0,
		Txid:     chainhash.Hash{1},
		State:    state,
	})
	require.ErrorIs(t, err, errNotImplemented)
}

// TestUpdateTxEmptyLabelPreservesLegacyError verifies that kvdb keeps the
// legacy empty-label rejection instead of reaching into private buckets.
func TestUpdateTxEmptyLabelPreservesLegacyError(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{11},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})
	rec, err := wtxmgr.NewTxRecordFromMsgTx(txMsg, time.Now())
	require.NoError(t, err)

	label := "old label"
	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		err := txStore.InsertTx(ns, rec, nil)
		if err != nil {
			return err
		}

		return txStore.PutTxLabel(ns, rec.Hash, label)
	})
	require.NoError(t, err)

	empty := ""
	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: 0,
		Txid:     rec.Hash,
		Label:    &empty,
	})
	require.ErrorContains(t, err, "empty transaction label not allowed")

	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		details, err := txStore.TxDetails(ns, &rec.Hash)
		require.NoError(t, err)
		require.NotNil(t, details)
		require.Equal(t, label, details.Label)

		return nil
	})
	require.NoError(t, err)
}

// TestUpdateTxLongLabelPreservesLegacyError verifies that label length
// validation remains owned by the legacy kvdb path.
func TestUpdateTxLongLabelPreservesLegacyError(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{12},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x51}})
	rec, err := wtxmgr.NewTxRecordFromMsgTx(txMsg, time.Now())
	require.NoError(t, err)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		return txStore.InsertTx(ns, rec, nil)
	})
	require.NoError(t, err)

	longLabel := make([]byte, wtxmgr.TxLabelLimit+1)
	label := string(longLabel)
	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: 0,
		Txid:     rec.Hash,
		Label:    &label,
	})
	require.ErrorIs(t, err, wtxmgr.ErrLabelTooLong)
}

// TestGetTxSummarySuccess verifies that kvdb.Store adapts legacy tx details to
// the db-native summary model.
func TestGetTxSummarySuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{20},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 2_000, PkScript: []byte{0x51}})
	rec, err := wtxmgr.NewTxRecordFromMsgTx(txMsg, time.Now())
	require.NoError(t, err)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		return txStore.InsertTx(ns, rec, nil)
	})
	require.NoError(t, err)

	info, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: 0,
		Txid:     rec.Hash,
	})
	require.NoError(t, err)
	require.Equal(t, rec.Hash, info.Hash)
	require.Equal(t, rec.SerializedTx, info.SerializedTx)
	require.Equal(t, rec.Received.UTC().Unix(), info.Received.Unix())
	require.Nil(t, info.Block)
	require.Equal(t, db.TxStatusPublished, info.Status)
}

// TestGetTxDetailSuccess verifies that kvdb.Store adapts legacy tx details to
// the db-native detail model.
func TestGetTxDetailSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	funding, spend := insertSpendChain(t, dbConn, txStore)

	detail, err := store.GetTxDetail(t.Context(), db.GetTxDetailQuery{
		WalletID: 0,
		Txid:     spend.Hash,
	})
	require.NoError(t, err)
	require.Equal(t, spend.Hash, detail.Hash)
	require.Nil(t, detail.Block)
	require.Len(t, detail.OwnedInputs, 1)
	require.Len(t, detail.OwnedOutputs, 2)
	require.Equal(t, funding.Hash, spend.MsgTx.TxIn[0].PreviousOutPoint.Hash)
	require.Equal(t, uint32(0), detail.OwnedInputs[0].Index)
	require.Equal(t, btcutil.Amount(2_000), detail.OwnedInputs[0].Amount)
	require.Equal(t, uint32(0), detail.OwnedOutputs[0].Index)
	require.Equal(t, btcutil.Amount(900), detail.OwnedOutputs[0].Amount)
	require.Equal(t, uint32(1), detail.OwnedOutputs[1].Index)
	require.Equal(t, btcutil.Amount(800), detail.OwnedOutputs[1].Amount)
}

// TestGetTxSummaryNotFound verifies that kvdb.Store reports missing
// transactions through db.ErrTxNotFound.
func TestGetTxSummaryNotFound(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	_, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: 0,
		Txid:     chainhash.Hash{42},
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
}

// TestListTxnsSummaryUnminedOnlySuccess verifies that kvdb.Store can list the
// legacy unmined set through the db-native summary API.
func TestListTxnsSummaryUnminedOnlySuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{21},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 2_500, PkScript: []byte{0x51}})
	rec, err := wtxmgr.NewTxRecordFromMsgTx(txMsg, time.Now())
	require.NoError(t, err)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		return txStore.InsertTx(ns, rec, nil)
	})
	require.NoError(t, err)

	infos, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    0,
		UnminedOnly: true,
	})
	require.NoError(t, err)
	require.Len(t, infos, 1)
	require.Equal(t, rec.Hash, infos[0].Hash)
	require.Nil(t, infos[0].Block)
	require.Equal(t, db.TxStatusPublished, infos[0].Status)
}

// TestListTxnsSummaryConfirmedRangeSuccess verifies that kvdb.Store can adapt
// the legacy confirmed range iterator to the db-native summary API.
func TestListTxnsSummaryConfirmedRangeSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	rec := insertConfirmedTx(t, dbConn, txStore, 144)

	infos, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    0,
		StartHeight: 144,
		EndHeight:   144,
	})
	require.NoError(t, err)
	require.Len(t, infos, 1)
	require.Equal(t, rec.Hash, infos[0].Hash)
	require.NotNil(t, infos[0].Block)
	require.Equal(t, uint32(144), infos[0].Block.Height)
	require.Equal(t, db.TxStatusPublished, infos[0].Status)
}

// TestListTxnsSummaryBoundedRange verifies that kvdb summary reads preserve the
// confirmed height bounds.
func TestListTxnsSummaryBoundedRange(t *testing.T) {
	t.Parallel()

	// Arrange: Insert confirmed txns inside and after the requested height
	// range.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	insideLow := insertConfirmedTxWithSeed(t, dbConn, txStore, 144, 1)
	insideHigh := insertConfirmedTxWithSeed(t, dbConn, txStore, 145, 2)
	outsideHigh := insertConfirmedTxWithSeed(t, dbConn, txStore, 146, 3)

	// Act: List the bounded confirmed range.
	infos, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    0,
		StartHeight: 144,
		EndHeight:   145,
	})

	// Assert: The out-of-range confirmed tx is excluded.
	require.NoError(t, err)
	require.NotContains(t, txHashes(infos), outsideHigh.Hash)
	require.Equal(t, []chainhash.Hash{
		insideLow.Hash, insideHigh.Hash,
	}, txHashes(infos))
}

// TestListTxDetailsCopiesMsgTx verifies that each returned detail keeps its own
// stable MsgTx pointer even when RangeTransactions reuses the callback slice.
func TestListTxDetailsCopiesMsgTx(t *testing.T) {
	t.Parallel()

	// Arrange: Insert two confirmed transactions in different blocks so the
	// range callback has to cross block boundaries and can reuse its buffer.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	firstTx := &wire.MsgTx{Version: 1}
	firstTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{40},
	}})
	firstTx.AddTxOut(&wire.TxOut{Value: 3_000, PkScript: []byte{0x51}})
	firstRec, err := wtxmgr.NewTxRecordFromMsgTx(
		firstTx, time.Unix(1710002100, 0),
	)
	require.NoError(t, err)

	secondTx := &wire.MsgTx{Version: 1}
	secondTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{41},
	}})
	secondTx.AddTxOut(&wire.TxOut{Value: 4_000, PkScript: []byte{0x52}})
	secondRec, err := wtxmgr.NewTxRecordFromMsgTx(
		secondTx, time.Unix(1710002200, 0),
	)
	require.NoError(t, err)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		err := txStore.InsertTx(ns, firstRec, &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{
				Height: 144,
				Hash:   chainhash.Hash{50},
			},
			Time: time.Unix(1710002300, 0),
		})
		require.NoError(t, err)

		return txStore.InsertTx(ns, secondRec, &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{
				Height: 145,
				Hash:   chainhash.Hash{51},
			},
			Time: time.Unix(1710002400, 0),
		})
	})
	require.NoError(t, err)

	// Act: Load the detailed range through the kvdb adapter.
	details, err := store.ListTxDetails(t.Context(), db.ListTxDetailsQuery{
		WalletID:    0,
		StartHeight: 144,
		EndHeight:   145,
	})

	// Assert: Each returned detail keeps the MsgTx that matches its own hash.
	require.NoError(t, err)
	require.Len(t, details, 2)

	msgHashByDetailHash := make(map[chainhash.Hash]chainhash.Hash, len(details))
	for _, detail := range details {
		require.NotNil(t, detail.MsgTx)
		msgHashByDetailHash[detail.Hash] = detail.MsgTx.TxHash()
	}

	require.Equal(t, firstRec.Hash, msgHashByDetailHash[firstRec.Hash])
	require.Equal(t, secondRec.Hash, msgHashByDetailHash[secondRec.Hash])
}

var errInjectedCommit = errors.New("injected commit failure")

// commitFailDB wraps a walletdb.DB and makes its next Update fail after the
// write closure succeeds, simulating a commit failure without persisting the
// transaction.
type commitFailDB struct {
	walletdb.DB

	failNext bool
}

// Update executes a write transaction and injects one commit failure when
// failNext is set.
func (db *commitFailDB) Update(f func(walletdb.ReadWriteTx) error,
	reset func()) error {

	if reset != nil {
		reset()
	}

	tx, err := db.DB.BeginReadWriteTx()
	if err != nil {
		return err
	}

	err = f(tx)
	if err != nil {
		_ = tx.Rollback()

		return err
	}

	if db.failNext {
		db.failNext = false
		_ = tx.Rollback()

		return errInjectedCommit
	}

	return tx.Commit()
}

// birthdayBlockNotSetErr returns the legacy manager error used when no birthday
// block is stored.
func birthdayBlockNotSetErr() error {
	return waddrmgr.ManagerError{
		ErrorCode:   waddrmgr.ErrBirthdayBlockNotSet,
		Description: "birthday block not set",
	}
}

// mockNoBirthdayBlock makes a mock address store report that no birthday block
// is stored.
func mockNoBirthdayBlock(addrStore *bwmock.AddrStore) {
	addrStore.On("BirthdayBlock", mock.Anything).Return(
		waddrmgr.BlockStamp{}, false, birthdayBlockNotSetErr(),
	).Maybe()
}

// writeSyncedTo persists a sync tip through the real address manager.
func writeSyncedTo(t *testing.T, dbConn walletdb.DB,
	mgr *waddrmgr.Manager, tip waddrmgr.BlockStamp) {

	t.Helper()

	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		require.NotNil(t, addrmgrNs)

		return mgr.SetSyncedTo(addrmgrNs, &tip)
	})
	require.NoError(t, err)
}

// writeBirthdayBlock persists a verified or unverified birthday block through
// the real address manager.
func writeBirthdayBlock(t *testing.T, dbConn walletdb.DB,
	mgr *waddrmgr.Manager, block waddrmgr.BlockStamp, verified bool) {

	t.Helper()

	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		require.NotNil(t, addrmgrNs)

		return mgr.SetBirthdayBlock(addrmgrNs, block, verified)
	})
	require.NoError(t, err)
}

// readBirthdayBlock loads the current birthday block from the real address
// manager.
func readBirthdayBlock(t *testing.T, dbConn walletdb.DB,
	mgr *waddrmgr.Manager) (waddrmgr.BlockStamp, bool) {

	t.Helper()

	var (
		block    waddrmgr.BlockStamp
		verified bool
	)

	err := walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgr.NamespaceKey)
		require.NotNil(t, addrmgrNs)

		var err error

		block, verified, err = mgr.BirthdayBlock(addrmgrNs)

		return err
	})
	require.NoError(t, err)

	return block, verified
}

// insertConfirmedTx inserts one mined transaction into the legacy tx store so
// kvdb summary reads can exercise confirmed block metadata.
func insertConfirmedTx(t *testing.T, dbConn walletdb.DB,
	txStore *wtxmgr.Store, height int32) *wtxmgr.TxRecord {

	t.Helper()

	return insertConfirmedTxWithSeed(t, dbConn, txStore, height, byte(height))
}

// insertConfirmedTxWithSeed inserts one mined transaction with fixture-specific
// bytes into the legacy tx store.
func insertConfirmedTxWithSeed(t *testing.T, dbConn walletdb.DB,
	txStore *wtxmgr.Store, height int32, seed byte) *wtxmgr.TxRecord {

	t.Helper()

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{seed},
	}})
	txMsg.AddTxOut(&wire.TxOut{
		Value:    3_000 + int64(seed),
		PkScript: []byte{0x51, seed},
	})
	rec, err := wtxmgr.NewTxRecordFromMsgTx(txMsg, time.Now())
	require.NoError(t, err)

	block := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Height: height,
			Hash:   chainhash.Hash{31, seed},
		},
		Time: time.Unix(1710002000, 0),
	}

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		return txStore.InsertTx(ns, rec, block)
	})
	require.NoError(t, err)

	return rec
}

// txHashes returns transaction hashes in result order.
func txHashes(infos []db.TxInfo) []chainhash.Hash {
	hashes := make([]chainhash.Hash, 0, len(infos))
	for _, info := range infos {
		hashes = append(hashes, info.Hash)
	}

	return hashes
}

// insertSpendChain inserts one funding tx and one spending tx into the legacy
// tx store so kvdb detail reads can exercise both owned inputs and outputs.
func insertSpendChain(t *testing.T, dbConn walletdb.DB,
	txStore *wtxmgr.Store) (*wtxmgr.TxRecord, *wtxmgr.TxRecord) {

	t.Helper()

	fundingTx := &wire.MsgTx{Version: 1}
	fundingTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{20},
	}})
	fundingTx.AddTxOut(&wire.TxOut{Value: 2_000, PkScript: []byte{0x51}})
	fundingRec, err := wtxmgr.NewTxRecordFromMsgTx(fundingTx, time.Now())
	require.NoError(t, err)

	spendTx := &wire.MsgTx{Version: 1}
	spendTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash:  fundingRec.Hash,
		Index: 0,
	}})
	spendTx.AddTxOut(&wire.TxOut{Value: 900, PkScript: []byte{0x51}})
	spendTx.AddTxOut(&wire.TxOut{Value: 800, PkScript: []byte{0x51}})
	spendRec, err := wtxmgr.NewTxRecordFromMsgTx(spendTx, time.Now())
	require.NoError(t, err)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		err = txStore.InsertTx(ns, fundingRec, nil)
		require.NoError(t, err)

		err = txStore.AddCredit(ns, fundingRec, nil, 0, false)
		require.NoError(t, err)

		err = txStore.InsertTx(ns, spendRec, nil)
		require.NoError(t, err)

		err = txStore.AddCredit(ns, spendRec, nil, 0, false)
		require.NoError(t, err)

		err = txStore.AddCredit(ns, spendRec, nil, 1, false)
		require.NoError(t, err)

		return nil
	})
	require.NoError(t, err)

	return fundingRec, spendRec
}

// newMultisigScript builds a 1-of-2 bare-multisig output script and returns the
// first member's pubkey address along with the script.
func newMultisigScript(t *testing.T) (address.Address, []byte) {
	t.Helper()

	members, script := newMultisigScriptMembers(t)

	return members[0], script
}

// newMultisigScriptMembers builds a 1-of-2 bare-multisig output script and
// returns both member pubkey addresses along with the script.
func newMultisigScriptMembers(t *testing.T) ([]address.Address, []byte) {
	t.Helper()

	firstKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	secondKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	firstAddr, err := address.NewAddressPubKey(
		firstKey.PubKey().SerializeCompressed(),
		&chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)
	secondAddr, err := address.NewAddressPubKey(
		secondKey.PubKey().SerializeCompressed(),
		&chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	builder := txscript.NewScriptBuilder()
	builder.AddInt64(1)
	builder.AddData(firstKey.PubKey().SerializeCompressed())
	builder.AddData(secondKey.PubKey().SerializeCompressed())
	builder.AddInt64(2)
	builder.AddOp(txscript.OP_CHECKMULTISIG)

	script, err := builder.Script()
	require.NoError(t, err)

	return []address.Address{firstAddr, secondAddr}, script
}

// matchAddress returns a matcher for an address with the same encoded form.
func matchAddress(addr address.Address) interface{} {
	return mock.MatchedBy(func(got address.Address) bool {
		return got.EncodeAddress() == addr.EncodeAddress()
	})
}
