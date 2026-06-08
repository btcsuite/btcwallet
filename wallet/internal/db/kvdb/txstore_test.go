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

// failingRollbackTxStore injects a Rollback failure while delegating all other
// transaction-store methods to the embedded implementation.
type failingRollbackTxStore struct {
	wtxmgr.TxStore

	err error
}

// Rollback injects the configured rollback failure.
func (f failingRollbackTxStore) Rollback(walletdb.ReadWriteBucket,
	int32) error {

	return f.err
}

// succeedThenFailSyncedAddrStore writes the synced-to block through the real
// manager, then reports an induced failure so the walletdb transaction rolls
// back after the manager's in-memory tip has already advanced.
type succeedThenFailSyncedAddrStore struct {
	*waddrmgr.Manager

	beforeRestore func()
}

// SetSyncedTo writes the synced-to block before injecting the configured
// post-write failure.
func (s *succeedThenFailSyncedAddrStore) SetSyncedTo(
	ns walletdb.ReadWriteBucket, bs *waddrmgr.BlockStamp) error {

	err := s.Manager.SetSyncedTo(ns, bs)
	if err != nil {
		return err
	}

	return errInducedFailure
}

// RestoreSyncedToIfCurrent runs an optional hook before delegating the
// conditional restore to the wrapped manager.
func (s *succeedThenFailSyncedAddrStore) RestoreSyncedToIfCurrent(
	previous, current waddrmgr.BlockStamp) bool {

	if s.beforeRestore != nil {
		beforeRestore := s.beforeRestore
		s.beforeRestore = nil

		beforeRestore()
	}

	return s.Manager.RestoreSyncedToIfCurrent(previous, current)
}

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

// TestCreateTxPersistsPendingStatus verifies kvdb round-trips pending
// transactions through its status side bucket.
func TestCreateTxPersistsPendingStatus(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{77},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 8_000, PkScript: []byte{0x51}})

	err := store.CreateTx(t.Context(), db.CreateTxParams{
		WalletID: 0,
		Tx:       txMsg,
		Received: time.Unix(1710004300, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	txid := txMsg.TxHash()
	info, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: 0,
		Txid:     txid,
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPending, info.Status)

	detail, err := store.GetTxDetail(t.Context(), db.GetTxDetailQuery{
		WalletID: 0,
		Txid:     txid,
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPending, detail.Status)

	infos, err := store.ListTxns(t.Context(), db.ListTxnsQuery{
		WalletID:    0,
		UnminedOnly: true,
	})
	require.NoError(t, err)
	require.Len(t, infos, 1)
	require.Equal(t, db.TxStatusPending, infos[0].Status)

	details, err := store.ListTxDetails(
		t.Context(), db.ListTxDetailsQuery{
			WalletID:    0,
			StartHeight: -1,
			EndHeight:   -1,
		},
	)
	require.NoError(t, err)
	require.Len(t, details, 1)
	require.Equal(t, db.TxStatusPending, details[0].Status)
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

// TestRollbackToBlockFailureKeepsSyncTip verifies a transaction rollback
// failure does not leave the live address-manager sync tip rewound.
func TestRollbackToBlockFailureKeepsSyncTip(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	t.Cleanup(addrStore.Close)
	txStore := newTxStore(t, dbConn)

	forkTip := waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{9},
		Height:    9,
		Timestamp: time.Unix(1710004100, 0),
	}
	currentTip := waddrmgr.BlockStamp{
		Hash:      chainhash.Hash{10},
		Height:    10,
		Timestamp: time.Unix(1710004700, 0),
	}
	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		require.NotNil(t, addrmgrNs)

		err := addrStore.SetSyncedTo(addrmgrNs, &forkTip)
		if err != nil {
			return err
		}

		return addrStore.SetSyncedTo(addrmgrNs, &currentTip)
	})
	require.NoError(t, err)

	store := NewStore(
		dbConn, failingRollbackTxStore{
			TxStore: txStore,
			err:     errInducedFailure,
		}, addrStore,
	)
	err = store.RollbackToBlock(t.Context(), 10)
	require.ErrorIs(t, err, errInducedFailure)
	require.Equal(t, currentTip, addrStore.SyncedTo())
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

// TestUpdateTxEmptyLabelClearsLabel verifies that kvdb honors the db.Store
// contract that an empty label clears any prior label.
func TestUpdateTxEmptyLabelClearsLabel(t *testing.T) {
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
	require.NoError(t, err)

	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		details, err := txStore.TxDetails(ns, &rec.Hash)
		require.NoError(t, err)
		require.NotNil(t, details)
		require.Empty(t, details.Label)

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

var (
	errInjectedCommit    = errors.New("injected commit failure")
	errAccountProperties = errors.New("account properties")
)

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

// beforeUpdateDB wraps a walletdb.DB and runs one hook immediately before the
// next Update starts its underlying write transaction.
type beforeUpdateDB struct {
	walletdb.DB

	before func()
}

// Update runs the configured pre-update hook before delegating to the embedded
// DB implementation.
func (db *beforeUpdateDB) Update(f func(walletdb.ReadWriteTx) error,
	reset func()) error {

	if db.before != nil {
		before := db.before
		db.before = nil

		before()
	}

	return db.DB.Update(f, reset)
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

// TestApplyTxBatchDuplicateUnminedKeepsConfirmed verifies that a duplicate
// unmined notification for an already-confirmed transaction is a no-op and does
// not downgrade the recorded confirmed status to pending.
func TestApplyTxBatchDuplicateUnminedKeepsConfirmed(t *testing.T) {
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
	addrStore.On("SetSyncedTo", mock.Anything, mock.Anything).Return(nil)
	addrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{}).Maybe()
	store := NewStore(dbConn, txStore, addrStore)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{63},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 10_000, PkScript: script})

	block := &db.Block{
		Hash:      chainhash.Hash{64},
		Height:    144,
		Timestamp: time.Unix(1710003200, 0),
	}

	// Record the transaction as confirmed.
	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{{
			WalletID: 0,
			Tx:       txMsg,
			Received: time.Unix(1710003100, 0),
			Block:    block,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: addr},
		}},
		SyncedTo: block,
	})
	require.NoError(t, err)

	// A later duplicate unmined notification for the same transaction must
	// not downgrade its confirmed status to pending.
	err = store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{{
			WalletID: 0,
			Tx:       txMsg,
			Received: time.Unix(1710003300, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]address.Address{0: addr},
		}},
	})
	require.NoError(t, err)

	txInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: 0,
		Txid:     txMsg.TxHash(),
	})
	require.NoError(t, err)
	require.NotNil(t, txInfo.Block)
	require.Equal(t, db.TxStatusPublished, txInfo.Status)
}

// TestApplyTxBatchConfirmedDuplicatePreservesUnminedLabel verifies that a
// confirmed notification for an already-stored unmined transaction preserves
// the existing user label instead of replacing it with the batch label.
func TestApplyTxBatchConfirmedDuplicatePreservesUnminedLabel(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)
	addrStore := &bwmock.AddrStore{}
	addrStore.On("ChainParams").Return(&chaincfg.RegressionNetParams).Maybe()
	store := NewStore(dbConn, txStore, addrStore)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{69},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 10_000, PkScript: []byte{0x51}})

	const originalLabel = "original"

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{{
			WalletID: 0,
			Tx:       txMsg,
			Received: time.Unix(1710003800, 0),
			Status:   db.TxStatusPending,
			Label:    originalLabel,
		}},
	})
	require.NoError(t, err)

	block := &db.Block{
		Hash:      chainhash.Hash{70},
		Height:    147,
		Timestamp: time.Unix(1710003900, 0),
	}
	err = store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{{
			WalletID: 0,
			Tx:       txMsg,
			Received: time.Unix(1710004000, 0),
			Block:    block,
			Status:   db.TxStatusPublished,
			Label:    "ignored",
		}},
	})
	require.NoError(t, err)

	txInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: 0,
		Txid:     txMsg.TxHash(),
	})
	require.NoError(t, err)
	require.NotNil(t, txInfo.Block)
	require.Equal(t, block.Height, txInfo.Block.Height)
	require.Equal(t, db.TxStatusPublished, txInfo.Status)
	require.Equal(t, originalLabel, txInfo.Label)
}

// TestApplyTxBatchDuplicateConfirmedRejectsBlockMismatch verifies that a
// confirmed duplicate for the same transaction hash cannot be recorded in a
// second block.
func TestApplyTxBatchDuplicateConfirmedRejectsBlockMismatch(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)
	addrStore := &bwmock.AddrStore{}
	addrStore.On("ChainParams").Return(&chaincfg.RegressionNetParams).Maybe()
	store := NewStore(dbConn, txStore, addrStore)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{65},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 10_000, PkScript: []byte{0x51}})

	firstBlock := &db.Block{
		Hash:      chainhash.Hash{66},
		Height:    145,
		Timestamp: time.Unix(1710003400, 0),
	}
	secondBlock := &db.Block{
		Hash:      chainhash.Hash{67},
		Height:    146,
		Timestamp: time.Unix(1710003500, 0),
	}

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{{
			WalletID: 0,
			Tx:       txMsg,
			Received: time.Unix(1710003300, 0),
			Block:    firstBlock,
			Status:   db.TxStatusPublished,
		}},
	})
	require.NoError(t, err)

	err = store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{{
			WalletID: 0,
			Tx:       txMsg,
			Received: time.Unix(1710003600, 0),
			Block:    secondBlock,
			Status:   db.TxStatusPublished,
		}},
	})
	require.ErrorIs(t, err, db.ErrTxAlreadyExists)

	txInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: 0,
		Txid:     txMsg.TxHash(),
	})
	require.NoError(t, err)
	require.NotNil(t, txInfo.Block)
	require.Equal(t, firstBlock.Height, txInfo.Block.Height)
	require.Equal(t, firstBlock.Hash, txInfo.Block.Hash)
}

// TestApplyTxBatchDuplicateUnminedRejectsMutation verifies that a duplicate
// unconfirmed batch member cannot mutate status, label, or credit metadata for
// a transaction already stored as unconfirmed.
func TestApplyTxBatchDuplicateUnminedRejectsMutation(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)
	addrStore := &bwmock.AddrStore{}
	addrStore.On("ChainParams").Return(&chaincfg.RegressionNetParams).Maybe()
	store := NewStore(dbConn, txStore, addrStore)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{65},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 10_000, PkScript: []byte{0x51}})

	const originalLabel = "original"

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{{
			WalletID: 0,
			Tx:       txMsg,
			Received: time.Unix(1710003400, 0),
			Status:   db.TxStatusPending,
			Label:    originalLabel,
		}},
	})
	require.NoError(t, err)

	err = store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{{
			WalletID: 0,
			Tx:       txMsg,
			Received: time.Unix(1710003500, 0),
			Status:   db.TxStatusPublished,
			Label:    "mutated",
		}},
	})
	require.ErrorIs(t, err, db.ErrTxAlreadyExists)

	err = store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{{
			WalletID: 0,
			Tx:       txMsg,
			Received: time.Unix(1710003600, 0),
			Status:   db.TxStatusPending,
			Label:    originalLabel,
			Credits:  map[uint32]address.Address{0: nil},
		}},
	})
	require.ErrorIs(t, err, db.ErrTxAlreadyExists)

	txInfo, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: 0,
		Txid:     txMsg.TxHash(),
	})
	require.NoError(t, err)
	require.Nil(t, txInfo.Block)
	require.Equal(t, db.TxStatusPending, txInfo.Status)
	require.Equal(t, originalLabel, txInfo.Label)
}

// TestApplyTxBatchRecordsTxAndSyncedTo verifies that kvdb.Store applies
// transaction notifications and sync-tip updates atomically.
func TestApplyTxBatchRecordsTxAndSyncedTo(t *testing.T) {
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
	addrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{}).Maybe()
	addrStore.On("SetSyncedTo", mock.Anything, mock.Anything).Return(nil)
	addrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{}).Maybe()
	store := NewStore(dbConn, txStore, addrStore)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{63},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 10_000, PkScript: script})

	syncedTo := &db.Block{
		Hash:      chainhash.Hash{64},
		Height:    144,
		Timestamp: time.Unix(1710003200, 0),
	}
	label := "batch label"
	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{{
			WalletID: 0,
			Tx:       txMsg,
			Received: time.Unix(1710003100, 0),
			Status:   db.TxStatusPublished,
			Label:    label,
			Credits:  map[uint32]address.Address{0: addr},
		}},
		SyncedTo: syncedTo,
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
		require.True(t, details.Credits[0].Change)

		return nil
	})
	require.NoError(t, err)
	addrStore.AssertCalled(t, "MarkUsed", mock.Anything, mock.Anything)
	addrStore.AssertCalled(
		t, "SetSyncedTo", mock.Anything,
		mock.MatchedBy(func(bs *waddrmgr.BlockStamp) bool {
			return bs.Height == int32(syncedTo.Height)
		}),
	)
}

// TestApplyTxBatchRestoresSyncedToOnFailure verifies that a batch failure after
// SetSyncedTo restores the address manager's in-memory synced tip to match the
// rolled-back walletdb state.
func TestApplyTxBatchRestoresSyncedToOnFailure(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	mgr := newSpendableAddrMgr(t, dbConn)
	t.Cleanup(mgr.Close)

	preBatchTip := mgr.SyncedTo()
	syncedTo := someBlock(t, 300)

	// The sync-tip update advances the live tip and then fails, so the whole
	// batch unwinds after the in-memory advance.
	failStore := &succeedThenFailSyncedAddrStore{Manager: mgr}
	store := NewStore(dbConn, nil, failStore)

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		SyncedTo: syncedTo,
	})
	require.ErrorIs(t, err, errInducedFailure)

	// The live tip must be restored to the pre-batch value, not left at the
	// rolled-back synced block.
	require.Equal(t, preBatchTip, mgr.SyncedTo())

	// The persisted tip must also match the pre-batch value. Reopen the
	// manager from the rolled-back bucket rather than reading the live cache.
	var reopenedTip waddrmgr.BlockStamp

	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		require.NotNil(t, ns)

		reopened, err := waddrmgr.Open(
			ns, []byte("pub"), &chaincfg.SimNetParams,
		)
		if err != nil {
			return err
		}
		defer reopened.Close()

		reopenedTip = reopened.SyncedTo()

		return nil
	})
	require.NoError(t, err)

	require.Equal(t, preBatchTip.Height, reopenedTip.Height)
	require.Equal(t, preBatchTip.Hash, reopenedTip.Hash)

	// As a positive control, a fully-successful batch through the real
	// manager must advance the live tip to the synced block.
	successStore := NewStore(dbConn, nil, mgr)
	err = successStore.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		SyncedTo: syncedTo,
	})
	require.NoError(t, err)
	require.Equal(t, syncedTo.Height, uint32(mgr.SyncedTo().Height))
	require.Equal(t, syncedTo.Hash, mgr.SyncedTo().Hash)
}

// TestApplyTxBatchRestoresWriteLockedSyncedToOnFailure verifies that a failed
// batch restores the sync tip snapshot captured inside the walletdb write
// transaction, not a stale tip observed before another writer commits.
func TestApplyTxBatchRestoresWriteLockedSyncedToOnFailure(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	mgr := newSpendableAddrMgr(t, dbConn)
	t.Cleanup(mgr.Close)

	preBatchTip := waddrmgr.BlockStamp{
		Height:    100,
		Hash:      chainhash.Hash{81},
		Timestamp: time.Unix(1710004300, 0),
	}
	writeSyncedTo(t, dbConn, mgr, preBatchTip)
	require.Equal(t, preBatchTip, mgr.SyncedTo())

	writeLockedTip := waddrmgr.BlockStamp{
		Height:    101,
		Hash:      chainhash.Hash{82},
		Timestamp: time.Unix(1710004400, 0),
	}
	failDB := &beforeUpdateDB{
		DB: dbConn,
		before: func() {
			writeSyncedTo(t, dbConn, mgr, writeLockedTip)
		},
	}

	addrStore := &succeedThenFailSyncedAddrStore{Manager: mgr}
	store := NewStore(failDB, nil, addrStore)
	syncedTo := &db.Block{
		Hash:      chainhash.Hash{83},
		Height:    102,
		Timestamp: time.Unix(1710004500, 0),
	}

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		SyncedTo: syncedTo,
	})
	require.ErrorIs(t, err, errInducedFailure)
	require.Equal(t, writeLockedTip, mgr.SyncedTo())
}

// TestApplyTxBatchSkipsStaleSyncedToRestore verifies that the failed-batch
// restore path does not overwrite a newer live tip committed after the failed
// update has returned.
func TestApplyTxBatchSkipsStaleSyncedToRestore(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	mgr := newSpendableAddrMgr(t, dbConn)
	t.Cleanup(mgr.Close)

	preBatchTip := waddrmgr.BlockStamp{
		Height:    100,
		Hash:      chainhash.Hash{84},
		Timestamp: time.Unix(1710004600, 0),
	}
	writeSyncedTo(t, dbConn, mgr, preBatchTip)
	require.Equal(t, preBatchTip, mgr.SyncedTo())

	newerTip := waddrmgr.BlockStamp{
		Height:    101,
		Hash:      chainhash.Hash{85},
		Timestamp: time.Unix(1710004700, 0),
	}
	addrStore := &succeedThenFailSyncedAddrStore{
		Manager: mgr,
		beforeRestore: func() {
			writeSyncedTo(t, dbConn, mgr, newerTip)
		},
	}
	store := NewStore(dbConn, nil, addrStore)
	syncedTo := &db.Block{
		Hash:      chainhash.Hash{86},
		Height:    102,
		Timestamp: time.Unix(1710004800, 0),
	}

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		SyncedTo: syncedTo,
	})
	require.ErrorIs(t, err, errInducedFailure)
	require.Equal(t, newerTip, mgr.SyncedTo())
}

// TestApplyTxBatchEmptyNoAddrStore verifies that a batch with no transactions
// and no sync-tip update returns nil without an address manager and without
// opening a write transaction. The store is built with a nil addrStore and the
// db has no namespaces, so any attempt to open the addrmgr bucket would fail;
// a nil error therefore proves the empty batch short-circuits before
// walletdb.Update.
func TestApplyTxBatchEmptyNoAddrStore(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	// Deliberately create no namespaces and pass a nil addrStore: an empty
	// batch must touch neither.
	store := NewStore(dbConn, nil, nil)

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{WalletID: 0})
	require.NoError(t, err)
}

// TestApplyTxBatchCreditlessNoAddrStore verifies that a transaction-only batch
// with no credits records through wtxmgr without an address manager or addrmgr
// namespace.
func TestApplyTxBatchCreditlessNoAddrStore(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{87},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 1_000, PkScript: []byte{0x51}})
	txHash := txMsg.TxHash()

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{{
			WalletID: 0,
			Tx:       txMsg,
			Received: time.Unix(1710004900, 0),
			Status:   db.TxStatusPublished,
		}},
	})
	require.NoError(t, err)

	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, txmgrNs)

		details, err := txStore.TxDetails(txmgrNs, &txHash)
		require.NoError(t, err)
		require.NotNil(t, details)
		require.Empty(t, details.Credits)

		return nil
	})
	require.NoError(t, err)
}

// TestApplyTxBatchSyncTipOnlyDoesNotRequireTxStore verifies a sync-tip-only
// batch does not require the legacy wtxmgr namespace.
func TestApplyTxBatchSyncTipOnlyDoesNotRequireTxStore(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)

	syncedTo := &db.Block{
		Hash:      chainhash.Hash{78},
		Height:    144,
		Timestamp: time.Unix(1710004400, 0),
	}
	addrStore := &bwmock.AddrStore{}
	addrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{})
	addrStore.On("SetSyncedTo", mock.Anything, mock.MatchedBy(
		func(bs *waddrmgr.BlockStamp) bool {
			return bs.Height == int32(syncedTo.Height) &&
				bs.Hash == syncedTo.Hash
		},
	)).Return(nil)
	store := NewStore(dbConn, nil, addrStore)

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		SyncedTo: syncedTo,
	})
	require.NoError(t, err)
	addrStore.AssertExpectations(t)
}

// TestApplyTxBatchRejectsMismatchedWalletID verifies kvdb enforces the shared
// batch wallet-id invariant before opening a write transaction.
func TestApplyTxBatchRejectsMismatchedWalletID(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	store := NewStore(dbConn, nil, nil)
	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{75},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 1_000, PkScript: []byte{0x51}})

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{{
			WalletID: 1,
			Tx:       txMsg,
			Received: time.Unix(1710004000, 0),
			Status:   db.TxStatusPublished,
		}},
	})
	require.ErrorIs(t, err, db.ErrInvalidParam)
}

// TestApplyScanBatchRejectsMismatchedWalletID verifies kvdb rejects a scan
// batch whose transactions are owned by a wallet other than the batch wallet.
// The test database has no namespaces, so ErrInvalidParam also proves the guard
// runs before opening a write transaction or touching the address manager.
func TestApplyScanBatchRejectsMismatchedWalletID(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := &bwmock.AddrStore{}
	store := NewStore(dbConn, nil, addrStore)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{76},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 1_000, PkScript: []byte{0x51}})

	err := store.ApplyScanBatch(t.Context(), db.ScanBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{{
			WalletID: 1,
			Tx:       txMsg,
			Received: time.Unix(1710004050, 0),
			Status:   db.TxStatusPublished,
		}},
	})
	require.ErrorIs(t, err, db.ErrInvalidParam)
}

// TestApplyScanBatchRejectsNilTx verifies that a scan batch containing a nil Tx
// is rejected with ErrInvalidParam instead of panicking while reordering the
// batch parents-first.
func TestApplyScanBatchRejectsNilTx(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := &bwmock.AddrStore{}
	store := NewStore(dbConn, nil, addrStore)

	validTx := &wire.MsgTx{Version: 1}
	validTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{77},
	}})
	validTx.AddTxOut(&wire.TxOut{Value: 1_000, PkScript: []byte{0x51}})

	err := store.ApplyScanBatch(t.Context(), db.ScanBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{
			{
				WalletID: 0,
				Tx:       validTx,
				Received: time.Unix(1710004100, 0),
				Status:   db.TxStatusPublished,
			},
			{
				WalletID: 0,
				Tx:       nil,
				Received: time.Unix(1710004101, 0),
				Status:   db.TxStatusPublished,
			},
		},
	})
	require.ErrorIs(t, err, db.ErrInvalidParam)
}

// TestApplyScanBatchEvictsHorizonOnPostExtensionReadError verifies that kvdb
// evicts live derived-address state if an account-state read fails after a scan
// horizon extension mutates the address manager cache.
func TestApplyScanBatchEvictsHorizonOnPostExtensionReadError(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)

	addrStore := &bwmock.AddrStore{}
	scopedMgr := &bwmock.AccountStore{}
	addrStore.On("FetchScopedKeyManager", waddrmgr.KeyScopeBIP0084).
		Return(scopedMgr, nil).Once()
	scopedMgr.On("AccountProperties", mock.Anything, uint32(0)).Return(
		&waddrmgr.AccountProperties{ExternalKeyCount: 4}, nil,
	).Once()
	scopedMgr.On("ExtendAddresses", mock.Anything, uint32(0), uint32(10),
		waddrmgr.ExternalBranch).Return(nil).Once()
	scopedMgr.On("AccountProperties", mock.Anything, uint32(0)).Return(
		(*waddrmgr.AccountProperties)(nil), errAccountProperties,
	).Once()
	scopedMgr.On(
		"EvictDerivedAddresses", uint32(0), waddrmgr.ExternalBranch,
		uint32(4), uint32(waddrmgr.MaxAddressesPerAccount+1),
	).Once()
	scopedMgr.On("InvalidateAccountCache", uint32(0)).Once()

	store := NewStore(dbConn, txStore, addrStore)
	err := store.ApplyScanBatch(t.Context(), db.ScanBatchParams{
		WalletID: 0,
		Horizons: []db.ScanHorizon{{
			Scope:   db.KeyScopeBIP0084,
			Account: 0,
			Branch:  waddrmgr.ExternalBranch,
			Index:   10,
		}},
	})
	require.ErrorIs(t, err, errAccountProperties)

	addrStore.AssertExpectations(t)
	scopedMgr.AssertExpectations(t)
}

// TestApplyTxBatchRejectsNilTx verifies that a multi-transaction batch
// containing a nil Tx is rejected with ErrInvalidParam instead of panicking.
// ApplyTxBatch reorders the batch parents-first before applying it, and that
// sort dereferences each transaction's Tx; without an up-front nil check the
// sort would panic on the nil member rather than returning a validation error.
func TestApplyTxBatchRejectsNilTx(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	store := NewStore(dbConn, nil, nil)

	validTx := &wire.MsgTx{Version: 1}
	validTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{77},
	}})
	validTx.AddTxOut(&wire.TxOut{Value: 1_000, PkScript: []byte{0x51}})

	// The batch carries two transactions but the second has a nil Tx. The
	// parents-first sort runs before the per-tx request validation, so this
	// must be caught by the up-front guard rather than panicking.
	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{
			{
				WalletID: 0,
				Tx:       validTx,
				Received: time.Unix(1710004100, 0),
				Status:   db.TxStatusPublished,
			},
			{
				WalletID: 0,
				Tx:       nil,
				Received: time.Unix(1710004101, 0),
				Status:   db.TxStatusPublished,
			},
		},
	})
	require.ErrorIs(t, err, db.ErrInvalidParam)
}

// TestApplyTxBatchConfirmedChildBeforeParentSpendsParent verifies that a batch
// listing a confirmed child before its in-batch confirmed parent still records
// the child's spend of the parent's wallet-owned output. The confirmed write
// path records a debit only against an already-inserted parent credit, so
// applying the child first would find no credit to spend and silently leave the
// parent output unspent. ApplyTxBatch sorts the batch parents-first to close
// that gap.
func TestApplyTxBatchConfirmedChildBeforeParentSpendsParent(t *testing.T) {
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
	addrStore.On("SetSyncedTo", mock.Anything, mock.Anything).Return(nil)
	addrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{}).Maybe()
	store := NewStore(dbConn, txStore, addrStore)

	// The parent spends an external input and credits the wallet at output 0.
	parentTx := &wire.MsgTx{Version: 1}
	parentTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{91},
	}})
	parentTx.AddTxOut(&wire.TxOut{Value: 10_000, PkScript: script})
	parentOutPoint := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}

	// The child spends the parent's wallet-owned output and credits the wallet
	// at its own output 0.
	childTx := &wire.MsgTx{Version: 1}
	childTx.AddTxIn(&wire.TxIn{PreviousOutPoint: parentOutPoint})
	childTx.AddTxOut(&wire.TxOut{Value: 9_000, PkScript: script})
	childOutPoint := wire.OutPoint{Hash: childTx.TxHash(), Index: 0}

	block := &db.Block{
		Hash:      chainhash.Hash{92},
		Height:    200,
		Timestamp: time.Unix(1710005000, 0),
	}

	// Deliberately list the confirmed child before its in-batch confirmed
	// parent. A caller-order apply would record the child first and drop its
	// spend of the not-yet-stored parent output.
	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{
			{
				WalletID: 0,
				Tx:       childTx,
				Received: time.Unix(1710005100, 0),
				Block:    block,
				Status:   db.TxStatusPublished,
				Credits:  map[uint32]address.Address{0: addr},
			},
			{
				WalletID: 0,
				Tx:       parentTx,
				Received: time.Unix(1710005101, 0),
				Block:    block,
				Status:   db.TxStatusPublished,
				Credits:  map[uint32]address.Address{0: addr},
			},
		},
		SyncedTo: block,
	})
	require.NoError(t, err)

	// The parent output must be spent and the child output unspent: only the
	// child's own credit should remain in the unspent set. Without the
	// parents-first ordering the parent output would be left unspent and both
	// outputs would appear in the unspent set.
	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		unspent, err := txStore.UnspentOutputs(ns)
		require.NoError(t, err)

		unspentSet := make(map[wire.OutPoint]struct{}, len(unspent))
		for _, credit := range unspent {
			unspentSet[credit.OutPoint] = struct{}{}
		}

		require.NotContains(t, unspentSet, parentOutPoint)
		require.Contains(t, unspentSet, childOutPoint)

		return nil
	})
	require.NoError(t, err)
}

// TestApplyScanBatchConfirmedChildBeforeParentSpendsParent verifies that a
// scan batch listing a confirmed child before its in-batch confirmed parent
// still records the child's spend of the parent's wallet-owned output.
// ApplyScanBatch sorts the transaction batch parents-first before writing
// through the same legacy transaction path as ApplyTxBatch.
func TestApplyScanBatchConfirmedChildBeforeParentSpendsParent(t *testing.T) {
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
	addrStore.On("SetSyncedTo", mock.Anything, mock.Anything).Return(nil)
	addrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{}).Maybe()
	store := NewStore(dbConn, txStore, addrStore)

	// The parent spends an external input and credits the wallet at output 0.
	parentTx := &wire.MsgTx{Version: 1}
	parentTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{93},
	}})
	parentTx.AddTxOut(&wire.TxOut{Value: 10_000, PkScript: script})
	parentOutPoint := wire.OutPoint{Hash: parentTx.TxHash(), Index: 0}

	// The child spends the parent's wallet-owned output and credits the wallet
	// at its own output 0.
	childTx := &wire.MsgTx{Version: 1}
	childTx.AddTxIn(&wire.TxIn{PreviousOutPoint: parentOutPoint})
	childTx.AddTxOut(&wire.TxOut{Value: 9_000, PkScript: script})
	childOutPoint := wire.OutPoint{Hash: childTx.TxHash(), Index: 0}

	block := db.Block{
		Hash:      chainhash.Hash{94},
		Height:    201,
		Timestamp: time.Unix(1710005200, 0),
	}

	// Deliberately list the confirmed child before its in-batch confirmed
	// parent. A caller-order apply would record the child first and drop its
	// spend of the not-yet-stored parent output.
	err := store.ApplyScanBatch(t.Context(), db.ScanBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{
			{
				WalletID: 0,
				Tx:       childTx,
				Received: time.Unix(1710005300, 0),
				Block:    &block,
				Status:   db.TxStatusPublished,
				Credits:  map[uint32]address.Address{0: addr},
			},
			{
				WalletID: 0,
				Tx:       parentTx,
				Received: time.Unix(1710005301, 0),
				Block:    &block,
				Status:   db.TxStatusPublished,
				Credits:  map[uint32]address.Address{0: addr},
			},
		},
		SyncedBlocks: []db.Block{block},
	})
	require.NoError(t, err)

	// The parent output must be spent and the child output unspent: only the
	// child's own credit should remain in the unspent set. Without the
	// parents-first ordering the parent output would be left unspent and both
	// outputs would appear in the unspent set.
	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		unspent, err := txStore.UnspentOutputs(ns)
		require.NoError(t, err)

		unspentSet := make(map[wire.OutPoint]struct{}, len(unspent))
		for _, credit := range unspent {
			unspentSet[credit.OutPoint] = struct{}{}
		}

		require.NotContains(t, unspentSet, parentOutPoint)
		require.Contains(t, unspentSet, childOutPoint)

		return nil
	})
	require.NoError(t, err)
}

// TestApplyTxBatchPersistsPendingStatus verifies kvdb batch writes round-trip
// pending transactions through the status side bucket.
func TestApplyTxBatchPersistsPendingStatus(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)
	addrStore := &bwmock.AddrStore{}
	addrStore.On("ChainParams").Return(&chaincfg.RegressionNetParams).Maybe()
	store := NewStore(dbConn, txStore, addrStore)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{76},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 1_000, PkScript: []byte{0x51}})

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{{
			WalletID: 0,
			Tx:       txMsg,
			Received: time.Unix(1710004200, 0),
			Status:   db.TxStatusPending,
		}},
	})
	require.NoError(t, err)

	info, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: 0,
		Txid:     txMsg.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, db.TxStatusPending, info.Status)
}

// TestApplyTxBatchCreditAddrMismatch verifies that the batch credit path
// rejects a credit whose address the output script does not pay, with the same
// ErrInvalidParam the CreateTx path returns. This guards against recording a
// UTXO owned by an unrelated address.
func TestApplyTxBatchCreditAddrMismatch(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)

	// The output pays to one address, but the credit claims otherAddr,
	// which the output script does not contain.
	_, script := newTestAddressScript(t)
	otherAddr, _ := newTestAddressScript(t)

	// Register no Address/MarkUsed expectations: validation must reject the
	// mismatch before the address manager is consulted.
	addrStore := &bwmock.AddrStore{}
	addrStore.On("ChainParams").Return(&chaincfg.RegressionNetParams)
	store := NewStore(dbConn, txStore, addrStore)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{67},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 7_000, PkScript: script})

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{{
			WalletID: 0,
			Tx:       txMsg,
			Received: time.Unix(1710003600, 0),
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: otherAddr},
		}},
	})
	require.ErrorIs(t, err, db.ErrInvalidParam)

	// The mismatch must be caught before any address-manager access.
	addrStore.AssertNotCalled(t, "Address", mock.Anything, mock.Anything)
	addrStore.AssertNotCalled(t, "MarkUsed", mock.Anything, mock.Anything)
}

// TestApplyTxBatchCreditNilFallback verifies that a nil credit address in the
// batch path records the credit via the output's own script, matching the
// CreateTx fallback and the SQL backends. The nil path must not consult the
// address manager (no Address/MarkUsed lookup) and must not panic.
func TestApplyTxBatchCreditNilFallback(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)

	_, script := newTestAddressScript(t)

	// A non-nil addrStore is required because the batch is non-empty, but
	// the nil-credit path must only read ChainParams and never resolve or
	// mark an address. Register no Address/MarkUsed expectations so a
	// regression that consults the address manager surfaces here.
	addrStore := &bwmock.AddrStore{}
	addrStore.On("ChainParams").Return(&chaincfg.RegressionNetParams)
	store := NewStore(dbConn, txStore, addrStore)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{68},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 4_000, PkScript: script})

	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{{
			WalletID: 0,
			Tx:       txMsg,
			Received: time.Unix(1710003700, 0),
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		}},
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

// TestApplyScanBatchRecordsTxAndSyncedBlocks verifies that kvdb.Store applies
// scan-discovered transactions and connected sync blocks in one write batch.
func TestApplyScanBatchRecordsTxAndSyncedBlocks(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)

	addr, script := newTestAddressScript(t)
	managedAddr := &bwmock.ManagedAddress{}
	managedAddr.On("Internal").Return(false).Maybe()
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
	addrStore.On("SetSyncedTo", mock.Anything, mock.Anything).Return(nil)
	addrStore.On("SyncedTo").Return(waddrmgr.BlockStamp{}).Maybe()
	store := NewStore(dbConn, txStore, addrStore)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{65},
	}})
	txMsg.AddTxOut(&wire.TxOut{Value: 11_000, PkScript: script})

	syncedBlocks := []db.Block{{
		Hash:      chainhash.Hash{66},
		Height:    145,
		Timestamp: time.Unix(1710003300, 0),
	}, {
		Hash:      chainhash.Hash{67},
		Height:    146,
		Timestamp: time.Unix(1710003400, 0),
	}}
	err := store.ApplyScanBatch(t.Context(), db.ScanBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{{
			WalletID: 0,
			Tx:       txMsg,
			Received: time.Unix(1710003350, 0),
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: addr},
		}},
		SyncedBlocks: syncedBlocks,
	})
	require.NoError(t, err)

	txid := txMsg.TxHash()
	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		details, err := txStore.TxDetails(ns, &txid)
		require.NoError(t, err)
		require.NotNil(t, details)
		require.Len(t, details.Credits, 1)

		return nil
	})
	require.NoError(t, err)
	addrStore.AssertCalled(t, "MarkUsed", mock.Anything, mock.Anything)
	addrStore.AssertCalled(
		t, "SetSyncedTo", mock.Anything,
		mock.MatchedBy(func(bs *waddrmgr.BlockStamp) bool {
			return bs.Height == int32(146)
		}),
	)
}
