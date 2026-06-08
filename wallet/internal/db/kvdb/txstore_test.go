package kvdb

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
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
		Credits:  map[uint32]btcutil.Address{0: addr},
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
	addrStore.On("SetSyncedTo", mock.Anything, mock.Anything).Return(nil)
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
	err := store.ApplyTxBatch(t.Context(), db.TxBatchParams{
		WalletID: 0,
		Transactions: []db.CreateTxParams{{
			WalletID: 0,
			Tx:       txMsg,
			Received: time.Unix(1710003100, 0),
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]btcutil.Address{0: addr},
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
			Credits:  map[uint32]btcutil.Address{0: otherAddr},
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
			Credits:  map[uint32]btcutil.Address{0: nil},
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
			Credits:  map[uint32]btcutil.Address{0: addr},
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
		Credits:  map[uint32]btcutil.Address{0: otherAddr},
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
		Credits:  map[uint32]btcutil.Address{0: memberAddr},
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
		Credits:  map[uint32]btcutil.Address{0: nil},
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

// TestUpdateTxEmptyLabelPreservesLegacyError verifies that an empty label keeps
// the legacy kvdb validation behavior.
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

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		return txStore.InsertTx(ns, rec, nil)
	})
	require.NoError(t, err)

	empty := ""
	err = store.UpdateTx(t.Context(), db.UpdateTxParams{
		WalletID: 0,
		Txid:     rec.Hash,
		Label:    &empty,
	})
	require.ErrorIs(t, err, wtxmgr.ErrEmptyLabel)
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
func newMultisigScript(t *testing.T) (btcutil.Address, []byte) {
	t.Helper()

	firstKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	secondKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	memberAddr, err := btcutil.NewAddressPubKey(
		firstKey.PubKey().SerializeCompressed(),
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

	return memberAddr, script
}
