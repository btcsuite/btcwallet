package kvdb

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// TestUpdateTxLabelOnlySuccess verifies that kvdb.Store can apply a label-only
// UpdateTx patch through the legacy label path.
func TestUpdateTxLabelOnlySuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore)

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
	store := NewStore(dbConn, txStore)

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
	store := NewStore(dbConn, txStore)

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
	store := NewStore(dbConn, txStore)

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
	store := NewStore(dbConn, txStore)

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
	store := NewStore(dbConn, txStore)

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

// TestGetTxSummaryNotFound verifies that kvdb.Store reports missing
// transactions through db.ErrTxNotFound.
func TestGetTxSummaryNotFound(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore)

	_, err := store.GetTx(t.Context(), db.GetTxQuery{
		WalletID: 0,
		Txid:     chainhash.Hash{42},
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
}
