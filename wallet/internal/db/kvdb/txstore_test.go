package kvdb

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
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

// TestGetTxDetailSuccess verifies that kvdb.Store adapts legacy tx details to
// the db-native detail model.
func TestGetTxDetailSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore)

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
	store := NewStore(dbConn, txStore)

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
	store := NewStore(dbConn, txStore)

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
	store := NewStore(dbConn, txStore)

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
	store := NewStore(dbConn, txStore)

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
	store := NewStore(dbConn, txStore)

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
