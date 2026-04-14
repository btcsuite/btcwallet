package sqlite

import (
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
	"github.com/stretchr/testify/require"
)

// TestDeleteAndRollbackOpsWrapBackendErrors verifies sqlite delete and rollback
// error wrapping.
func TestDeleteAndRollbackOpsWrapBackendErrors(t *testing.T) {
	t.Parallel()

	qtx := sqlc.New(errorDBTX{execErr: errDummy, queryErr: errDummy})
	deleteOps := deleteTxOps{qtx: qtx}
	rollbackOps := rollbackToBlockOps{qtx: qtx}

	err := deleteOps.ClearSpentUtxos(t.Context(), 1, 2)
	require.ErrorContains(t, err, "clear spent utxo rows")

	err = deleteOps.DeleteCreatedUtxos(t.Context(), 1, 2)
	require.ErrorContains(t, err, "delete created utxo rows")

	_, err = deleteOps.DeleteUnminedTransaction(
		t.Context(), 1, chainhash.Hash{1},
	)
	require.ErrorContains(t, err, "delete unmined tx row")

	_, err = rollbackOps.ListUnminedTxRecords(t.Context(), 1)
	require.ErrorContains(t, err, "list unmined txns")

	err = rollbackOps.ClearDescendantSpends(t.Context(), 1, 2)
	require.ErrorContains(t, err, "clear descendant spends")

	err = rollbackOps.MarkDescendantsFailed(t.Context(), 1, []int64{2})
	require.ErrorContains(t, err, "mark descendants failed")
}

// TestTxStoreOpsWrapBackendErrors verifies sqlite helper error wrapping.
func TestTxStoreOpsWrapBackendErrors(t *testing.T) {
	t.Parallel()

	qtx := sqlc.New(errorDBTX{execErr: errDummy, queryErr: errDummy})
	createOps := &createTxOps{
		invalidateUnminedTxOps: invalidateUnminedTxOps{qtx: qtx},
	}
	invalidateOps := invalidateUnminedTxOps{qtx: qtx}
	rollbackOps := rollbackToBlockOps{qtx: qtx}
	updateOps := &updateTxOps{qtx: qtx}
	releaseOps := releaseOutputOps{qtx: qtx}

	err := createOps.MarkTxnsReplaced(t.Context(), 1, []int64{2})
	require.ErrorContains(t, err, "mark txns replaced")

	err = createOps.InsertReplacementEdges(t.Context(), 1, []int64{2}, 3)
	require.ErrorContains(t, err, "insert replacement edge")

	err = markInputsSpent(t.Context(), qtx, db.CreateTxParams{
		WalletID: 1,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(1, 0),
		Status:   db.TxStatusPending,
	}, 7)
	require.ErrorContains(t, err, "mark spent input 0")

	_, err = invalidateOps.ListUnminedTxRecords(t.Context(), 1)
	require.ErrorContains(t, err, "list unmined txns")

	err = invalidateOps.ClearSpentUtxos(t.Context(), 1, 2)
	require.ErrorContains(t, err, "clear spent utxos")

	err = invalidateOps.MarkTxnsFailed(t.Context(), 1, []int64{2})
	require.ErrorContains(t, err, "mark txns failed")

	_, err = rollbackOps.ListRollbackRootHashes(t.Context(), 1)
	require.ErrorContains(t, err, "query rollback coinbase roots")

	err = rollbackOps.RewindWalletSyncStateHeights(t.Context(), 1)
	require.ErrorContains(t, err, "rewind wallet sync state heights query")

	err = rollbackOps.DeleteBlocksAtOrAboveHeight(t.Context(), 1)
	require.ErrorContains(t, err, "delete blocks at or above height query")

	err = rollbackOps.MarkTxRootsOrphaned(t.Context(), 1, []chainhash.Hash{{1}})
	require.ErrorContains(t, err, "update rollback coinbase state query")

	updateOps.blockHeight = sql.NullInt64{}
	updateOps.status = int64(db.TxStatusPublished)
	err = updateOps.UpdateState(
		t.Context(), 1, chainhash.Hash{1},
		db.UpdateTxState{Status: db.TxStatusPublished},
	)
	require.ErrorContains(t, err, "update tx state query")

	err = updateOps.UpdateLabel(t.Context(), 1, chainhash.Hash{1}, "note")
	require.ErrorContains(t, err, "update tx label query")

	_, err = releaseOps.Release(t.Context(), 1, 2, [32]byte{1})
	require.ErrorContains(t, err, "release lease row")
}
