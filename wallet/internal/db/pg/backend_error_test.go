package pg

import (
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var errDummy = errors.New("dummy")

// TestPgDeleteAndRollbackOpsWrapBackendErrors verifies that the postgres delete
// and rollback adapters preserve their step-specific error context when sqlc
// exec and query calls fail.
func TestPgDeleteAndRollbackOpsWrapBackendErrors(t *testing.T) {
	t.Parallel()

	dbtx := &mockDBTX{}
	dbtx.On(
		"Exec", mock.Anything, mock.Anything, mock.Anything,
	).Return(pgconn.CommandTag{}, errDummy)
	dbtx.On(
		"Query", mock.Anything, mock.Anything, mock.Anything,
	).Return(nil, errDummy)
	qtx := sqlc.New(dbtx)
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
	dbtx.AssertNumberOfCalls(t, "Exec", 5)
	dbtx.AssertNumberOfCalls(t, "Query", 1)
	dbtx.AssertExpectations(t)
}

// TestPgTxStoreOpsWrapBackendErrors verifies that the postgres tx-store helper
// adapters preserve step-specific error context for create, invalidate,
// rollback, update, and Release workflows.
func TestPgTxStoreOpsWrapBackendErrors(t *testing.T) {
	t.Parallel()

	dbtx := &mockDBTX{}
	dbtx.On(
		"Exec", mock.Anything, mock.Anything, mock.Anything,
	).Return(pgconn.CommandTag{}, errDummy)
	dbtx.On(
		"Query", mock.Anything, mock.Anything, mock.Anything,
	).Return(nil, errDummy)
	qtx := sqlc.New(dbtx)
	createOps := &createTxOps{
		invalidateUnminedTxOps: invalidateUnminedTxOps{qtx: qtx},
	}
	invalidateOps := invalidateUnminedTxOps{qtx: qtx}
	rollbackOps := rollbackToBlockOps{qtx: qtx}
	updateOps := &updateTxOps{qtx: qtx}
	releaseOps := releaseOutputOps{qtx: qtx}

	err := createOps.MarkTxnsReplaced(
		t.Context(), 1, []int64{2},
	)
	require.ErrorContains(t, err, "mark txns replaced")

	err = createOps.InsertReplacementEdges(
		t.Context(), 1, []int64{2}, 3,
	)
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

	err = rollbackOps.MarkTxRootsOrphaned(
		t.Context(), 1, []chainhash.Hash{{1}},
	)
	require.ErrorContains(t, err, "update rollback coinbase state query")

	updateOps.blockHeight = pgtype.Int4{}
	updateOps.status = int16(db.TxStatusPublished)
	err = updateOps.UpdateState(t.Context(), 1, chainhash.Hash{1},
		db.UpdateTxState{Status: db.TxStatusPublished})
	require.ErrorContains(t, err, "update tx state query")

	err = updateOps.UpdateLabel(t.Context(), 1, chainhash.Hash{1}, "note")
	require.ErrorContains(t, err, "update tx label query")

	_, err = releaseOps.Release(t.Context(), 1, 2, [32]byte{1})
	require.ErrorContains(t, err, "release lease row")
	dbtx.AssertNumberOfCalls(t, "Exec", 11)
	dbtx.AssertNumberOfCalls(t, "Query", 2)
	dbtx.AssertExpectations(t)
}

// TestPgBackendHelpersRejectOverflow verifies the remaining postgres helper
// branches that fail before issuing any SQL query.
func TestPgBackendHelpersRejectOverflow(t *testing.T) {
	t.Parallel()

	req, err := db.NewCreateTxRequest(db.CreateTxParams{
		WalletID: 1,
		Tx: &wire.MsgTx{
			Version: wire.TxVersion,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{1},
					Index: ^uint32(0),
				},
			}},
			TxOut: []*wire.TxOut{{Value: 1, PkScript: []byte{0x51}}},
		},
		Received: time.Unix(1, 0),
		Status:   db.TxStatusPending,
	})
	require.NoError(t, err)

	_, err = collectConflictRootIDs(
		t.Context(), nil, req,
	)
	require.ErrorContains(t, err, "convert input outpoint index 0")

	_, _, err = creditExists(t.Context(), nil, 1, chainhash.Hash{1}, ^uint32(0))
	require.ErrorContains(t, err, "convert credit index")

	err = markInputsSpent(t.Context(), nil, db.CreateTxParams{
		WalletID: 1,
		Tx: &wire.MsgTx{
			Version: wire.TxVersion,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{1},
					Index: ^uint32(0),
				},
			}},
		},
		Status: db.TxStatusPending,
	}, 3)
	require.ErrorContains(t, err, "convert input outpoint index 0")

	err = rollbackToBlockOps{}.RewindWalletSyncStateHeights(
		t.Context(), ^uint32(0),
	)
	require.ErrorContains(t, err, "convert rollback height")

	err = rollbackToBlockOps{}.DeleteBlocksAtOrAboveHeight(
		t.Context(), ^uint32(0),
	)
	require.ErrorContains(t, err, "convert rollback height")

	_, _, err = buildConflictRoots([]sqlc.ListUnminedTransactionsRow{{
		ID:       1,
		TxHash:   []byte{1},
		TxStatus: 0,
	}}, map[int64]struct{}{1: {}})
	require.ErrorContains(t, err, "tx hash")

	leaseOps := &leaseOutputOps{}

	_, err = leaseOps.Acquire(t.Context(), db.LeaseOutputParams{
		WalletID: 1,
		OutPoint: wire.OutPoint{Hash: chainhash.Hash{1}, Index: ^uint32(0)},
		ID:       [32]byte{1},
	}, time.Now(), time.Now().Add(time.Minute))
	require.ErrorContains(t, err, "convert output index")

	_, err = leaseOps.HasUtxo(t.Context(), db.LeaseOutputParams{
		WalletID: 1,
		OutPoint: wire.OutPoint{Hash: chainhash.Hash{1}, Index: ^uint32(0)},
		ID:       [32]byte{1},
	})
	require.ErrorContains(t, err, "convert output index")
}
