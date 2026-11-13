package pg

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var errDummy = errors.New("dummy")

// TestPgDeleteAndRollbackOpsWrapBackendErrors verifies that the postgres delete
// and rollback adapters preserve their step-specific error context when sqlc
// exec and query calls fail.
func TestPgDeleteAndRollbackOpsWrapBackendErrors(t *testing.T) {
	t.Parallel()

	// Arrange: Fail each existing generated query through one native DBTX mock,
	// with exact call budgets for these adapter error paths.
	dbtx := &mockDBTX{}
	dbtx.On(
		"Exec", mock.Anything, mock.Anything, mock.Anything,
	).Return(pgconn.CommandTag{}, errDummy).Times(3)
	dbtx.On(
		"Query", mock.Anything, mock.Anything, mock.Anything,
	).Return(nil, errDummy).Once()
	qtx := sqlc.New(dbtx)
	deleteOps := deleteTxOps{qtx: qtx}
	rollbackOps := rollbackToBlockOps{qtx: qtx}

	// Act: Invoke the existing adapter operations in order, using the
	// configured driver failure to exercise their contextual error returns.
	err := deleteOps.DeleteCreatedUtxos(t.Context(), 1, 2)
	// Assert: Each surviving adapter preserves its own failure context; the
	// final check accounts for the reduced set of pointer-free operations.
	require.ErrorContains(t, err, "delete created utxo rows")

	_, err = deleteOps.DeleteUnminedTransaction(
		t.Context(), 1, chainhash.Hash{1},
	)
	require.ErrorContains(t, err, "delete unmined tx row")

	_, err = rollbackOps.ListUnminedTxRecords(t.Context(), 1)
	require.ErrorContains(t, err, "list unmined txns")

	err = rollbackOps.MarkDescendantsFailed(t.Context(), 1, []int64{2})
	require.ErrorContains(t, err, "mark descendants failed")
	dbtx.AssertExpectations(t)
}

// TestPgTxStoreOpsWrapBackendErrors verifies that the postgres tx-store helper
// adapters preserve step-specific error context for create, invalidate,
// rollback, update, and Release workflows.
func TestPgTxStoreOpsWrapBackendErrors(t *testing.T) {
	t.Parallel()

	// Arrange: Fail each existing generated query through one native DBTX mock,
	// with exact call budgets for these adapter error paths.
	dbtx := &mockDBTX{}
	dbtx.On(
		"Exec", mock.Anything, mock.Anything, mock.Anything,
	).Return(pgconn.CommandTag{}, errDummy).Times(9)
	dbtx.On(
		"Query", mock.Anything, mock.Anything, mock.Anything,
	).Return(nil, errDummy).Times(2)
	qtx := sqlc.New(dbtx)
	createOps := &createTxOps{
		invalidateUnminedTxOps: invalidateUnminedTxOps{qtx: qtx},
	}
	invalidateOps := invalidateUnminedTxOps{qtx: qtx}
	rollbackOps := rollbackToBlockOps{qtx: qtx}
	updateOps := &updateTxOps{qtx: qtx}
	releaseOps := releaseOutputOps{qtx: qtx}

	// Act: Invoke the existing adapter operations in order, using the
	// configured driver failure to exercise their contextual error returns.
	err := createOps.MarkTxnsReplaced(
		t.Context(), 1, []int64{2},
	)

	// Assert: Check each operation's specific error context immediately; the
	// final expectation check verifies all query budgets once.
	require.ErrorContains(t, err, "mark txns replaced")

	err = createOps.InsertReplacementEdges(
		t.Context(), 1, []int64{2}, 3,
	)
	require.ErrorContains(t, err, "insert replacement edge")

	_, err = invalidateOps.ListUnminedTxRecords(t.Context(), 1)
	require.ErrorContains(t, err, "list unmined txns")

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

	updateOps.blockHeight = sql.NullInt32{}
	updateOps.status = int16(db.TxStatusPublished)
	err = updateOps.UpdateState(t.Context(), 1, chainhash.Hash{1},
		db.UpdateTxState{Status: db.TxStatusPublished})
	require.ErrorContains(t, err, "update tx state query")

	err = updateOps.UpdateLabel(t.Context(), 1, chainhash.Hash{1}, "note")
	require.ErrorContains(t, err, "update tx label query")

	_, err = releaseOps.Release(t.Context(), 1, 2, [32]byte{1})
	require.ErrorContains(t, err, "release lease row")
	dbtx.AssertExpectations(t)
}

// TestPgBackendHelpersRejectOverflow verifies the remaining postgres helper
// branches that fail before issuing any SQL query.
func TestPgBackendHelpersRejectOverflow(t *testing.T) {
	t.Parallel()

	// Arrange: Use values outside the SQL integer range; nil query adapters
	// ensure each conversion fails before attempting a database operation.

	// Act: Pass an oversized output index through the remaining credit lookup.
	_, _, err := creditExists(
		t.Context(), nil, 1, chainhash.Hash{1}, ^uint32(0),
	)
	// Assert: Every conversion reports its specific context before querying.
	require.ErrorContains(t, err, "convert credit index")

	err = rollbackToBlockOps{}.RewindWalletSyncStateHeights(
		t.Context(), ^uint32(0),
	)
	require.ErrorContains(t, err, "convert rollback height")

	err = rollbackToBlockOps{}.DeleteBlocksAtOrAboveHeight(
		t.Context(), ^uint32(0),
	)
	require.ErrorContains(t, err, "convert rollback height")

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
