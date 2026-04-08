package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
	"github.com/stretchr/testify/require"
)

var errDummy = errors.New("dummy")

// errorDBTX forces sqlc exec/query calls down their wrapped error paths.
type errorDBTX struct {
	execErr  error
	queryErr error
}

// ExecContext implements the sqlc DBTX interface.
func (e errorDBTX) ExecContext(context.Context, string,
	...interface{}) (sql.Result, error) {

	return nil, e.execErr
}

// PrepareContext implements the sqlc DBTX interface.
func (e errorDBTX) PrepareContext(context.Context,
	string) (*sql.Stmt, error) {

	return nil, errDummy
}

// QueryContext implements the sqlc DBTX interface.
func (e errorDBTX) QueryContext(context.Context, string,
	...interface{}) (*sql.Rows, error) {

	return nil, e.queryErr
}

// QueryRowContext implements the sqlc DBTX interface.
func (e errorDBTX) QueryRowContext(context.Context, string,
	...interface{}) *sql.Row {

	return &sql.Row{}
}

// TestPgDeleteAndRollbackOpsWrapBackendErrors verifies that the postgres delete
// and rollback adapters preserve their step-specific error context when sqlc
// exec and query calls fail.
func TestPgDeleteAndRollbackOpsWrapBackendErrors(t *testing.T) {
	t.Parallel()

	qtx := sqlcpg.New(errorDBTX{
		execErr:  errDummy,
		queryErr: errDummy,
	})
	deleteOps := pgDeleteTxOps{qtx: qtx}
	rollbackOps := pgRollbackToBlockOps{qtx: qtx}

	err := deleteOps.clearSpentUtxos(t.Context(), 1, 2)
	require.ErrorContains(t, err, "clear spent utxo rows")

	err = deleteOps.deleteCreatedUtxos(t.Context(), 1, 2)
	require.ErrorContains(t, err, "delete created utxo rows")

	_, err = deleteOps.deleteUnminedTransaction(
		t.Context(), 1, chainhash.Hash{1},
	)
	require.ErrorContains(t, err, "delete unmined tx row")

	_, err = rollbackOps.listUnminedTxRecords(t.Context(), 1)
	require.ErrorContains(t, err, "list unmined txns")

	err = rollbackOps.clearDescendantSpends(t.Context(), 1, 2)
	require.ErrorContains(t, err, "clear descendant spends")

	err = rollbackOps.markDescendantsFailed(t.Context(), 1, []int64{2})
	require.ErrorContains(t, err, "mark descendants failed")
}

// TestSqliteDeleteAndRollbackOpsWrapBackendErrors verifies that the sqlite
// delete and rollback adapters preserve their step-specific error context when
// sqlc exec and query calls fail.
func TestSqliteDeleteAndRollbackOpsWrapBackendErrors(t *testing.T) {
	t.Parallel()

	qtx := sqlcsqlite.New(errorDBTX{execErr: errDummy, queryErr: errDummy})
	deleteOps := sqliteDeleteTxOps{qtx: qtx}
	rollbackOps := sqliteRollbackToBlockOps{qtx: qtx}

	err := deleteOps.clearSpentUtxos(t.Context(), 1, 2)
	require.ErrorContains(t, err, "clear spent utxo rows")

	err = deleteOps.deleteCreatedUtxos(t.Context(), 1, 2)
	require.ErrorContains(t, err, "delete created utxo rows")

	_, err = deleteOps.deleteUnminedTransaction(
		t.Context(), 1, chainhash.Hash{1},
	)
	require.ErrorContains(t, err, "delete unmined tx row")

	_, err = rollbackOps.listUnminedTxRecords(t.Context(), 1)
	require.ErrorContains(t, err, "list unmined txns")

	err = rollbackOps.clearDescendantSpends(t.Context(), 1, 2)
	require.ErrorContains(t, err, "clear descendant spends")

	err = rollbackOps.markDescendantsFailed(t.Context(), 1, []int64{2})
	require.ErrorContains(t, err, "mark descendants failed")
}

// TestPgTxStoreOpsWrapBackendErrors verifies that the postgres tx-store helper
// adapters preserve step-specific error context for create, invalidate,
// rollback, update, and release workflows.
func TestPgTxStoreOpsWrapBackendErrors(t *testing.T) {
	t.Parallel()

	qtx := sqlcpg.New(errorDBTX{execErr: errDummy, queryErr: errDummy})
	createOps := &pgCreateTxOps{
		pgInvalidateUnminedTxOps: pgInvalidateUnminedTxOps{qtx: qtx},
	}
	invalidateOps := pgInvalidateUnminedTxOps{qtx: qtx}
	rollbackOps := pgRollbackToBlockOps{qtx: qtx}
	updateOps := &pgUpdateTxOps{qtx: qtx}
	releaseOps := pgReleaseOutputOps{qtx: qtx}

	err := createOps.markTxnsReplaced(
		t.Context(), 1, []int64{2},
	)
	require.ErrorContains(t, err, "mark txns replaced")

	err = createOps.insertReplacementEdges(
		t.Context(), 1, []int64{2}, 3,
	)
	require.ErrorContains(t, err, "insert replacement edge")

	err = markInputsSpentPg(t.Context(), qtx, CreateTxParams{
		WalletID: 1,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(1, 0),
		Status:   TxStatusPending,
	}, 7)
	require.ErrorContains(t, err, "mark spent input 0")

	_, err = invalidateOps.listUnminedTxRecords(t.Context(), 1)
	require.ErrorContains(t, err, "list unmined txns")

	err = invalidateOps.clearSpentUtxos(t.Context(), 1, 2)
	require.ErrorContains(t, err, "clear spent utxos")

	err = invalidateOps.markTxnsFailed(t.Context(), 1, []int64{2})
	require.ErrorContains(t, err, "mark txns failed")

	_, err = rollbackOps.listRollbackRootHashes(t.Context(), 1)
	require.ErrorContains(t, err, "query rollback coinbase roots")

	err = rollbackOps.rewindWalletSyncStateHeights(t.Context(), 1)
	require.ErrorContains(t, err, "rewind wallet sync state heights query")

	err = rollbackOps.deleteBlocksAtOrAboveHeight(t.Context(), 1)
	require.ErrorContains(t, err, "delete blocks at or above height query")

	err = rollbackOps.markTxRootsOrphaned(
		t.Context(), 1, []chainhash.Hash{{1}},
	)
	require.ErrorContains(t, err, "update rollback coinbase state query")

	updateOps.blockHeight = sql.NullInt32{}
	updateOps.status = int16(TxStatusPublished)
	err = updateOps.updateState(t.Context(), 1, chainhash.Hash{1},
		UpdateTxState{Status: TxStatusPublished})
	require.ErrorContains(t, err, "update tx state query")

	err = updateOps.updateLabel(t.Context(), 1, chainhash.Hash{1}, "note")
	require.ErrorContains(t, err, "update tx label query")

	_, err = releaseOps.release(t.Context(), 1, 2, [32]byte{1})
	require.ErrorContains(t, err, "release lease row")
}

// TestSqliteTxStoreOpsWrapBackendErrors verifies that the sqlite tx-store
// helper adapters preserve step-specific error context for create, invalidate,
// rollback, update, and release workflows.
func TestSqliteTxStoreOpsWrapBackendErrors(t *testing.T) {
	t.Parallel()

	qtx := sqlcsqlite.New(errorDBTX{execErr: errDummy, queryErr: errDummy})
	createOps := &sqliteCreateTxOps{
		sqliteInvalidateUnminedTxOps: sqliteInvalidateUnminedTxOps{
			qtx: qtx,
		},
	}
	invalidateOps := sqliteInvalidateUnminedTxOps{qtx: qtx}
	rollbackOps := sqliteRollbackToBlockOps{qtx: qtx}
	updateOps := &sqliteUpdateTxOps{qtx: qtx}
	releaseOps := sqliteReleaseOutputOps{qtx: qtx}

	err := createOps.markTxnsReplaced(
		t.Context(), 1, []int64{2},
	)
	require.ErrorContains(t, err, "mark txns replaced")

	err = createOps.insertReplacementEdges(
		t.Context(), 1, []int64{2}, 3,
	)
	require.ErrorContains(t, err, "insert replacement edge")

	err = markInputsSpentSqlite(t.Context(), qtx, CreateTxParams{
		WalletID: 1,
		Tx:       testRegularMsgTx(),
		Received: time.Unix(1, 0),
		Status:   TxStatusPending,
	}, 7)
	require.ErrorContains(t, err, "mark spent input 0")

	_, err = invalidateOps.listUnminedTxRecords(t.Context(), 1)
	require.ErrorContains(t, err, "list unmined txns")

	err = invalidateOps.clearSpentUtxos(t.Context(), 1, 2)
	require.ErrorContains(t, err, "clear spent utxos")

	err = invalidateOps.markTxnsFailed(t.Context(), 1, []int64{2})
	require.ErrorContains(t, err, "mark txns failed")

	_, err = rollbackOps.listRollbackRootHashes(t.Context(), 1)
	require.ErrorContains(t, err, "query rollback coinbase roots")

	err = rollbackOps.rewindWalletSyncStateHeights(t.Context(), 1)
	require.ErrorContains(t, err, "rewind wallet sync state heights query")

	err = rollbackOps.deleteBlocksAtOrAboveHeight(t.Context(), 1)
	require.ErrorContains(t, err, "delete blocks at or above height query")

	err = rollbackOps.markTxRootsOrphaned(
		t.Context(), 1, []chainhash.Hash{{1}},
	)
	require.ErrorContains(t, err, "update rollback coinbase state query")

	updateOps.blockHeight = sql.NullInt64{}
	updateOps.status = int64(TxStatusPublished)
	err = updateOps.updateState(t.Context(), 1, chainhash.Hash{1},
		UpdateTxState{Status: TxStatusPublished})
	require.ErrorContains(t, err, "update tx state query")

	err = updateOps.updateLabel(t.Context(), 1, chainhash.Hash{1}, "note")
	require.ErrorContains(t, err, "update tx label query")

	_, err = releaseOps.release(t.Context(), 1, 2, [32]byte{1})
	require.ErrorContains(t, err, "release lease row")
}

// TestPgBackendHelpersRejectOverflow verifies the remaining postgres helper
// branches that fail before issuing any SQL query.
func TestPgBackendHelpersRejectOverflow(t *testing.T) {
	t.Parallel()

	req, err := newCreateTxRequest(CreateTxParams{
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
		Status:   TxStatusPending,
	})
	require.NoError(t, err)

	_, err = collectPgConflictRootIDs(
		t.Context(), nil, req,
	)
	require.ErrorContains(t, err, "convert input outpoint index 0")

	_, err = creditExistsPg(t.Context(), nil, 1, chainhash.Hash{1}, ^uint32(0))
	require.ErrorContains(t, err, "convert credit index")

	err = markInputsSpentPg(t.Context(), nil, CreateTxParams{
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
		Status: TxStatusPending,
	}, 3)
	require.ErrorContains(t, err, "convert input outpoint index 0")

	err = pgRollbackToBlockOps{}.rewindWalletSyncStateHeights(
		t.Context(), ^uint32(0),
	)
	require.ErrorContains(t, err, "convert rollback height")

	err = pgRollbackToBlockOps{}.deleteBlocksAtOrAboveHeight(
		t.Context(), ^uint32(0),
	)
	require.ErrorContains(t, err, "convert rollback height")

	_, _, err = buildPgConflictRoots([]sqlcpg.ListUnminedTransactionsRow{{
		ID:       1,
		TxHash:   []byte{1},
		TxStatus: 0,
	}}, map[int64]struct{}{1: {}})
	require.ErrorContains(t, err, "tx hash")

	leaseOps := &pgLeaseOutputOps{}

	_, err = leaseOps.acquire(t.Context(), LeaseOutputParams{
		WalletID: 1,
		OutPoint: wire.OutPoint{Hash: chainhash.Hash{1}, Index: ^uint32(0)},
		ID:       [32]byte{1},
	}, time.Now(), time.Now().Add(time.Minute))
	require.ErrorContains(t, err, "convert output index")

	_, err = leaseOps.hasUtxo(t.Context(), LeaseOutputParams{
		WalletID: 1,
		OutPoint: wire.OutPoint{Hash: chainhash.Hash{1}, Index: ^uint32(0)},
		ID:       [32]byte{1},
	})
	require.ErrorContains(t, err, "convert output index")
}
