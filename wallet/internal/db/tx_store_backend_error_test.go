package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
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
