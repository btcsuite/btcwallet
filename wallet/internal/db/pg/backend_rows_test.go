package pg

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// staticResult is a minimal sql.Result stub with a caller-controlled row count.
type staticResult struct {
	rows int64
}

// LastInsertId implements sql.Result.
func (r staticResult) LastInsertId() (int64, error) {
	return 0, nil
}

// RowsAffected implements sql.Result.
func (r staticResult) RowsAffected() (int64, error) {
	return r.rows, nil
}

// rowDBTX is a sqlc DBTX stub that lets tests mix fixed exec counts with
// query-row scan failures from a temporary sqlite handle.
type rowDBTX struct {
	row       *sql.Row
	queryRows *sql.Rows
	queryErr  error
	execErr   error
	rows      int64
}

// ExecContext implements the sqlc DBTX interface.
func (r rowDBTX) ExecContext(context.Context, string,
	...any) (sql.Result, error) {

	if r.execErr != nil {
		return nil, r.execErr
	}

	return staticResult{rows: r.rows}, nil
}

// PrepareContext implements the sqlc DBTX interface.
func (r rowDBTX) PrepareContext(context.Context, string) (*sql.Stmt, error) {
	return nil, errDummy
}

// QueryContext implements the sqlc DBTX interface.
func (r rowDBTX) QueryContext(context.Context, string,
	...any) (*sql.Rows, error) {

	if r.queryErr != nil {
		return nil, r.queryErr
	}

	return r.queryRows, nil
}

// QueryRowContext implements the sqlc DBTX interface.
func (r rowDBTX) QueryRowContext(context.Context, string,
	...any) *sql.Row {

	if r.row != nil {
		return r.row
	}

	return &sql.Row{}
}

// newSQLiteRow creates a query row backed by an in-memory sqlite database so
// sqlc scan paths can fail without standing up a real store.
func newSQLiteRow(t *testing.T, query string, args ...any) *sql.Row {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = db.Close()
	})

	return db.QueryRowContext(t.Context(), query, args...)
}

// newSQLiteRows runs a multi-row query against an in-memory sqlite database so
// sqlc :many scan paths can be exercised without standing up a real store.
func newSQLiteRows(t *testing.T, query string, args ...any) *sql.Rows {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = db.Close()
	})

	rows, err := db.QueryContext(t.Context(), query, args...)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = rows.Close()
	})

	return rows
}

// TestPgCreateTxOpsAdditionalBranches covers remaining postgres CreateTx helper
// branches that are hard to reach through public integration tests alone.
func TestPgCreateTxOpsAdditionalBranches(t *testing.T) {
	t.Parallel()

	req := testCreateTxRequest(t)
	ctx := context.Background()
	loadOps := &createTxOps{
		invalidateUnminedTxOps: invalidateUnminedTxOps{
			qtx: sqlc.New(rowDBTX{
				row: newSQLiteRow(t, "SELECT 1 FROM missing_table"),
			}),
		},
	}

	_, err := loadOps.LoadExisting(ctx, req)
	require.ErrorContains(t, err, "get tx metadata")

	block := &db.Block{
		Hash:      chainhash.Hash{3},
		Height:    7,
		Timestamp: time.Unix(77, 0),
	}
	confirmOps := &createTxOps{
		invalidateUnminedTxOps: invalidateUnminedTxOps{
			qtx: sqlc.New(rowDBTX{
				row: newSQLiteRow(
					t, "SELECT ?, ?, ?",
					int64(block.Height), block.Hash[:],
					block.Timestamp.Unix(),
				),
				rows: 0,
			}),
		},
	}
	err = confirmOps.ConfirmExisting(ctx, db.CreateTxRequest{
		Params: db.CreateTxParams{WalletID: 1, Block: block},
		TxHash: chainhash.Hash{9},
	}, db.CreateTxExistingTarget{})
	require.ErrorIs(t, err, db.ErrTxNotFound)

	conflictOps := &createTxOps{
		invalidateUnminedTxOps: invalidateUnminedTxOps{
			qtx: sqlc.New(rowDBTX{
				row:      newSQLiteRow(t, "SELECT ?, ?", int64(5), []byte{1}),
				queryErr: errDummy,
			}),
		},
	}
	_, _, err = conflictOps.ListConflictTxns(ctx, req)
	require.ErrorContains(t, err, "lookup input spenders")
}

// TestPgUpdateTxOpsAdditionalBranches covers the remaining postgres UpdateTx
// helper branches that are hard to reach through public integration tests
// alone.
func TestPgUpdateTxOpsAdditionalBranches(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	txHash := chainhash.Hash{9}
	loadOps := &updateTxOps{qtx: sqlc.New(rowDBTX{
		row: newSQLiteRow(t, "SELECT 1 FROM missing_table"),
	})}
	stateOps := &updateTxOps{
		qtx:         sqlc.New(rowDBTX{rows: 0}),
		blockHeight: sql.NullInt32{},
		status:      int16(db.TxStatusPublished),
	}
	labelOps := &updateTxOps{qtx: sqlc.New(rowDBTX{rows: 0})}

	_, err := loadOps.LoadIsCoinbase(ctx, 1, txHash)
	require.ErrorContains(t, err, "get tx metadata")

	err = stateOps.UpdateState(ctx, 1, txHash, db.UpdateTxState{
		Status: db.TxStatusPublished,
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)

	err = labelOps.UpdateLabel(ctx, 1, txHash, "note")
	require.ErrorIs(t, err, db.ErrTxNotFound)
}
