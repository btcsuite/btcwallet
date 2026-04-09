package db

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
	"github.com/stretchr/testify/require"
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
	row      *sql.Row
	queryErr error
	execErr  error
	rows     int64
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

	return nil, r.queryErr
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

// TestPgCreateTxOpsAdditionalBranches covers remaining postgres CreateTx helper
// branches that are hard to reach through public integration tests alone.
func TestPgCreateTxOpsAdditionalBranches(t *testing.T) {
	t.Parallel()

	req := testCreateTxRequest(t)
	ctx := context.Background()
	loadOps := &pgCreateTxOps{
		pgInvalidateUnminedTxOps: pgInvalidateUnminedTxOps{
			qtx: sqlcpg.New(rowDBTX{
				row: newSQLiteRow(t, "SELECT 1 FROM missing_table"),
			}),
		},
	}

	_, err := loadOps.LoadExisting(ctx, req)
	require.ErrorContains(t, err, "get tx metadata")

	block := &Block{
		Hash:      chainhash.Hash{3},
		Height:    7,
		Timestamp: time.Unix(77, 0),
	}
	confirmOps := &pgCreateTxOps{
		pgInvalidateUnminedTxOps: pgInvalidateUnminedTxOps{
			qtx: sqlcpg.New(rowDBTX{
				row: newSQLiteRow(
					t, "SELECT ?, ?, ?",
					int64(block.Height), block.Hash[:],
					block.Timestamp.Unix(),
				),
				rows: 0,
			}),
		},
	}
	err = confirmOps.ConfirmExisting(ctx, CreateTxRequest{
		Params: CreateTxParams{WalletID: 1, Block: block},
		TxHash: chainhash.Hash{9},
	}, CreateTxExistingTarget{})
	require.ErrorIs(t, err, ErrTxNotFound)

	conflictOps := &pgCreateTxOps{
		pgInvalidateUnminedTxOps: pgInvalidateUnminedTxOps{
			qtx: sqlcpg.New(rowDBTX{
				row:      newSQLiteRow(t, "SELECT ?", int64(5)),
				queryErr: errDummy,
			}),
		},
	}
	_, _, err = conflictOps.ListConflictTxns(ctx, req)
	require.ErrorContains(t, err, "list unmined txns")
}

// TestSqliteCreateTxOpsAdditionalBranches covers remaining sqlite CreateTx
// helper branches that are hard to reach through public integration tests
// alone.
func TestSqliteCreateTxOpsAdditionalBranches(t *testing.T) {
	t.Parallel()

	req := testCreateTxRequest(t)
	ctx := context.Background()
	loadOps := &sqliteCreateTxOps{
		sqliteInvalidateUnminedTxOps: sqliteInvalidateUnminedTxOps{
			qtx: sqlcsqlite.New(rowDBTX{
				row: newSQLiteRow(t, "SELECT 1 FROM missing_table"),
			}),
		},
	}

	_, err := loadOps.LoadExisting(ctx, req)
	require.ErrorContains(t, err, "get tx metadata")

	block := &Block{
		Hash:      chainhash.Hash{4},
		Height:    8,
		Timestamp: time.Unix(88, 0),
	}
	confirmOps := &sqliteCreateTxOps{
		sqliteInvalidateUnminedTxOps: sqliteInvalidateUnminedTxOps{
			qtx: sqlcsqlite.New(rowDBTX{
				row: newSQLiteRow(
					t, "SELECT ?, ?, ?",
					int64(block.Height), block.Hash[:],
					block.Timestamp.Unix(),
				),
				rows: 0,
			}),
		},
	}
	err = confirmOps.ConfirmExisting(ctx, CreateTxRequest{
		Params: CreateTxParams{WalletID: 1, Block: block},
		TxHash: chainhash.Hash{9},
	}, CreateTxExistingTarget{})
	require.ErrorIs(t, err, ErrTxNotFound)

	prepareOps := &sqliteCreateTxOps{
		sqliteInvalidateUnminedTxOps: sqliteInvalidateUnminedTxOps{
			qtx: sqlcsqlite.New(rowDBTX{
				row: newSQLiteRow(t, "SELECT 1 FROM missing_table"),
			}),
		},
	}
	err = prepareOps.PrepareBlock(ctx, CreateTxRequest{
		Params: CreateTxParams{WalletID: 1, Block: block},
	})
	require.ErrorContains(t, err, "get block by height")

	conflictOps := &sqliteCreateTxOps{
		sqliteInvalidateUnminedTxOps: sqliteInvalidateUnminedTxOps{
			qtx: sqlcsqlite.New(rowDBTX{
				row:      newSQLiteRow(t, "SELECT ?", int64(5)),
				queryErr: errDummy,
			}),
		},
	}
	_, _, err = conflictOps.ListConflictTxns(ctx, req)
	require.ErrorContains(t, err, "list unmined txns")
}

// TestSqliteReleaseOutputOpsAdditionalBranches covers the remaining sqlite
// Release-helper query-row error wrappers.
func TestSqliteReleaseOutputOpsAdditionalBranches(t *testing.T) {
	t.Parallel()

	ops := &sqliteReleaseOutputOps{qtx: sqlcsqlite.New(rowDBTX{
		row: newSQLiteRow(t, "SELECT 1 FROM missing_table"),
	})}

	_, err := ops.LookupUtxoID(context.Background(), ReleaseOutputParams{
		WalletID: 1,
		OutPoint: wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0},
	})
	require.ErrorContains(t, err, "lookup utxo row")

	_, err = ops.ActiveLockID(context.Background(), 1, 2, time.Now())
	require.ErrorContains(t, err, "lookup active lease row")
}

// TestPgUpdateTxOpsAdditionalBranches covers the remaining postgres UpdateTx
// helper branches that are hard to reach through public integration tests
// alone.
func TestPgUpdateTxOpsAdditionalBranches(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	txHash := chainhash.Hash{9}
	loadOps := &pgUpdateTxOps{qtx: sqlcpg.New(rowDBTX{
		row: newSQLiteRow(t, "SELECT 1 FROM missing_table"),
	})}
	stateOps := &pgUpdateTxOps{
		qtx:         sqlcpg.New(rowDBTX{rows: 0}),
		blockHeight: sql.NullInt32{},
		status:      int16(TxStatusPublished),
	}
	labelOps := &pgUpdateTxOps{qtx: sqlcpg.New(rowDBTX{rows: 0})}

	_, err := loadOps.LoadIsCoinbase(ctx, 1, txHash)
	require.ErrorContains(t, err, "get tx metadata")

	err = stateOps.UpdateState(ctx, 1, txHash, UpdateTxState{
		Status: TxStatusPublished,
	})
	require.ErrorIs(t, err, ErrTxNotFound)

	err = labelOps.UpdateLabel(ctx, 1, txHash, "note")
	require.ErrorIs(t, err, ErrTxNotFound)
}

// TestSqliteUpdateTxOpsAdditionalBranches covers the remaining sqlite UpdateTx
// helper branches that are hard to reach through public integration tests
// alone.
func TestSqliteUpdateTxOpsAdditionalBranches(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	txHash := chainhash.Hash{9}
	loadOps := &sqliteUpdateTxOps{qtx: sqlcsqlite.New(rowDBTX{
		row: newSQLiteRow(t, "SELECT 1 FROM missing_table"),
	})}
	stateOps := &sqliteUpdateTxOps{
		qtx:         sqlcsqlite.New(rowDBTX{rows: 0}),
		blockHeight: sql.NullInt64{},
		status:      int64(TxStatusPublished),
	}
	labelOps := &sqliteUpdateTxOps{qtx: sqlcsqlite.New(rowDBTX{rows: 0})}

	_, err := loadOps.LoadIsCoinbase(ctx, 1, txHash)
	require.ErrorContains(t, err, "get tx metadata")

	err = stateOps.UpdateState(ctx, 1, txHash, UpdateTxState{
		Status: TxStatusPublished,
	})
	require.ErrorIs(t, err, ErrTxNotFound)

	err = labelOps.UpdateLabel(ctx, 1, txHash, "note")
	require.ErrorIs(t, err, ErrTxNotFound)
}
