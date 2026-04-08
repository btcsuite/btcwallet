package sqlite

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
	"github.com/stretchr/testify/require"
)

// TestCreateTxOpsAdditionalBranches covers remaining sqlite CreateTx branches.
func TestCreateTxOpsAdditionalBranches(t *testing.T) {
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

	block := testBlock(8)
	confirmOps := &sqliteCreateTxOps{
		sqliteInvalidateUnminedTxOps: sqliteInvalidateUnminedTxOps{
			qtx: sqlcsqlite.New(rowDBTX{
				row: newSQLiteRow(
					t,
					"SELECT ?, ?, ?",
					int64(block.Height),
					block.Hash[:],
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

	prepareOps := &sqliteCreateTxOps{
		sqliteInvalidateUnminedTxOps: sqliteInvalidateUnminedTxOps{
			qtx: sqlcsqlite.New(rowDBTX{
				row: newSQLiteRow(t, "SELECT 1 FROM missing_table"),
			}),
		},
	}
	err = prepareOps.PrepareBlock(ctx, db.CreateTxRequest{
		Params: db.CreateTxParams{WalletID: 1, Block: block},
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

// TestReleaseOutputOpsAdditionalBranches covers remaining sqlite Release paths.
func TestReleaseOutputOpsAdditionalBranches(t *testing.T) {
	t.Parallel()

	ops := &sqliteReleaseOutputOps{qtx: sqlcsqlite.New(rowDBTX{
		row: newSQLiteRow(t, "SELECT 1 FROM missing_table"),
	})}

	_, err := ops.LookupUtxoID(context.Background(), db.ReleaseOutputParams{
		WalletID: 1,
		OutPoint: wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0},
	})
	require.ErrorContains(t, err, "lookup utxo row")

	_, err = ops.ActiveLockID(context.Background(), 1, 2, time.Now())
	require.ErrorContains(t, err, "lookup active lease row")
}

// TestUpdateTxOpsAdditionalBranches covers remaining sqlite UpdateTx branches.
func TestUpdateTxOpsAdditionalBranches(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	txHash := chainhash.Hash{9}
	loadOps := &sqliteUpdateTxOps{qtx: sqlcsqlite.New(rowDBTX{
		row: newSQLiteRow(t, "SELECT 1 FROM missing_table"),
	})}
	stateOps := &sqliteUpdateTxOps{
		qtx:         sqlcsqlite.New(rowDBTX{rows: 0}),
		blockHeight: sql.NullInt64{},
		status:      int64(db.TxStatusPublished),
	}
	labelOps := &sqliteUpdateTxOps{qtx: sqlcsqlite.New(rowDBTX{rows: 0})}

	_, err := loadOps.LoadIsCoinbase(ctx, 1, txHash)
	require.ErrorContains(t, err, "get tx metadata")

	err = stateOps.UpdateState(
		ctx, 1, txHash, db.UpdateTxState{Status: db.TxStatusPublished},
	)
	require.ErrorIs(t, err, db.ErrTxNotFound)

	err = labelOps.UpdateLabel(ctx, 1, txHash, "note")
	require.ErrorIs(t, err, db.ErrTxNotFound)
}
