package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"

	"github.com/btcsuite/btcd/chainhash/v2"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// InvalidateUnminedTx atomically invalidates one wallet-owned unmined
// transaction branch and marks the root plus descendants failed.
func (s *SqliteStore) InvalidateUnminedTx(ctx context.Context,
	params db.InvalidateUnminedTxParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		return db.InvalidateUnminedTxWithOps(
			ctx, params, sqliteInvalidateUnminedTxOps{qtx: qtx},
		)
	})
}

// sqliteInvalidateUnminedTxOps adapts sqlite sqlc queries to the shared
// InvalidateUnminedTx workflow.
type sqliteInvalidateUnminedTxOps struct {
	qtx *sqlcsqlite.Queries
}

var _ db.InvalidateUnminedTxOps = (*sqliteInvalidateUnminedTxOps)(nil)

// LoadInvalidateTarget loads the root tx metadata used by the shared
// invalidation workflow.
func (o sqliteInvalidateUnminedTxOps) LoadInvalidateTarget(ctx context.Context,
	walletID uint32,
	txHash chainhash.Hash) (db.InvalidateUnminedTxTarget, error) {

	row, err := o.qtx.GetTransactionMetaByHash(
		ctx, sqlcsqlite.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return db.InvalidateUnminedTxTarget{}, fmt.Errorf(
				"tx %s: %w", txHash, db.ErrTxNotFound,
			)
		}

		return db.InvalidateUnminedTxTarget{}, fmt.Errorf("get tx metadata: %w",
			err)
	}

	status, err := db.ParseTxStatus(row.TxStatus)
	if err != nil {
		return db.InvalidateUnminedTxTarget{}, err
	}

	return db.InvalidateUnminedTxTarget{
		ID:         row.ID,
		TxHash:     txHash,
		Status:     status,
		HasBlock:   row.BlockHeight.Valid,
		IsCoinbase: row.IsCoinbase,
	}, nil
}

// ListUnminedTxRecords loads and decodes the wallet's active unmined
// transaction rows.
func (o sqliteInvalidateUnminedTxOps) ListUnminedTxRecords(
	ctx context.Context, walletID int64) ([]db.UnminedTxRecord, error) {

	rows, err := o.qtx.ListUnminedTransactions(ctx, walletID)
	if err != nil {
		return nil, fmt.Errorf("list unmined txns: %w", err)
	}

	return db.BuildUnminedTxRecords(
		rows, func(row sqlcsqlite.ListUnminedTransactionsRow) (
			int64, []byte, []byte) {

			return row.ID, row.TxHash, row.RawTx
		},
	)
}

// ClearSpentUtxos restores any wallet-owned parent outputs spent by the given
// transaction row.
func (o sqliteInvalidateUnminedTxOps) ClearSpentUtxos(ctx context.Context,
	walletID int64, txID int64) error {

	_, err := o.qtx.ClearUtxosSpentByTxID(
		ctx, sqlcsqlite.ClearUtxosSpentByTxIDParams{
			WalletID: walletID,
			SpentByTxID: sql.NullInt64{
				Int64: txID,
				Valid: true,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("clear spent utxos: %w", err)
	}

	return nil
}

// MarkTxnsFailed marks the provided tx rows failed in one
// batch update.
func (o sqliteInvalidateUnminedTxOps) MarkTxnsFailed(
	ctx context.Context, walletID int64, txIDs []int64) error {

	_, err := o.qtx.UpdateTransactionStatusByIDs(
		ctx, sqlcsqlite.UpdateTransactionStatusByIDsParams{
			WalletID: walletID,
			Status:   int64(db.TxStatusFailed),
			TxIds:    txIDs,
		},
	)
	if err != nil {
		return fmt.Errorf("mark txns failed: %w", err)
	}

	return nil
}
