package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"

	"github.com/btcsuite/btcd/chainhash/v2"
	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// InvalidateUnminedTx atomically invalidates one wallet-owned unmined
// transaction branch and marks the root plus descendants failed.
func (s *PostgresStore) InvalidateUnminedTx(ctx context.Context,
	params db.InvalidateUnminedTxParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		return db.InvalidateUnminedTxWithOps(
			ctx, params, pgInvalidateUnminedTxOps{qtx: qtx},
		)
	})
}

// pgInvalidateUnminedTxOps adapts postgres sqlc queries to the shared
// InvalidateUnminedTx workflow.
type pgInvalidateUnminedTxOps struct {
	qtx *sqlcpg.Queries
}

var _ db.InvalidateUnminedTxOps = (*pgInvalidateUnminedTxOps)(nil)

// LoadInvalidateTarget loads the root tx metadata used by the shared
// invalidation workflow.
func (o pgInvalidateUnminedTxOps) LoadInvalidateTarget(ctx context.Context,
	walletID uint32, txHash chainhash.Hash) (db.InvalidateUnminedTxTarget, error) {

	row, err := o.qtx.GetTransactionMetaByHash(
		ctx, sqlcpg.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return db.InvalidateUnminedTxTarget{}, fmt.Errorf("tx %s: %w", txHash,
				db.ErrTxNotFound)
		}

		return db.InvalidateUnminedTxTarget{}, fmt.Errorf("get tx metadata: %w",
			err)
	}

	status, err := db.ParseTxStatus(int64(row.TxStatus))
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
func (o pgInvalidateUnminedTxOps) ListUnminedTxRecords(
	ctx context.Context, walletID int64) ([]db.UnminedTxRecord, error) {

	rows, err := o.qtx.ListUnminedTransactions(ctx, walletID)
	if err != nil {
		return nil, fmt.Errorf("list unmined txns: %w", err)
	}

	return db.BuildUnminedTxRecords(rows,
		func(row sqlcpg.ListUnminedTransactionsRow) (int64, []byte, []byte) {
			return row.ID, row.TxHash, row.RawTx
		},
	)
}

// ClearSpentUtxos restores any wallet-owned parent outputs spent by the given
// transaction row.
func (o pgInvalidateUnminedTxOps) ClearSpentUtxos(ctx context.Context,
	walletID int64, txID int64) error {

	_, err := o.qtx.ClearUtxosSpentByTxID(
		ctx, sqlcpg.ClearUtxosSpentByTxIDParams{
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
func (o pgInvalidateUnminedTxOps) MarkTxnsFailed(
	ctx context.Context, walletID int64, txIDs []int64) error {

	_, err := o.qtx.UpdateTransactionStatusByIDs(
		ctx, sqlcpg.UpdateTransactionStatusByIDsParams{
			WalletID: walletID,
			Status:   int16(db.TxStatusFailed),
			TxIds:    txIDs,
		},
	)
	if err != nil {
		return fmt.Errorf("mark txns failed: %w", err)
	}

	return nil
}
