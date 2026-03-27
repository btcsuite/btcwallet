package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// InvalidateUnminedTx atomically invalidates one wallet-owned unmined
// transaction branch and marks the root plus descendants failed.
func (s *SqliteStore) InvalidateUnminedTx(ctx context.Context,
	params InvalidateUnminedTxParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		return invalidateUnminedTxWithOps(
			ctx, params, sqliteInvalidateUnminedTxOps{qtx: qtx},
		)
	})
}

// sqliteInvalidateUnminedTxOps adapts sqlite sqlc queries to the shared
// InvalidateUnminedTx workflow.
type sqliteInvalidateUnminedTxOps struct {
	qtx *sqlcsqlite.Queries
}

var _ invalidateUnminedTxOps = (*sqliteInvalidateUnminedTxOps)(nil)

// loadInvalidateTarget loads the root tx metadata used by the shared
// invalidation workflow.
func (o sqliteInvalidateUnminedTxOps) loadInvalidateTarget(ctx context.Context,
	walletID uint32, txHash chainhash.Hash) (invalidateUnminedTxTarget, error) {

	row, err := o.qtx.GetTransactionMetaByHash(
		ctx, sqlcsqlite.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return invalidateUnminedTxTarget{}, fmt.Errorf("tx %s: %w", txHash,
				ErrTxNotFound)
		}

		return invalidateUnminedTxTarget{}, fmt.Errorf("get tx metadata: %w",
			err)
	}

	status, err := parseTxStatus(row.TxStatus)
	if err != nil {
		return invalidateUnminedTxTarget{}, err
	}

	return invalidateUnminedTxTarget{
		id:         row.ID,
		txHash:     txHash,
		status:     status,
		hasBlock:   row.BlockHeight.Valid,
		isCoinbase: row.IsCoinbase,
	}, nil
}

// listUnminedTxRecords loads and decodes the wallet's active unmined
// transaction rows.
func (o sqliteInvalidateUnminedTxOps) listUnminedTxRecords(
	ctx context.Context, walletID int64) ([]unminedTxRecord, error) {

	rows, err := o.qtx.ListUnminedTransactions(ctx, walletID)
	if err != nil {
		return nil, fmt.Errorf("list unmined txns: %w", err)
	}

	return buildUnminedTxRecords(
		rows, func(row sqlcsqlite.ListUnminedTransactionsRow) (
			int64, []byte, []byte) {

			return row.ID, row.TxHash, row.RawTx
		},
	)
}

// clearSpentUtxos restores any wallet-owned parent outputs spent by the given
// transaction row.
func (o sqliteInvalidateUnminedTxOps) clearSpentUtxos(ctx context.Context,
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

// markTxnsFailed marks the provided tx rows failed in one
// batch update.
func (o sqliteInvalidateUnminedTxOps) markTxnsFailed(
	ctx context.Context, walletID int64, txIDs []int64) error {

	_, err := o.qtx.UpdateTransactionStatusByIDs(
		ctx, sqlcsqlite.UpdateTransactionStatusByIDsParams{
			WalletID: walletID,
			Status:   int64(TxStatusFailed),
			TxIds:    txIDs,
		},
	)
	if err != nil {
		return fmt.Errorf("mark txns failed: %w", err)
	}

	return nil
}
