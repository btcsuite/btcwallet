package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// DeleteTx atomically removes one unmined transaction and restores any wallet
// UTXO rows that it had spent.
//
// DeleteTx is limited to unmined pending/published rows; confirmed rows and
// terminal invalid-history rows remain part of the wallet timeline. The
// transaction must also be a leaf among the wallet's unmined transactions so
// the delete cannot detach child spenders from their parent history.
func (s *PostgresStore) DeleteTx(ctx context.Context,
	params DeleteTxParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcpg.Queries) error {
		return deleteTxWithOps(ctx, params, pgDeleteTxOps{qtx: qtx})
	})
}

// pgDeleteTxOps adapts postgres sqlc queries to the shared DeleteTx flow.
type pgDeleteTxOps struct {
	qtx *sqlcpg.Queries
}

var _ deleteTxOps = (*pgDeleteTxOps)(nil)

// loadDeleteTarget loads and validates the unmined transaction row DeleteTx is
// allowed to remove.
func (o pgDeleteTxOps) loadDeleteTarget(ctx context.Context, walletID uint32,
	txHash chainhash.Hash) (int64, error) {

	meta, err := getDeleteTxMetaPg(ctx, o.qtx, walletID, txHash)
	if err != nil {
		return 0, err
	}

	return meta.ID, nil
}

// ensureLeaf rejects DeleteTx when the target still has direct unmined child
// spenders.
func (o pgDeleteTxOps) ensureLeaf(ctx context.Context, walletID uint32,
	txHash chainhash.Hash, txID int64) error {

	return ensureDeleteLeafPg(ctx, o.qtx, walletID, txHash, txID)
}

// clearSpentUtxos restores any wallet-owned parent outputs the transaction had
// marked spent.
func (o pgDeleteTxOps) clearSpentUtxos(ctx context.Context, walletID uint32,
	txID int64) error {

	_, err := o.qtx.ClearUtxosSpentByTxID(
		ctx,
		sqlcpg.ClearUtxosSpentByTxIDParams{
			WalletID:    int64(walletID),
			SpentByTxID: sql.NullInt64{Int64: txID, Valid: true},
		},
	)
	if err != nil {
		return fmt.Errorf("clear spent utxo rows: %w", err)
	}

	return nil
}

// deleteCreatedUtxos removes any wallet-owned outputs created by the
// transaction being deleted.
func (o pgDeleteTxOps) deleteCreatedUtxos(ctx context.Context,
	walletID uint32, txID int64) error {

	_, err := o.qtx.DeleteUtxosByTxID(
		ctx,
		sqlcpg.DeleteUtxosByTxIDParams{
			WalletID: int64(walletID),
			TxID:     txID,
		},
	)
	if err != nil {
		return fmt.Errorf("delete created utxo rows: %w", err)
	}

	return nil
}

// deleteUnminedTransaction removes the target unmined row after its dependent
// wallet state has been cleaned up.
func (o pgDeleteTxOps) deleteUnminedTransaction(ctx context.Context,
	walletID uint32, txHash chainhash.Hash) (int64, error) {

	rows, err := o.qtx.DeleteUnminedTransactionByHash(
		ctx,
		sqlcpg.DeleteUnminedTransactionByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	if err != nil {
		return 0, fmt.Errorf("delete unmined tx row: %w", err)
	}

	return rows, nil
}

// ensureDeleteLeafPg rejects DeleteTx requests for transactions that still have
// direct unmined child spenders, including children that spend non-credit
// parent outputs.
func ensureDeleteLeafPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, txHash chainhash.Hash, txID int64) error {

	rows, err := qtx.ListUnminedTransactions(ctx, int64(walletID))
	if err != nil {
		return fmt.Errorf("list unmined txns: %w", err)
	}

	candidates, err := buildUnminedTxRecords(rows,
		func(row sqlcpg.ListUnminedTransactionsRow) (int64, []byte, []byte) {
			return row.ID, row.TxHash, row.RawTx
		},
	)
	if err != nil {
		return err
	}

	filtered := candidates[:0]
	for _, candidate := range candidates {
		if candidate.id == txID {
			continue
		}

		filtered = append(filtered, candidate)
	}

	if len(collectDirectChildTxIDs(txHash, filtered)) > 0 {
		return fmt.Errorf("delete tx %s: %w", txHash,
			ErrDeleteRequiresLeaf)
	}

	return nil
}

// getDeleteTxMetaPg loads the transaction metadata DeleteTx needs and enforces
// the unmined precondition up front.
func getDeleteTxMetaPg(ctx context.Context, qtx *sqlcpg.Queries,
	walletID uint32, txHash chainhash.Hash) (
	sqlcpg.GetTransactionMetaByHashRow, error) {

	meta, err := qtx.GetTransactionMetaByHash(
		ctx, sqlcpg.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sqlcpg.GetTransactionMetaByHashRow{},
				fmt.Errorf("tx %s: %w", txHash, ErrTxNotFound)
		}

		return sqlcpg.GetTransactionMetaByHashRow{},
			fmt.Errorf("get tx metadata: %w", err)
	}

	status, err := parseTxStatus(int64(meta.TxStatus))
	if err != nil {
		return sqlcpg.GetTransactionMetaByHashRow{}, err
	}

	if meta.BlockHeight.Valid || !isUnminedStatus(status) {
		return sqlcpg.GetTransactionMetaByHashRow{},
			fmt.Errorf("delete tx %s: %w", txHash,
				ErrDeleteRequiresUnmined)
	}

	return meta, nil
}
