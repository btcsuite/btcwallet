package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// DeleteTx atomically removes one unmined transaction and restores any wallet
// UTXO rows that it had spent.
//
// DeleteTx is limited to unmined pending/published rows; confirmed rows and
// terminal invalid-history rows remain part of the wallet timeline. The
// transaction must also be a leaf among the wallet's unmined transactions so
// the delete cannot detach child spenders from their parent history.
func (s *Store) DeleteTx(ctx context.Context,
	params db.DeleteTxParams) error {

	return s.ExecuteTx(ctx, func(qtx *sqlc.Queries) error {
		return db.DeleteTxWithOps(ctx, params, deleteTxOps{qtx: qtx})
	})
}

// deleteTxOps adapts sqlite sqlc queries to the shared DeleteTx flow.
type deleteTxOps struct {
	qtx *sqlc.Queries
}

var _ db.DeleteTxOps = (*deleteTxOps)(nil)

// LoadDeleteTarget loads and validates the unmined transaction row DeleteTx is
// allowed to remove.
func (o deleteTxOps) LoadDeleteTarget(ctx context.Context,
	walletID uint32, txHash chainhash.Hash) (int64, error) {

	meta, err := getDeleteTxMeta(ctx, o.qtx, walletID, txHash)
	if err != nil {
		return 0, err
	}

	return meta.ID, nil
}

// EnsureLeaf rejects DeleteTx when the target still has direct unmined child
// spenders.
func (o deleteTxOps) EnsureLeaf(ctx context.Context, walletID uint32,
	txHash chainhash.Hash, txID int64) error {

	return ensureDeleteLeaf(ctx, o.qtx, walletID, txHash, txID)
}

// ClearSpentUtxos restores any wallet-owned parent outputs the transaction had
// marked spent.
func (o deleteTxOps) ClearSpentUtxos(ctx context.Context,
	walletID uint32, txID int64) error {

	_, err := o.qtx.ClearUtxosSpentByTxID(
		ctx,
		sqlc.ClearUtxosSpentByTxIDParams{
			WalletID:    int64(walletID),
			SpentByTxID: sql.NullInt64{Int64: txID, Valid: true},
		},
	)
	if err != nil {
		return fmt.Errorf("clear spent utxo rows: %w", err)
	}

	return nil
}

// DeleteCreatedUtxos removes any wallet-owned outputs created by the
// transaction being deleted.
func (o deleteTxOps) DeleteCreatedUtxos(ctx context.Context,
	walletID uint32, txID int64) error {

	_, err := o.qtx.DeleteUtxosByTxID(
		ctx,
		sqlc.DeleteUtxosByTxIDParams{
			WalletID: int64(walletID),
			TxID:     txID,
		},
	)
	if err != nil {
		return fmt.Errorf("delete created utxo rows: %w", err)
	}

	return nil
}

// DeleteUnminedTransaction removes the target unmined row after its dependent
// wallet state has been cleaned up.
func (o deleteTxOps) DeleteUnminedTransaction(ctx context.Context,
	walletID uint32, txHash chainhash.Hash) (int64, error) {

	rows, err := o.qtx.DeleteUnminedTransactionByHash(
		ctx,
		sqlc.DeleteUnminedTransactionByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	if err != nil {
		return 0, fmt.Errorf("delete unmined tx row: %w", err)
	}

	return rows, nil
}

// ensureDeleteLeaf rejects DeleteTx requests for transactions that still
// have direct unmined child spenders, including children that spend non-credit
// parent outputs.
func ensureDeleteLeaf(ctx context.Context, qtx *sqlc.Queries,
	walletID uint32, txHash chainhash.Hash, txID int64) error {

	rows, err := qtx.ListUnminedTransactions(ctx, int64(walletID))
	if err != nil {
		return fmt.Errorf("list unmined txns: %w", err)
	}

	candidates, err := db.BuildUnminedTxRecords(
		rows,
		func(row sqlc.ListUnminedTransactionsRow) (int64,
			[]byte, []byte) {

			return row.ID, row.TxHash, row.RawTx
		},
	)
	if err != nil {
		return err
	}

	filtered := candidates[:0]
	for _, candidate := range candidates {
		if candidate.ID == txID {
			continue
		}

		filtered = append(filtered, candidate)
	}

	if len(db.CollectDirectChildTxIDs(txHash, filtered)) > 0 {
		return fmt.Errorf("delete tx %s: %w", txHash,
			db.ErrDeleteRequiresLeaf)
	}

	return nil
}

// getDeleteTxMeta loads the transaction metadata DeleteTx needs and
// enforces the unmined precondition up front.
func getDeleteTxMeta(ctx context.Context, qtx *sqlc.Queries,
	walletID uint32, txHash chainhash.Hash) (
	sqlc.GetTransactionMetaByHashRow, error) {

	meta, err := qtx.GetTransactionMetaByHash(
		ctx, sqlc.GetTransactionMetaByHashParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sqlc.GetTransactionMetaByHashRow{},
				fmt.Errorf("tx %s: %w", txHash, db.ErrTxNotFound)
		}

		return sqlc.GetTransactionMetaByHashRow{},
			fmt.Errorf("get tx metadata: %w", err)
	}

	status, err := db.ParseTxStatus(meta.TxStatus)
	if err != nil {
		return sqlc.GetTransactionMetaByHashRow{}, err
	}

	if meta.BlockHeight.Valid || !db.IsUnminedStatus(status) {
		return sqlc.GetTransactionMetaByHashRow{},
			fmt.Errorf("delete tx %s: %w", txHash,
				db.ErrDeleteRequiresUnmined)
	}

	return meta, nil
}
