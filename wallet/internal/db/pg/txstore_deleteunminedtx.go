package pg

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// DeleteUnminedTx atomically removes one wallet-owned unmined transaction
// branch and restores the wallet outputs it spent.
func (s *Store) DeleteUnminedTx(ctx context.Context,
	params db.DeleteUnminedTxParams) error {

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		return db.DeleteUnminedTxWithOps(ctx, params, deleteUnminedTxOps{
			invalidateUnminedTxOps: invalidateUnminedTxOps{qtx: qtx},
			rows:                   deleteTxOps{qtx: qtx},
		})
	})
}

// deleteUnminedTxOps adapts postgres sqlc queries to the shared
// DeleteUnminedTx workflow by joining the invalidation and DeleteTx
// operations.
type deleteUnminedTxOps struct {
	invalidateUnminedTxOps

	rows deleteTxOps
}

var _ db.DeleteUnminedTxOps = (*deleteUnminedTxOps)(nil)

// ListUnminedTxRecords loads every unmined row, including descendants an
// earlier event already made terminal. Removal must take those with the branch:
// a retained row left behind by its deleted parent would refuse the chain's
// later attempt to record that tx again.
func (o deleteUnminedTxOps) ListUnminedTxRecords(
	ctx context.Context, walletID int64) ([]db.UnminedTxRecord, error) {

	rows, err := o.rows.qtx.ListTransactionsWithoutBlock(ctx, walletID)
	if err != nil {
		return nil, fmt.Errorf("list txns without block: %w", err)
	}

	return db.BuildUnminedTxRecords(
		rows, func(row sqlc.ListTransactionsWithoutBlockRow) (
			int64, []byte, []byte) {

			return row.ID, row.TxHash, row.RawTx
		},
	)
}

// DeleteUnminedTransaction removes one unmined row whatever its status, so a
// descendant an earlier event made terminal leaves with the branch.
func (o deleteUnminedTxOps) DeleteUnminedTransaction(ctx context.Context,
	walletID uint32, txHash chainhash.Hash) (int64, error) {

	rows, err := o.rows.qtx.DeleteUnminedTransactionByHashWithInvalid(
		ctx,
		sqlc.DeleteUnminedTransactionByHashWithInvalidParams{
			WalletID: int64(walletID),
			TxHash:   txHash[:],
		},
	)
	if err != nil {
		return 0, fmt.Errorf("delete unmined tx row: %w", err)
	}

	return rows, nil
}

// DeleteCreatedUtxos removes the wallet-owned outputs the given transaction
// row created.
func (o deleteUnminedTxOps) DeleteCreatedUtxos(ctx context.Context,
	walletID uint32, txID int64) error {

	return o.rows.DeleteCreatedUtxos(ctx, walletID, txID)
}
