package pg

import (
	"context"

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

// DeleteCreatedUtxos removes the wallet-owned outputs the given transaction
// row created.
func (o deleteUnminedTxOps) DeleteCreatedUtxos(ctx context.Context,
	walletID uint32, txID int64) error {

	return o.rows.DeleteCreatedUtxos(ctx, walletID, txID)
}

// DeleteUnminedTransaction removes one unmined transaction row.
func (o deleteUnminedTxOps) DeleteUnminedTransaction(ctx context.Context,
	walletID uint32, txHash chainhash.Hash) (int64, error) {

	return o.rows.DeleteUnminedTransaction(ctx, walletID, txHash)
}
