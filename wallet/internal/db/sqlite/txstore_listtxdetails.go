package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// ListTxDetails lists detailed wallet-scoped transaction views using wallet
// tx-reader range semantics.
func (s *Store) ListTxDetails(ctx context.Context,
	query db.ListTxDetailsQuery) ([]db.TxDetailInfo, error) {

	var details []db.TxDetailInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		var err error

		details, err = db.ListTxDetailsWithOps(ctx, query, &listTxDetailsOps{
			txDetailEdgesOps: txDetailEdgesOps{q: q},
		})

		return err
	})
	if err != nil {
		return nil, err
	}

	return details, nil
}

// listTxDetailsOps adapts sqlite sqlc queries to the shared ListTxDetails flow.
type listTxDetailsOps struct {
	txDetailEdgesOps
}

var _ db.ListTxDetailsOps = (*listTxDetailsOps)(nil)

// ListUnmined loads every transaction row that currently has no confirming
// block. This includes the active unmined set together with any retained
// invalid history that rollback or invalidation flows left without a confirming
// block.
func (o *listTxDetailsOps) ListUnmined(ctx context.Context,
	walletID uint32) ([]db.TxDetailBase, error) {

	rows, err := o.q.ListTransactionsWithoutBlock(ctx, int64(walletID))
	if err != nil {
		return nil, fmt.Errorf("list tx details without block: %w", err)
	}

	bases := make([]db.TxDetailBase, len(rows))
	for i, row := range rows {
		bases[i] = db.TxDetailBase{
			ID:       row.ID,
			Hash:     row.TxHash,
			RawTx:    row.RawTx,
			Received: row.ReceivedTime,
			Status:   row.TxStatus,
			Label:    row.TxLabel,
		}
	}

	return bases, nil
}

// ListConfirmed loads the confirmed height-range view used by ListTxDetails
// when callers query mined history.
func (o *listTxDetailsOps) ListConfirmed(ctx context.Context, walletID uint32,
	startHeight, endHeight int32, reverse bool) ([]db.TxDetailBase, error) {

	rows, err := o.q.ListTransactionsByHeightRange(
		ctx, sqlc.ListTransactionsByHeightRangeParams{
			WalletID:    int64(walletID),
			StartHeight: int64(startHeight),
			EndHeight:   int64(endHeight),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list confirmed tx details: %w", err)
	}

	bases := make([]db.TxDetailBase, len(rows))
	for i, row := range rows {
		block, err := buildBlock(
			row.BlockHeight, row.BlockHash,
			sql.NullInt64{Int64: row.BlockTimestamp, Valid: true},
		)
		if err != nil {
			return nil, err
		}

		bases[i] = db.TxDetailBase{
			ID:       row.ID,
			Hash:     row.TxHash,
			RawTx:    row.RawTx,
			Received: row.ReceivedTime,
			Block:    block,
			Status:   row.TxStatus,
			Label:    row.TxLabel,
		}
	}

	if reverse {
		db.ReverseTxDetailBasesByBlock(bases)
	}

	return bases, nil
}
