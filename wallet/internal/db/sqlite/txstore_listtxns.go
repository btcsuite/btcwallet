package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// ListTxns lists wallet-scoped transactions using either the confirmed-range
// or unmined-only read path.
//
// The no-confirming-block path returns every row without a confirming block,
// including retained invalid history such as orphaned or failed transactions,
// while the confirmed path is bounded by the requested height range.
func (s *Store) ListTxns(ctx context.Context,
	query db.ListTxnsQuery) ([]db.TxInfo, error) {

	var txns []db.TxInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		if query.UnminedOnly {
			var err error

			txns, err = s.listTxnsWithoutBlock(ctx, q, query.WalletID)

			return err
		}

		var err error

		txns, err = s.listConfirmedTxns(ctx, q, query)

		return err
	})
	if err != nil {
		return nil, err
	}

	return txns, nil
}

// listTxnsWithoutBlock loads every transaction row that currently has no
// confirming block. This includes the active unmined set together with any
// retained invalid history that rollback or invalidation flows left without a
// confirming block.
func (s *Store) listTxnsWithoutBlock(ctx context.Context,
	q *sqlc.Queries, walletID uint32) ([]db.TxInfo, error) {

	rows, err := q.ListTransactionsWithoutBlock(ctx, int64(walletID))
	if err != nil {
		return nil, fmt.Errorf("list txns without block: %w", err)
	}

	infos := make([]db.TxInfo, len(rows))
	for i, row := range rows {
		info, err := txInfoFromRow(
			row.TxHash, row.RawTx, row.ReceivedTime, row.BlockHeight,
			row.BlockHash, row.BlockTimestamp, row.TxStatus, row.TxLabel,
		)
		if err != nil {
			return nil, err
		}

		infos[i] = *info
	}

	return infos, nil
}

// listConfirmedTxns loads the confirmed height-range view used by
// ListTxns when callers query mined history.
func (s *Store) listConfirmedTxns(ctx context.Context,
	q *sqlc.Queries, query db.ListTxnsQuery) ([]db.TxInfo, error) {

	rows, err := q.ListTransactionsByHeightRange(
		ctx, sqlc.ListTransactionsByHeightRangeParams{
			WalletID:    int64(query.WalletID),
			StartHeight: int64(query.StartHeight),
			EndHeight:   int64(query.EndHeight),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list txns by height: %w", err)
	}

	infos := make([]db.TxInfo, len(rows))
	for i, row := range rows {
		block, err := buildBlock(
			row.BlockHeight,
			row.BlockHash,
			sql.NullInt64{Int64: row.BlockTimestamp, Valid: true},
		)
		if err != nil {
			return nil, err
		}

		info, err := db.BuildTxInfo(
			row.TxHash, row.RawTx, row.ReceivedTime, block, row.TxStatus,
			row.TxLabel,
		)
		if err != nil {
			return nil, err
		}

		infos[i] = *info
	}

	return infos, nil
}
