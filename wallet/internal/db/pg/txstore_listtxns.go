package pg

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// ListTxns lists wallet-scoped transactions using either the confirmed-range
// or unmined-only read path.
//
// The no-confirming-block path returns every row without a confirming block,
// including retained invalid history such as orphaned or failed transactions,
// while the confirmed path is bounded by the requested height range.
func (s *Store) ListTxns(ctx context.Context,
	query db.ListTxnsQuery) ([]db.TxInfo, error) {

	if query.UnminedOnly {
		return s.listTxnsWithoutBlock(ctx, query.WalletID)
	}

	return s.listConfirmedTxns(ctx, query)
}

// listTxnsWithoutBlock loads every transaction row that currently has no
// confirming block. This includes the active unmined set together with any
// retained invalid history that rollback or invalidation flows left without a
// confirming block.
func (s *Store) listTxnsWithoutBlock(ctx context.Context,
	walletID uint32) ([]db.TxInfo, error) {

	rows, err := s.queries.ListTransactionsWithoutBlock(ctx, int64(walletID))
	if err != nil {
		return nil, fmt.Errorf("list txns without block: %w", err)
	}

	infos := make([]db.TxInfo, len(rows))
	for i, row := range rows {
		info, err := txInfoFromRow(
			row.TxHash, row.RawTx, row.ReceivedTime, row.BlockHeight,
			row.BlockHash, row.BlockTimestamp, int64(row.TxStatus), row.TxLabel,
		)
		if err != nil {
			return nil, err
		}

		infos[i] = *info
	}

	return infos, nil
}

// listConfirmedTxns loads the confirmed height-range view used by ListTxns
// when callers query mined history.
func (s *Store) listConfirmedTxns(ctx context.Context,
	query db.ListTxnsQuery) ([]db.TxInfo, error) {

	startHeight, err := db.Uint32ToInt32(query.StartHeight)
	if err != nil {
		return nil, fmt.Errorf("convert start height: %w", err)
	}

	endHeight, err := db.Uint32ToInt32(query.EndHeight)
	if err != nil {
		return nil, fmt.Errorf("convert end height: %w", err)
	}

	rows, err := s.queries.ListTransactionsByHeightRange(
		ctx, sqlc.ListTransactionsByHeightRangeParams{
			WalletID:    int64(query.WalletID),
			StartHeight: startHeight,
			EndHeight:   endHeight,
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
			row.TxHash, row.RawTx, row.ReceivedTime, block,
			int64(row.TxStatus), row.TxLabel,
		)
		if err != nil {
			return nil, err
		}

		infos[i] = *info
	}

	return infos, nil
}
