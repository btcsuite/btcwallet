package db

import (
	"context"
	"database/sql"
	"fmt"

	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// ListTxns lists wallet-scoped transactions using either the confirmed-range
// or unmined-only read path.
//
// The no-confirming-block path returns every row without a confirming block,
// including retained invalid history such as orphaned or failed transactions,
// while the confirmed path is bounded by the requested height range.
func (s *SqliteStore) ListTxns(ctx context.Context,
	query ListTxnsQuery) ([]TxInfo, error) {

	if query.UnminedOnly {
		return s.listTxnsWithoutBlockSqlite(ctx, query.WalletID)
	}

	return s.listConfirmedTxnsSqlite(ctx, query)
}

// listTxnsWithoutBlockSqlite loads every transaction row that currently has no
// confirming block. This includes the active unmined set together with any
// retained invalid history that rollback or invalidation flows left without a
// confirming block.
func (s *SqliteStore) listTxnsWithoutBlockSqlite(ctx context.Context,
	walletID uint32) ([]TxInfo, error) {

	rows, err := s.queries.ListTransactionsWithoutBlock(ctx, int64(walletID))
	if err != nil {
		return nil, fmt.Errorf("list txns without block: %w", err)
	}

	infos := make([]TxInfo, len(rows))
	for i, row := range rows {
		info, err := txInfoFromSqliteRow(
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

// listConfirmedTxnsSqlite loads the confirmed height-range view used by
// ListTxns when callers query mined history.
func (s *SqliteStore) listConfirmedTxnsSqlite(ctx context.Context,
	query ListTxnsQuery) ([]TxInfo, error) {

	rows, err := s.queries.ListTransactionsByHeightRange(
		ctx, sqlcsqlite.ListTransactionsByHeightRangeParams{
			WalletID:    int64(query.WalletID),
			StartHeight: int64(query.StartHeight),
			EndHeight:   int64(query.EndHeight),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list txns by height: %w", err)
	}

	infos := make([]TxInfo, len(rows))
	for i, row := range rows {
		block, err := buildSqliteBlock(
			row.BlockHeight,
			row.BlockHash,
			sql.NullInt64{Int64: row.BlockTimestamp, Valid: true},
		)
		if err != nil {
			return nil, err
		}

		info, err := BuildTxInfo(
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
