package db

import (
	"context"
	"database/sql"
	"fmt"

	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// ListUTXOs lists all current wallet-owned UTXOs matching the caller filters.
//
// The result set is already constrained to outputs whose creating
// transactions are still in `pending` or `published` status.
func (s *SqliteStore) ListUTXOs(ctx context.Context,
	query ListUtxosQuery) ([]UtxoInfo, error) {

	rows, err := s.queries.ListUtxos(ctx, sqlcsqlite.ListUtxosParams{
		WalletID:      int64(query.WalletID),
		AccountNumber: optionalUint32Int64Sqlite(query.Account),
		MinConfirms:   optionalInt32Sqlite(query.MinConfs),
		MaxConfirms:   optionalInt32Sqlite(query.MaxConfs),
	})
	if err != nil {
		return nil, fmt.Errorf("list utxos: %w", err)
	}

	utxos := make([]UtxoInfo, len(rows))
	for i, row := range rows {
		utxo, err := utxoInfoFromSqliteRow(
			row.TxHash, row.OutputIndex, row.Amount, row.ScriptPubKey,
			row.ReceivedTime, row.IsCoinbase, row.BlockHeight,
		)
		if err != nil {
			return nil, err
		}

		utxos[i] = *utxo
	}

	return utxos, nil
}

// optionalUint32Int64Sqlite converts an optional uint32 filter into the typed
// nullable form used by sqlite sqlc queries.
func optionalUint32Int64Sqlite(value *uint32) sql.NullInt64 {
	if value == nil {
		return sql.NullInt64{}
	}

	return sql.NullInt64{Int64: int64(*value), Valid: true}
}

// optionalInt32Sqlite converts an optional int32 filter into the typed nullable
// form used by sqlite sqlc queries.
func optionalInt32Sqlite(value *int32) sql.NullInt64 {
	if value == nil {
		return sql.NullInt64{}
	}

	return sql.NullInt64{Int64: int64(*value), Valid: true}
}
