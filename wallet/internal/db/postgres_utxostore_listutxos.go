package db

import (
	"context"
	"database/sql"
	"fmt"

	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// ListUTXOs lists all current wallet-owned UTXOs matching the caller filters.
//
// The result set is already constrained to outputs whose creating
// transactions are still in `pending` or `published` status.
func (s *PostgresStore) ListUTXOs(ctx context.Context,
	query ListUtxosQuery) ([]UtxoInfo, error) {

	rows, err := s.queries.ListUtxos(ctx, buildListUtxosParamsPg(query))
	if err != nil {
		return nil, fmt.Errorf("list utxos: %w", err)
	}

	utxos := make([]UtxoInfo, len(rows))
	for i, row := range rows {
		utxo, err := utxoInfoFromPgRow(
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

// buildListUtxosParamsPg prepares the typed nullable filters required by the
// postgres ListUtxos query.
func buildListUtxosParamsPg(query ListUtxosQuery) sqlcpg.ListUtxosParams {
	return sqlcpg.ListUtxosParams{
		WalletID:      int64(query.WalletID),
		AccountNumber: nullableUint32Int64Pg(query.Account),
		MinConfirms:   nullableInt32Pg(query.MinConfs),
		MaxConfirms:   nullableInt32Pg(query.MaxConfs),
	}
}

// nullableUint32Int64Pg converts an optional uint32 filter into the typed null
// form used by postgres sqlc queries.
func nullableUint32Int64Pg(value *uint32) sql.NullInt64 {
	if value == nil {
		return sql.NullInt64{}
	}

	return sql.NullInt64{Int64: int64(*value), Valid: true}
}

// nullableInt32Pg converts an optional int32 filter into the typed null form
// used by postgres sqlc queries.
func nullableInt32Pg(value *int32) sql.NullInt32 {
	if value == nil {
		return sql.NullInt32{}
	}

	return sql.NullInt32{Int32: *value, Valid: true}
}
