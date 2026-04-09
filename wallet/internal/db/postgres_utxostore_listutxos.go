package db

import (
	"context"
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
		AccountNumber: NullableUint32ToSQLInt64(query.Account),
		MinConfirms:   NullableInt32ToSQLInt32(query.MinConfs),
		MaxConfirms:   NullableInt32ToSQLInt32(query.MaxConfs),
	}
}
