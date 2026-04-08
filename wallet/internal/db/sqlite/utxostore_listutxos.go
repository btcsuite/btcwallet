package sqlite

import (
	"context"
	"fmt"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"

	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// ListUTXOs lists all current wallet-owned UTXOs matching the caller filters.
//
// The result set is already constrained to outputs whose creating
// transactions are still in `pending` or `published` status.
func (s *SqliteStore) ListUTXOs(ctx context.Context,
	query db.ListUtxosQuery) ([]db.UtxoInfo, error) {

	rows, err := s.queries.ListUtxos(ctx, sqlcsqlite.ListUtxosParams{
		WalletID:      int64(query.WalletID),
		AccountNumber: db.NullableUint32ToSQLInt64(query.Account),
		MinConfirms:   db.NullableInt32ToSQLInt64(query.MinConfs),
		MaxConfirms:   db.NullableInt32ToSQLInt64(query.MaxConfs),
	})
	if err != nil {
		return nil, fmt.Errorf("list utxos: %w", err)
	}

	utxos := make([]db.UtxoInfo, len(rows))
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
