package sqlite

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// ListUTXOs lists all current wallet-owned UTXOs matching the caller filters.
//
// The result set is already constrained to outputs whose creating
// transactions are still in `pending` or `published` status.
func (s *Store) ListUTXOs(ctx context.Context,
	query db.ListUtxosQuery) ([]db.UtxoInfo, error) {

	var utxos []db.UtxoInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		rows, err := q.ListUtxos(ctx, sqlc.ListUtxosParams{
			WalletID:      int64(query.WalletID),
			AccountNumber: db.NullableUint32ToSQLInt64(query.Account),
			MinConfirms:   db.NullableInt32ToSQLInt64(query.MinConfs),
			MaxConfirms:   db.NullableInt32ToSQLInt64(query.MaxConfs),
		})
		if err != nil {
			return fmt.Errorf("list utxos: %w", err)
		}

		utxos = make([]db.UtxoInfo, len(rows))
		for i, row := range rows {
			utxo, err := utxoInfoFromRow(
				row.TxHash, row.OutputIndex, row.Amount, row.ScriptPubKey,
				row.ReceivedTime, row.IsCoinbase, row.BlockHeight,
			)
			if err != nil {
				return err
			}

			utxos[i] = *utxo
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return utxos, nil
}
