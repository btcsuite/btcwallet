package sqlite

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// ListUTXOs lists all current wallet-owned UTXOs matching the caller filters.
//
// The result set is already constrained to outputs whose creating
// transactions are still in `pending` or `published` status. Enrichment
// columns (account name + origin, address type, has-script bit, lease
// status) are populated by the same query.
func (s *Store) ListUTXOs(ctx context.Context,
	query db.ListUtxosQuery) ([]db.UtxoInfo, error) {

	var utxos []db.UtxoInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		rows, err := q.ListUtxos(ctx, sqlc.ListUtxosParams{
			NowUtc:        time.Now().UTC(),
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
				row.TxHash, row.OutputIndex, row.Amount,
				row.ScriptPubKey, row.ReceivedTime, row.IsCoinbase,
				row.BlockHeight,
			)
			if err != nil {
				return err
			}

			err = applyListRowEnrichment(utxo, row)
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

// applyListRowEnrichment derives and sets the per-row UTXO enrichment
// fields (account name + origin, address type, has-script bit, lease
// status) on utxo from a ListUtxos result row.
func applyListRowEnrichment(utxo *db.UtxoInfo,
	row sqlc.ListUtxosRow) error {

	origin, err := db.IDToAccountOrigin[int64](row.OriginID)
	if err != nil {
		return fmt.Errorf("origin: %w", err)
	}

	addrType, err := db.IDToAddressType(row.TypeID)
	if err != nil {
		return fmt.Errorf("addr type: %w", err)
	}

	keyScope, err := db.KeyScopeFromIDs(row.Purpose, row.CoinType)
	if err != nil {
		return fmt.Errorf("key scope: %w", err)
	}

	utxo.AccountName = row.AccountName
	utxo.Origin = origin
	utxo.AddrType = addrType
	utxo.HasScript = row.HasScript
	utxo.IsLocked = row.IsLocked != 0
	utxo.KeyScope = keyScope

	return nil
}
