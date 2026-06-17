package pg

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// ListUTXOs lists all current wallet-owned UTXOs matching the caller filters.
//
// The result set is already constrained to outputs whose creating
// transactions are still in `pending` or `published` status. Enrichment
// columns (account name, address type, has-script bit, lease status) are
// populated by the same query.
func (s *Store) ListUTXOs(ctx context.Context,
	query db.ListUtxosQuery) ([]db.UtxoInfo, error) {

	err := query.Validate()
	if err != nil {
		return nil, err
	}

	var utxos []db.UtxoInfo

	err = s.execRead(ctx, func(q *sqlc.Queries) error {
		rows, err := q.ListUtxos(ctx, buildListUtxosParams(query))
		if err != nil {
			return fmt.Errorf("list utxos: %w", err)
		}

		utxos = make([]db.UtxoInfo, len(rows))
		for i, row := range rows {
			err = db.ValidateUtxoAddressShape(db.UtxoAddressShape{
				IsDerived:        row.AddressIsDerived,
				DerivedAddressID: row.DerivedAddressID,
				AccountID:        row.AccountID,
				AccountIsDerived: row.AccountIsDerived,
				AccountNumber:    row.AccountNumber,
			})
			if err != nil {
				return err
			}

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

// buildListUtxosParams prepares the typed nullable filters required by the
// postgres ListUtxos query. The NowUtc argument feeds the lease-expiration
// check the query performs in SQL, in line with the existing Balance /
// lease-query convention this repo follows.
func buildListUtxosParams(query db.ListUtxosQuery) sqlc.ListUtxosParams {
	purpose, coinType := db.ScopeFilter(query.Scope)

	return sqlc.ListUtxosParams{
		NowUtc:        time.Now().UTC(),
		WalletID:      int64(query.WalletID),
		Purpose:       purpose,
		CoinType:      coinType,
		AccountNumber: db.NullableUint32ToSQLInt64(query.Account),
		AccountName:   db.NullableStringToSQLNullString(query.AccountName),
		MinConfirms:   db.NullableInt32ToSQLInt32(query.MinConfs),
		MaxConfirms:   db.NullableInt32ToSQLInt32(query.MaxConfs),
	}
}

// applyListRowEnrichment derives and sets the per-row UTXO enrichment
// fields (account name, address type, has-script bit, lease status) on utxo
// from a ListUtxos result row.
func applyListRowEnrichment(utxo *db.UtxoInfo,
	row sqlc.ListUtxosRow) error {

	addrType, err := db.IDToAddressType(row.TypeID)
	if err != nil {
		return fmt.Errorf("addr type: %w", err)
	}

	keyScope, err := db.KeyScopeFromIDs(row.Purpose, row.CoinType)
	if err != nil {
		return fmt.Errorf("key scope: %w", err)
	}

	utxo.AccountName = row.AccountName
	utxo.AddrType = addrType
	utxo.HasScript = row.HasScript
	utxo.IsLocked = row.IsLocked
	utxo.KeyScope = keyScope

	return nil
}
