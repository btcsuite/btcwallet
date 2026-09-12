package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// GetAddress retrieves information about a specific address, identified by
// its script pubkey.
func (s *Store) GetAddress(ctx context.Context,
	query db.GetAddressQuery) (*db.AddressInfo, error) {

	err := query.Validate()
	if err != nil {
		return nil, err
	}

	var info *db.AddressInfo

	err = s.execRead(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetAddressByScriptPubKey(
			ctx, sqlc.GetAddressByScriptPubKeyParams{
				ScriptPubKey: query.ScriptPubKey,
				WalletID:     int64(query.WalletID),
			},
		)
		if errors.Is(err, sql.ErrNoRows) {
			return db.ErrAddressNotFound
		}

		if err != nil {
			return fmt.Errorf("get address: %w", err)
		}

		info, err = addressRowToInfo(row)

		return err
	})
	if err != nil {
		return nil, err
	}

	return info, nil
}
