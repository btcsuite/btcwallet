package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// GetAddressSecret retrieves the encrypted secret information for an address.
func (s *Store) GetAddressSecret(ctx context.Context,
	query db.GetAddressSecretQuery) (*db.AddressSecret, error) {

	err := query.Validate()
	if err != nil {
		return nil, err
	}

	var secret *db.AddressSecret

	err = s.execRead(ctx, func(q *sqlc.Queries) error {
		if query.AddressID != nil {
			row, err := q.GetAddressSecretByID(
				ctx, sqlc.GetAddressSecretByIDParams{
					WalletID: int64(query.WalletID),
					ID:       int64(*query.AddressID),
				},
			)
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("address secret for wallet %d "+
					"address %d: %w", query.WalletID,
					*query.AddressID, db.ErrAddressNotFound)
			}

			if err != nil {
				return fmt.Errorf("get address secret by ID: %w", err)
			}

			secret, err = addressSecretByIDRowToSecret(row)

			return err
		}

		row, err := q.GetAddressSecret(
			ctx, sqlc.GetAddressSecretParams{
				WalletID:     int64(query.WalletID),
				ScriptPubKey: query.ScriptPubKey,
			},
		)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("address secret for wallet %d "+
				"script %x: %w", query.WalletID,
				query.ScriptPubKey, db.ErrAddressNotFound)
		}

		if err != nil {
			return fmt.Errorf("get address secret: %w", err)
		}

		secret, err = addressSecretRowToSecret(row)

		return err
	})
	if err != nil {
		return nil, err
	}

	return secret, nil
}
