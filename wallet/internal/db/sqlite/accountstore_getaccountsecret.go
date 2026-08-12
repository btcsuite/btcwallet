package sqlite

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// GetAccountSecret retrieves encrypted account-level signing material for one
// account.
func (s *Store) GetAccountSecret(ctx context.Context,
	query db.GetAccountSecretQuery) (*db.AccountSecret, error) {

	var secret *db.AccountSecret

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		row, err := q.GetAccountSecret(ctx, sqlc.GetAccountSecretParams{
			WalletID: int64(query.WalletID),
			Purpose:  int64(query.Scope.Purpose),
			CoinType: int64(query.Scope.Coin),
			AccountNumber: nullableInt64FromUint32(
				&query.AccountNumber,
			),
		})
		if err != nil {
			if !isNoRows(err) {
				return fmt.Errorf("get account secret: %w", err)
			}

			return fmt.Errorf("account %d in scope %d/%d: %w",
				query.AccountNumber, query.Scope.Purpose,
				query.Scope.Coin, db.ErrAccountNotFound)
		}

		secret = &db.AccountSecret{EncryptedPrivateKey: row}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return secret, nil
}
