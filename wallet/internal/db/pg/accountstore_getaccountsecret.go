package pg

import (
	"context"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
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
			AccountNumber: db.NullableUint32ToSQLInt64(
				&query.AccountNumber,
			),
		})
		if err != nil {
			return db.MapGetAccountSecretErr(err, query)
		}

		secret = &db.AccountSecret{EncryptedPrivateKey: row}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return secret, nil
}
