package pg

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// Balance returns the sum of wallet-owned current UTXOs after optional filters.
func (s *Store) Balance(ctx context.Context,
	params db.BalanceParams) (db.BalanceResult, error) {

	nowUTC := time.Now().UTC()

	var result db.BalanceResult

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		balance, err := q.Balance(ctx, sqlc.BalanceParams{
			NowUtc:        nowUTC,
			WalletID:      int64(params.WalletID),
			AccountNumber: db.NullableUint32ToSQLInt64(params.Account),
			MinConfirms:   db.NullableInt32ToSQLInt32(params.MinConfs),
			MaxConfirms:   db.NullableInt32ToSQLInt32(params.MaxConfs),
			CoinbaseMaturity: db.NullableInt32ToSQLInt32(
				params.CoinbaseMaturity,
			),
		})
		if err != nil {
			return fmt.Errorf("balance: %w", err)
		}

		result = db.BalanceResult{
			Total:  btcutil.Amount(balance.TotalBalance),
			Locked: btcutil.Amount(balance.LockedBalance),
		}

		return nil
	})
	if err != nil {
		return db.BalanceResult{}, err
	}

	return result, nil
}
