package db

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// Balance returns the sum of wallet-owned current UTXOs after optional filters.
func (s *SqliteStore) Balance(ctx context.Context,
	params BalanceParams) (BalanceResult, error) {

	nowUTC := time.Now().UTC()

	balance, err := s.queries.Balance(ctx, sqlcsqlite.BalanceParams{
		NowUtc:           nowUTC,
		WalletID:         int64(params.WalletID),
		AccountNumber:    NullableUint32ToSQLInt64(params.Account),
		MinConfirms:      NullableInt32ToSQLInt64(params.MinConfs),
		MaxConfirms:      NullableInt32ToSQLInt64(params.MaxConfs),
		CoinbaseMaturity: NullableInt32ToSQLInt64(params.CoinbaseMaturity),
	})
	if err != nil {
		return BalanceResult{}, fmt.Errorf("balance: %w", err)
	}

	return BalanceResult{
		Total:  btcutil.Amount(balance.TotalBalance),
		Locked: btcutil.Amount(balance.LockedBalance),
	}, nil
}
