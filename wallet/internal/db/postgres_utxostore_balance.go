package db

import (
	"context"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// Balance returns the sum of wallet-owned current UTXOs after optional filters.
func (s *PostgresStore) Balance(ctx context.Context,
	params BalanceParams) (BalanceResult, error) {

	nowUTC := time.Now().UTC()

	balance, err := s.queries.Balance(ctx, sqlcpg.BalanceParams{
		NowUtc:           nowUTC,
		WalletID:         int64(params.WalletID),
		AccountNumber:    nullableUint32Int64Pg(params.Account),
		MinConfirms:      nullableInt32Pg(params.MinConfs),
		MaxConfirms:      nullableInt32Pg(params.MaxConfs),
		CoinbaseMaturity: nullableInt32Pg(params.CoinbaseMaturity),
	})
	if err != nil {
		return BalanceResult{}, fmt.Errorf("balance: %w", err)
	}

	return BalanceResult{
		Total:  btcutil.Amount(balance.TotalBalance),
		Locked: btcutil.Amount(balance.LockedBalance),
	}, nil
}
