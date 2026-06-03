package sqlite

import (
	"context"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// ensureKeyScope retrieves an existing key scope or creates it if missing
// for SQLite. It returns the scope ID once available.
func ensureKeyScope(ctx context.Context, qtx *sqlc.Queries,
	walletID uint32, scope db.KeyScope,
	addrSchema *db.ScopeAddrSchema) (int64, db.ScopeAddrSchema, error) {

	return db.EnsureKeyScope(
		ctx, qtx.GetKeyScopeByWalletAndScope,
		sqlc.GetKeyScopeByWalletAndScopeParams{
			WalletID: int64(walletID),
			Purpose:  int64(scope.Purpose),
			CoinType: int64(scope.Coin),
		}, qtx.CreateKeyScope,
		func(addrSchema db.ScopeAddrSchema) sqlc.CreateKeyScopeParams {
			return sqlc.CreateKeyScopeParams{
				WalletID:   int64(walletID),
				Purpose:    int64(scope.Purpose),
				CoinType:   int64(scope.Coin),
				CoinPubKey: nil,
				InternalTypeID: int64(
					addrSchema.InternalAddrType,
				),
				ExternalTypeID: int64(
					addrSchema.ExternalAddrType,
				),
			}
		},
		func(row sqlc.GetKeyScopeByWalletAndScopeRow) int64 {
			return row.ID
		},
		func(row sqlc.GetKeyScopeByWalletAndScopeRow) (
			db.ScopeAddrSchema, error) {

			return db.DerivedAddressAccountSchema(
				row.InternalTypeID, row.ExternalTypeID,
			)
		},
		scope, addrSchema,
	)
}
