package pg

import (
	"context"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// ensureKeyScope retrieves an existing key scope or creates it if missing
// for PostgreSQL. It returns the scope ID together with the schema that is
// now persisted for the scope so callers can build AccountInfo from
// authoritative state instead of recomputing from ScopeAddrMap.
func ensureKeyScope(ctx context.Context, qtx *sqlc.Queries, walletID uint32,
	scope db.KeyScope,
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
				InternalTypeID: int16(
					addrSchema.InternalAddrType,
				),
				ExternalTypeID: int16(
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
