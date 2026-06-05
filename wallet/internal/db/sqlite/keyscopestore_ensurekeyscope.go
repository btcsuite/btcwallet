package sqlite

import (
	"context"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// ensureKeyScope retrieves an existing key scope or creates it if missing
// for SQLite. It returns the scope ID together with the persisted schema.
func ensureKeyScope(ctx context.Context, qtx *sqlc.Queries, walletID uint32,
	scope db.KeyScope, addrSchema *db.ScopeAddrSchema) (int64,
	db.ScopeAddrSchema, error) {

	scopeID, err := db.EnsureKeyScopeWithOps(
		ctx, sqliteEnsureKeyScopeOps{q: qtx}, walletID, scope, addrSchema,
	)
	if err != nil {
		return 0, db.ScopeAddrSchema{}, err
	}

	persistedSchema, err := getPersistedKeyScopeSchema(
		ctx, qtx, walletID, scope,
	)
	if err != nil {
		return 0, db.ScopeAddrSchema{}, err
	}

	return scopeID, persistedSchema, nil
}

// getPersistedKeyScopeSchema returns the address schema currently stored for
// the wallet/scope pair.
func getPersistedKeyScopeSchema(ctx context.Context, qtx *sqlc.Queries,
	walletID uint32, scope db.KeyScope) (db.ScopeAddrSchema, error) {

	row, err := qtx.GetKeyScopeByWalletAndScope(
		ctx, sqlc.GetKeyScopeByWalletAndScopeParams{
			WalletID: int64(walletID),
			Purpose:  int64(scope.Purpose),
			CoinType: int64(scope.Coin),
		},
	)
	if err != nil {
		return db.ScopeAddrSchema{}, err
	}

	return db.DerivedAddressAccountSchema(
		row.InternalTypeID, row.ExternalTypeID,
	)
}

// sqliteEnsureKeyScopeOps adapts SQLite sqlc queries to the shared
// EnsureKeyScopeWithOps workflow.
type sqliteEnsureKeyScopeOps struct {
	q *sqlc.Queries
}

// Verify sqliteEnsureKeyScopeOps implements db.EnsureKeyScopeOps.
var _ db.EnsureKeyScopeOps = sqliteEnsureKeyScopeOps{}

// GetKeyScope implements db.EnsureKeyScopeOps.
func (o sqliteEnsureKeyScopeOps) GetKeyScope(ctx context.Context,
	walletID uint32, scope db.KeyScope) (int64, error) {

	row, err := o.q.GetKeyScopeByWalletAndScope(
		ctx, sqlc.GetKeyScopeByWalletAndScopeParams{
			WalletID: int64(walletID),
			Purpose:  int64(scope.Purpose),
			CoinType: int64(scope.Coin),
		},
	)
	if err != nil {
		return 0, err
	}

	return row.ID, nil
}

// CreateKeyScope implements db.EnsureKeyScopeOps.
func (o sqliteEnsureKeyScopeOps) CreateKeyScope(ctx context.Context,
	walletID uint32, scope db.KeyScope,
	addrSchema db.ScopeAddrSchema) (int64, error) {

	return o.q.CreateKeyScope(
		ctx, sqlc.CreateKeyScopeParams{
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
		},
	)
}
