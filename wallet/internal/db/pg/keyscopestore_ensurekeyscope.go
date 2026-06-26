package pg

import (
	"context"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// ensureKeyScope retrieves an existing key scope or creates it if missing
// for PostgreSQL. It returns the scope ID together with the persisted schema.
func ensureKeyScope(ctx context.Context, qtx *sqlc.Queries, walletID uint32,
	scope db.KeyScope, addrSchema *db.ScopeAddrSchema) (int64,
	db.ScopeAddrSchema, error) {

	scopeID, err := db.EnsureKeyScopeWithOps(
		ctx, pgEnsureKeyScopeOps{q: qtx}, walletID, scope, addrSchema,
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

// pgEnsureKeyScopeOps adapts PostgreSQL sqlc queries to the shared
// EnsureKeyScopeWithOps workflow.
type pgEnsureKeyScopeOps struct {
	q *sqlc.Queries
}

// Verify pgEnsureKeyScopeOps implements db.EnsureKeyScopeOps.
var _ db.EnsureKeyScopeOps = pgEnsureKeyScopeOps{}

// GetKeyScope implements db.EnsureKeyScopeOps.
func (o pgEnsureKeyScopeOps) GetKeyScope(ctx context.Context, walletID uint32,
	scope db.KeyScope) (int64, error) {

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
func (o pgEnsureKeyScopeOps) CreateKeyScope(ctx context.Context,
	walletID uint32, scope db.KeyScope,
	addrSchema db.ScopeAddrSchema) (int64, error) {

	return o.q.CreateKeyScope(
		ctx, sqlc.CreateKeyScopeParams{
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
		},
	)
}
