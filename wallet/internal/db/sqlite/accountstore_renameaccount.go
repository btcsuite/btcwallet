package sqlite

import (
	"context"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// RenameAccount changes the name of an account. The account can be identified
// by its old name or its account number.
func (s *Store) RenameAccount(ctx context.Context,
	params db.RenameAccountParams) error {

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		renameOps := accountRenameOps{q: qtx}
		return db.RenameAccountWithOps(ctx, params, renameOps)
	})
}

// accountRenameOps implements db.RenameAccountOps for SQLite.
type accountRenameOps struct {
	q *sqlc.Queries
}

// RenameByNumber renames an account identified by wallet ID, scope, and
// account number. It returns the number of rows affected.
func (s accountRenameOps) RenameByNumber(ctx context.Context,
	params db.RenameAccountParams) (int64, error) {

	return s.q.UpdateAccountNameByWalletScopeAndNumber(ctx,
		sqlc.UpdateAccountNameByWalletScopeAndNumberParams{
			NewName:       params.NewName,
			WalletID:      int64(params.WalletID),
			Purpose:       int64(params.Scope.Purpose),
			CoinType:      int64(params.Scope.Coin),
			AccountNumber: db.NullableUint32ToSQLInt64(params.AccountNumber),
		},
	)
}

// RenameByName renames an account identified by wallet ID, scope, and old
// account name. It returns the number of rows affected.
func (s accountRenameOps) RenameByName(ctx context.Context,
	params db.RenameAccountParams) (int64, error) {

	return s.q.UpdateAccountNameByWalletScopeAndName(ctx,
		sqlc.UpdateAccountNameByWalletScopeAndNameParams{
			NewName:  params.NewName,
			WalletID: int64(params.WalletID),
			Purpose:  int64(params.Scope.Purpose),
			CoinType: int64(params.Scope.Coin),
			OldName:  params.OldName,
		},
	)
}
