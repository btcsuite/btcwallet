package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// Ensure Store satisfies the AccountStore interface.
var _ db.AccountStore = (*Store)(nil)

var (
	errDryRunRollback = errors.New("postgres imported account dry run rollback")
)

// ListAccounts returns a slice of AccountInfo for all accounts, optionally
// filtered by name or key scope.
func (s *Store) ListAccounts(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	var accounts []db.AccountInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		listQueries := accountListQueries{q: q}

		var err error

		accounts, err = db.ListAccountsByQuery(
			ctx, query, listQueries.byScope, listQueries.byName,
			listQueries.all,
		)

		return err
	})
	if err != nil {
		return nil, err
	}

	return accounts, nil
}

// RenameAccount changes the name of an account. The account can be identified
// by its old name or its account number.
func (s *Store) RenameAccount(ctx context.Context,
	params db.RenameAccountParams) error {

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		renameQueries := accountRenameQueries{q: qtx}

		return db.RenameAccountByQuery(
			ctx, params, renameQueries.byNumber, renameQueries.byName,
		)
	})
}

// accountInfoRow is a type constraint for PostgreSQL account info row types
// that share the same field structure. This enables a single generic conversion
// function to handle all account query result types.
type accountInfoRow interface {
	sqlc.GetAccountByScopeAndNameRow |
		sqlc.GetAccountByScopeAndNumberRow |
		sqlc.GetAccountByWalletScopeAndNameRow |
		sqlc.GetAccountByWalletScopeAndNumberRow |
		sqlc.ListAccountsByWalletRow |
		sqlc.ListAccountsByWalletScopeRow |
		sqlc.ListAccountsByWalletAndNameRow
}

// derivedAddressGetAccountID extracts the account ID from a row.
func derivedAddressGetAccountID(
	row sqlc.GetAccountByWalletScopeAndNameRow) int64 {

	return row.ID
}

// derivedAddressGetAccountNumber extracts the derived account number from a
// row.
func derivedAddressGetAccountNumber(
	row sqlc.GetAccountByWalletScopeAndNameRow) (uint32, error) {

	return db.DerivedAddressAccountNumber(row.AccountNumber)
}

// derivedAddressGetWalletWatchOnly extracts the wallet-level watch-only state
// from a row.
func derivedAddressGetWalletWatchOnly(
	row sqlc.GetAccountByWalletScopeAndNameRow) bool {

	return row.WalletIsWatchOnly
}

// derivedAddressGetAccountAddrSchema returns the address schema persisted for
// the account's key scope.
func derivedAddressGetAccountAddrSchema(
	row sqlc.GetAccountByWalletScopeAndNameRow) (db.ScopeAddrSchema,
	error) {

	return db.DerivedAddressAccountSchema(
		row.InternalTypeID, row.ExternalTypeID,
	)
}

// derivedAddressGetAccountPubKey extracts the account public key from a row.
func derivedAddressGetAccountPubKey(
	row sqlc.GetAccountByWalletScopeAndNameRow) []byte {

	return row.PublicKey
}

// importedAddressGetAccountID extracts the account ID from a row.
func importedAddressGetAccountID(
	row sqlc.GetAccountByWalletScopeAndNameRow) int64 {

	return row.ID
}

// importedAddressGetWalletWatchOnly extracts the wallet-level watch-only state
// from a row.
func importedAddressGetWalletWatchOnly(
	row sqlc.GetAccountByWalletScopeAndNameRow) bool {

	return row.WalletIsWatchOnly
}

// accountRowToInfo converts a PostgreSQL account row to an AccountInfo
// struct. It uses type conversion since all accountInfoRow types have
// identical fields.
func accountRowToInfo[T accountInfoRow](row T) (*db.AccountInfo, error) {
	// Direct conversion works only because all constraint types have
	// identical fields. If sqlc types diverge, compilation will fail.
	base := sqlc.GetAccountByScopeAndNameRow(row)

	return db.AccountRowToInfo(
		db.AccountInfoRow[int16]{
			AccountNumber:     base.AccountNumber,
			AccountName:       base.AccountName,
			OriginID:          base.OriginID,
			ExternalKeyCount:  base.ExternalKeyCount,
			InternalKeyCount:  base.InternalKeyCount,
			ImportedKeyCount:  base.ImportedKeyCount,
			PublicKey:         base.PublicKey,
			MasterFingerprint: base.MasterFingerprint,
			IsWatchOnly:       base.IsWatchOnly,
			CreatedAt:         base.CreatedAt,
			Purpose:           base.Purpose,
			CoinType:          base.CoinType,
			InternalTypeID:    base.InternalTypeID,
			ExternalTypeID:    base.ExternalTypeID,
			IDToOriginType:    db.IDToAccountOrigin[int16],
		},
	)
}

// accountListQueries groups PostgreSQL account listing query methods.
type accountListQueries struct {
	q *sqlc.Queries
}

// byScope lists accounts filtered by wallet ID and key scope, then
// attaches each account's balance via AccountBalancesByIDs unless
// query.SkipBalance is set.
func (p accountListQueries) byScope(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	rows, err := p.q.ListAccountsByWalletScope(
		ctx, sqlc.ListAccountsByWalletScopeParams{
			WalletID: int64(query.WalletID),
			Purpose:  int64(query.Scope.Purpose),
			CoinType: int64(query.Scope.Coin),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}

	infos, err := db.ProcessAccountRows(
		rows,
		func(r sqlc.ListAccountsByWalletScopeRow) (*db.AccountInfo, int64,
			error) {

			info, err := accountRowToInfo(r)
			return info, r.ID, err
		},
	)
	if err != nil {
		return nil, err
	}

	return p.attachBalances(ctx, query, infos)
}

// byName lists accounts filtered by wallet ID and account name, then
// attaches each account's balance via AccountBalancesByIDs unless
// query.SkipBalance is set.
func (p accountListQueries) byName(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	rows, err := p.q.ListAccountsByWalletAndName(
		ctx, sqlc.ListAccountsByWalletAndNameParams{
			WalletID:    int64(query.WalletID),
			AccountName: *query.Name,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}

	infos, err := db.ProcessAccountRows(
		rows,
		func(r sqlc.ListAccountsByWalletAndNameRow) (*db.AccountInfo, int64,
			error) {

			info, err := accountRowToInfo(r)
			return info, r.ID, err
		},
	)
	if err != nil {
		return nil, err
	}

	return p.attachBalances(ctx, query, infos)
}

// all lists every account for a wallet, then attaches each account's
// balance via AccountBalancesByIDs unless query.SkipBalance is set.
func (p accountListQueries) all(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	rows, err := p.q.ListAccountsByWallet(ctx, int64(query.WalletID))
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}

	infos, err := db.ProcessAccountRows(
		rows,
		func(r sqlc.ListAccountsByWalletRow) (*db.AccountInfo, int64,
			error) {

			info, err := accountRowToInfo(r)
			return info, r.ID, err
		},
	)
	if err != nil {
		return nil, err
	}

	return p.attachBalances(ctx, query, infos)
}

// attachBalances forwards to db.AttachBalances with a backend-specific
// closure that runs AccountBalancesByIDs and converts the sqlc rows into
// the dialect-agnostic db.AccountBalance shape.
func (p accountListQueries) attachBalances(ctx context.Context,
	query db.ListAccountsQuery,
	infos []*db.AccountInfo) ([]db.AccountInfo, error) {

	return db.AttachBalances(
		ctx, query.WalletID, query.SkipBalance, infos,
		func(ctx context.Context, walletID uint32,
			ids []int64) ([]db.AccountBalance, error) {

			rows, err := p.q.AccountBalancesByIDs(
				ctx, sqlc.AccountBalancesByIDsParams{
					WalletID:   int64(walletID),
					AccountIds: ids,
				},
			)
			if err != nil {
				return nil, err
			}

			balances := make([]db.AccountBalance, len(rows))
			for i := range rows {
				balances[i] = db.AccountBalance{
					AccountID:   rows[i].AccountID,
					Confirmed:   rows[i].ConfirmedBalance,
					Unconfirmed: rows[i].UnconfirmedBalance,
				}
			}

			return balances, nil
		},
	)
}

// accountRenameQueries groups PostgreSQL account rename query methods.
type accountRenameQueries struct {
	q *sqlc.Queries
}

// byNumber renames an account identified by wallet ID, scope, and account
// number.
func (p accountRenameQueries) byNumber(ctx context.Context,
	params db.RenameAccountParams) error {

	return db.RenameAccount(
		ctx, p.q.UpdateAccountNameByWalletScopeAndNumber,
		sqlc.UpdateAccountNameByWalletScopeAndNumberParams{
			NewName:       params.NewName,
			WalletID:      int64(params.WalletID),
			Purpose:       int64(params.Scope.Purpose),
			CoinType:      int64(params.Scope.Coin),
			AccountNumber: db.NullableUint32ToSQLInt64(params.AccountNumber),
		}, params,
	)
}

// byName renames an account identified by wallet ID, scope, and old account
// name.
func (p accountRenameQueries) byName(ctx context.Context,
	params db.RenameAccountParams) error {

	return db.RenameAccount(
		ctx, p.q.UpdateAccountNameByWalletScopeAndName,
		sqlc.UpdateAccountNameByWalletScopeAndNameParams{
			NewName:  params.NewName,
			WalletID: int64(params.WalletID),
			Purpose:  int64(params.Scope.Purpose),
			CoinType: int64(params.Scope.Coin),
			OldName:  params.OldName,
		}, params,
	)
}
