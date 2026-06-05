package sqlite

import (
	"context"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// ListAccounts returns a slice of AccountInfo for all accounts, optionally
// filtered by name or key scope.
func (s *Store) ListAccounts(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	var accounts []db.AccountInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		listQueries := accountListQueries{q: q}

		var err error

		accounts, err = db.ListAccountsWithOps(ctx, query, listQueries)

		return err
	})
	if err != nil {
		return nil, err
	}

	return accounts, nil
}

// accountListQueries adapts SQLite account listing queries to the shared
// ListAccountsOps interface for the ListAccountsWithOps workflow.
type accountListQueries struct {
	q *sqlc.Queries
}

// Verify accountListQueries implements ListAccountsOps.
var _ db.ListAccountsOps = accountListQueries{}

// ListByScope implements db.ListAccountsOps.
func (s accountListQueries) ListByScope(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	rows, err := s.q.ListAccountsByWalletScope(
		ctx, sqlc.ListAccountsByWalletScopeParams{
			WalletID: int64(query.WalletID),
			Purpose:  int64(query.Scope.Purpose),
			CoinType: int64(query.Scope.Coin),
		},
	)
	if err != nil {
		return nil, err
	}

	return db.ProcessAccountRows(
		rows,
		func(r sqlc.ListAccountsByWalletScopeRow) (*db.AccountInfo, int64,
			error) {

			info, err := accountRowToInfo(r)
			return info, r.ID, err
		},
	)
}

// ListByName implements db.ListAccountsOps.
func (s accountListQueries) ListByName(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	rows, err := s.q.ListAccountsByWalletAndName(
		ctx, sqlc.ListAccountsByWalletAndNameParams{
			WalletID:    int64(query.WalletID),
			AccountName: *query.Name,
		},
	)
	if err != nil {
		return nil, err
	}

	return db.ProcessAccountRows(
		rows,
		func(r sqlc.ListAccountsByWalletAndNameRow) (*db.AccountInfo, int64,
			error) {

			info, err := accountRowToInfo(r)
			return info, r.ID, err
		},
	)
}

// ListAll implements db.ListAccountsOps.
func (s accountListQueries) ListAll(ctx context.Context,
	query db.ListAccountsQuery) ([]db.AccountInfo, error) {

	rows, err := s.q.ListAccountsByWallet(ctx, int64(query.WalletID))
	if err != nil {
		return nil, err
	}

	return db.ProcessAccountRows(
		rows,
		func(r sqlc.ListAccountsByWalletRow) (*db.AccountInfo, int64,
			error) {

			info, err := accountRowToInfo(r)
			return info, r.ID, err
		},
	)
}

// AttachAccountBalances implements db.ListAccountsOps. It forwards to
// db.AttachAccountBalances with a backend-specific closure that runs
// AccountBalancesByIDs and converts the sqlc rows into the dialect-agnostic
// db.AccountBalance shape after the shared workflow has decided balances are
// needed.
func (s accountListQueries) AttachAccountBalances(ctx context.Context,
	walletID uint32, infos []db.AccountInfo) ([]db.AccountInfo, error) {

	return db.AttachAccountBalances(
		ctx, walletID, infos,
		func(ctx context.Context, walletID uint32,
			ids []int64) ([]db.AccountBalance, error) {

			rows, err := s.q.AccountBalancesByIDs(
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
