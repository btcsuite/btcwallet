package pg

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
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
	infos []db.AccountInfo) ([]db.AccountInfo, error) {
	if query.SkipBalance {
		return infos, nil
	}

	return db.AttachAccountBalances(
		ctx, query.WalletID, infos,
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
