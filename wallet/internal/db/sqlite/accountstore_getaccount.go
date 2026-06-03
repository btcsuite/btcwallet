package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// GetAccount retrieves information about a specific account, identified by its
// name or account number within a given key scope.
func (s *Store) GetAccount(ctx context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	var account *db.AccountInfo

	err := s.execRead(ctx, func(q *sqlc.Queries) error {
		getQueries := accountGetQueries{q: q}

		var err error

		account, err = db.GetAccountByQuery(
			ctx, query, getQueries.byNumber, getQueries.byName,
		)

		return err
	})
	if err != nil {
		return nil, err
	}

	return account, nil
}

// accountGetQueries groups SQLite account retrieval query methods.
type accountGetQueries struct {
	q *sqlc.Queries
}

// byNumber retrieves an account by wallet ID, scope, and account number,
// then attaches its balance via AccountBalance unless query.SkipBalance
// is set.
func (s accountGetQueries) byNumber(ctx context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	row, err := s.q.GetAccountByWalletScopeAndNumber(
		ctx, sqlc.GetAccountByWalletScopeAndNumberParams{
			WalletID:      int64(query.WalletID),
			Purpose:       int64(query.Scope.Purpose),
			CoinType:      int64(query.Scope.Coin),
			AccountNumber: db.NullableUint32ToSQLInt64(query.AccountNumber),
		},
	)
	if err != nil {
		return nil, mapGetAccountErr(err, query)
	}

	info, err := accountRowToInfo(row)
	if err != nil {
		return nil, err
	}

	return s.attachBalance(ctx, query, info, row.ID)
}

// byName retrieves an account by wallet ID, scope, and account name, then
// attaches its balance via AccountBalance unless query.SkipBalance is set.
func (s accountGetQueries) byName(ctx context.Context,
	query db.GetAccountQuery) (*db.AccountInfo, error) {

	row, err := s.q.GetAccountByWalletScopeAndName(
		ctx, sqlc.GetAccountByWalletScopeAndNameParams{
			WalletID:    int64(query.WalletID),
			Purpose:     int64(query.Scope.Purpose),
			CoinType:    int64(query.Scope.Coin),
			AccountName: *query.Name,
		},
	)
	if err != nil {
		return nil, mapGetAccountErr(err, query)
	}

	info, err := accountRowToInfo(row)
	if err != nil {
		return nil, err
	}

	return s.attachBalance(ctx, query, info, row.ID)
}

// attachBalance fills ConfirmedBalance and UnconfirmedBalance on info via
// the dedicated AccountBalance query, unless the caller opted out via
// query.SkipBalance. The query runs inside the caller's read transaction.
func (s accountGetQueries) attachBalance(ctx context.Context,
	query db.GetAccountQuery, info *db.AccountInfo,
	accountID int64) (*db.AccountInfo, error) {

	if query.SkipBalance {
		return info, nil
	}

	bal, err := s.q.AccountBalance(
		ctx, sqlc.AccountBalanceParams{
			WalletID:  int64(query.WalletID),
			AccountID: accountID,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("account balance: %w", err)
	}

	info.ConfirmedBalance = btcutil.Amount(bal.ConfirmedBalance)
	info.UnconfirmedBalance = btcutil.Amount(bal.UnconfirmedBalance)

	return info, nil
}

// mapGetAccountErr returns the typed ErrAccountNotFound when err is
// sql.ErrNoRows, falling back to a wrapped form otherwise. The caller
// names the queried account in the error using whichever selector
// (Name or AccountNumber) was set.
func mapGetAccountErr(err error, query db.GetAccountQuery) error {
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("get account: %w", err)
	}

	if query.Name != nil {
		return fmt.Errorf("account %q in scope %d/%d: %w", *query.Name,
			query.Scope.Purpose, query.Scope.Coin,
			db.ErrAccountNotFound)
	}

	return fmt.Errorf("account %d in scope %d/%d: %w",
		*query.AccountNumber, query.Scope.Purpose, query.Scope.Coin,
		db.ErrAccountNotFound)
}
