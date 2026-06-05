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

	err := s.execRead(
		ctx, func(q *sqlc.Queries) error {
			getQueries := accountGetQueries{q: q}

			var err error

			account, err = db.GetAccountWithOps(ctx, query, getQueries)

			return err
		},
	)
	if err != nil {
		return nil, err
	}

	return account, nil
}

// accountGetQueries groups SQLite account retrieval query methods.
type accountGetQueries struct {
	q *sqlc.Queries
}

// Verify accountGetQueries implements GetAccountOps.
var _ db.GetAccountOps = accountGetQueries{}

// GetAccountByNumber implements db.GetAccountOps.
func (s accountGetQueries) GetAccountByNumber(ctx context.Context,
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
		return nil, mapGetAccountErr(err)
	}

	info, err := accountRowToInfo(row)
	if err != nil {
		return nil, err
	}

	return info, nil
}

// GetAccountByName implements db.GetAccountOps.
func (s accountGetQueries) GetAccountByName(ctx context.Context,
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
		return nil, mapGetAccountErr(err)
	}

	info, err := accountRowToInfo(row)
	if err != nil {
		return nil, err
	}

	return info, nil
}

// mapGetAccountErr normalizes SQLite not-found transport errors to the
// backend-neutral account contract.
func mapGetAccountErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return db.ErrAccountNotFound
	}

	return fmt.Errorf("get account: %w", err)
}

// AttachAccountBalance implements db.GetAccountOps.
func (s accountGetQueries) AttachAccountBalance(ctx context.Context,
	query db.GetAccountQuery, accountID int64,
	info *db.AccountInfo) (*db.AccountInfo, error) {

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
