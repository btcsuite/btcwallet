package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Validate checks that exactly one account selector was set.
func (query GetAccountQuery) Validate() error {
	if query.Name == nil && query.AccountNumber == nil {
		return ErrInvalidAccountQuery
	}

	if query.Name != nil && query.AccountNumber != nil {
		return ErrInvalidAccountQuery
	}

	return nil
}

// GetAccountFunc defines a function signature for retrieving a single account.
type GetAccountFunc func(context.Context, GetAccountQuery) (*AccountInfo, error)

// GetAccountByQuery dispatches to the appropriate query based on the provided
// account identifier.
func GetAccountByQuery(ctx context.Context, query GetAccountQuery,
	getByNumber GetAccountFunc, getByName GetAccountFunc) (*AccountInfo,
	error) {

	err := query.Validate()
	if err != nil {
		return nil, err
	}

	if query.AccountNumber != nil {
		return getByNumber(ctx, query)
	}

	return getByName(ctx, query)
}

// GetAccount is a generic helper that retrieves an account using the provided
// query function. It handles error mapping and delegates conversion to the
// toInfo function.
func GetAccount[T any, Args any](ctx context.Context,
	getter func(context.Context, Args) (T, error), args Args,
	query GetAccountQuery, toInfo func(T) (*AccountInfo, error)) (*AccountInfo,
	error) {

	row, err := getter(ctx, args)
	if err == nil {
		return toInfo(row)
	}

	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("get account: %w", err)
	}

	if query.Name != nil {
		return nil, fmt.Errorf("account %q in scope %d/%d: %w", *query.Name,
			query.Scope.Purpose, query.Scope.Coin, ErrAccountNotFound)
	}

	return nil, fmt.Errorf("account %d in scope %d/%d: %w",
		*query.AccountNumber, query.Scope.Purpose, query.Scope.Coin,
		ErrAccountNotFound)
}
