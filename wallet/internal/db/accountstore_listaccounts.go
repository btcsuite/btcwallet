package db

import (
	"context"
	"fmt"
)

// accountInfosFromRows converts a slice of database rows into AccountInfo
// structs using the provided conversion function.
func accountInfosFromRows[T any](rows []T,
	toInfo func(T) (*AccountInfo, error)) ([]AccountInfo, error) {

	accounts := make([]AccountInfo, len(rows))
	for i, row := range rows {
		info, err := toInfo(row)
		if err != nil {
			return nil, err
		}

		accounts[i] = *info
	}

	return accounts, nil
}

// ListAccounts is a generic helper that retrieves accounts using the provided
// list function and converts the results to AccountInfo structs.
func ListAccounts[T any, Args any](ctx context.Context,
	lister func(context.Context, Args) ([]T, error), args Args,
	toInfo func(T) (*AccountInfo, error)) ([]AccountInfo, error) {

	rows, err := lister(ctx, args)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}

	return accountInfosFromRows(rows, toInfo)
}

// ListAccountsFunc defines a function signature for listing accounts.
type ListAccountsFunc func(context.Context, ListAccountsQuery) ([]AccountInfo,
	error)

// ListAccountsByQuery dispatches to the appropriate list query based on the
// provided filters. It returns an error if both scope and name filters are
// provided, as they are mutually exclusive.
func ListAccountsByQuery(ctx context.Context, query ListAccountsQuery,
	listByScope ListAccountsFunc, listByName ListAccountsFunc,
	listAll ListAccountsFunc) ([]AccountInfo, error) {

	switch {
	case query.Scope != nil && query.Name != nil:
		return nil, ErrInvalidAccountQuery

	case query.Scope != nil:
		return listByScope(ctx, query)

	case query.Name != nil:
		return listByName(ctx, query)

	default:
		return listAll(ctx, query)
	}
}
