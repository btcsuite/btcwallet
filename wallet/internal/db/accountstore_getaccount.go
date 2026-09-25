package db

import (
	"context"
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

// GetAccountOps is the backend adapter the shared GetAccount workflow uses.
//
// The shared account-read algorithm is intentionally ordered:
//   - validate the public query before any backend step runs
//   - load the AccountInfo in one backend selector step; backend-native account
//     identity is populated in the returned AccountInfo for later extraction
//   - extract backend-native account row ID for optional balance attachment
//   - attach the account balance unless the query opted out
//
// The adapter methods map directly to those stages so the shared helper keeps
// sequencing and invariants while each backend keeps sqlc query types, kvdb
// manager lookups, row conversions, and balance-query shapes local.
type GetAccountOps interface {
	// GetAccountByNumber returns the normalized public account view for the
	// account selected by account number.
	GetAccountByNumber(ctx context.Context,
		query GetAccountQuery) (*AccountInfo, error)

	// GetAccountByName returns the normalized public account view for the
	// account selected by account name.
	GetAccountByName(ctx context.Context, query GetAccountQuery) (*AccountInfo,
		error)

	// AttachAccountBalance fills balance fields on info for the loaded account.
	// The accountID is the SQL account row ID extracted from the loaded
	// AccountInfo; kvdb adapters may ignore it and use their own adapter-local
	// cached account identity instead.
	AttachAccountBalance(ctx context.Context, query GetAccountQuery,
		accountID int64, info *AccountInfo) (*AccountInfo, error)
}

// GetAccountWithOps runs the backend-independent account-read workflow once the
// caller has opened a backend-specific read transaction.
//
// The helper owns the ordered sequencing, so postgres, sqlite, and kvdb all
// validate before any backend step, load exactly one selector path into a
// normalized AccountInfo through backend-local conversions, extract the account
// row ID from the loaded AccountInfo, reject number-based imported-account
// lookups consistently, and attach balances after the account has been loaded.
func GetAccountWithOps(ctx context.Context, query GetAccountQuery,
	ops GetAccountOps) (*AccountInfo, error) {

	err := query.Validate()
	if err != nil {
		return nil, err
	}

	var info *AccountInfo

	if query.AccountNumber != nil {
		info, err = ops.GetAccountByNumber(ctx, query)
	} else {
		info, err = ops.GetAccountByName(ctx, query)
	}

	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			return nil, formatGetAccountNotFound(query)
		}

		return nil, fmt.Errorf("load account: %w", err)
	}

	// Imported accounts may only be looked up by Name; they do not expose a
	// public account number. Reject inbound number-based lookups that resolve
	// to imported so kvdb-internal account numbers cannot leak through this
	// API.
	if query.AccountNumber != nil && info.IsImported {
		return nil, formatGetAccountNotFound(query)
	}

	if query.SkipBalance {
		return info, nil
	}

	info, err = ops.AttachAccountBalance(ctx, query, info.rowID, info)
	if err != nil {
		return nil, fmt.Errorf("attach account balance: %w", err)
	}

	return info, nil
}

// formatGetAccountNotFound adds selector-specific query context to the shared
// not-found error contract.
func formatGetAccountNotFound(query GetAccountQuery) error {
	if query.Name != nil {
		return fmt.Errorf("account %q in scope %d/%d: %w", *query.Name,
			query.Scope.Purpose, query.Scope.Coin, ErrAccountNotFound)
	}

	return fmt.Errorf("account %d in scope %d/%d: %w", *query.AccountNumber,
		query.Scope.Purpose, query.Scope.Coin, ErrAccountNotFound)
}
