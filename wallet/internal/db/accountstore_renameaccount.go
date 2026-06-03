package db

import (
	"context"
	"fmt"
)

// Validate checks that the rename parameters identify exactly one account.
func (params RenameAccountParams) Validate() error {
	if params.NewName == "" {
		return ErrMissingAccountName
	}

	if params.OldName == "" && params.AccountNumber == nil {
		return ErrInvalidAccountQuery
	}

	if params.OldName != "" && params.AccountNumber != nil {
		return ErrInvalidAccountQuery
	}

	return nil
}

// RenameAccountFunc defines a function signature for renaming an account.
type RenameAccountFunc func(context.Context, RenameAccountParams) error

// RenameAccountByQuery dispatches to the appropriate rename query based on the
// provided account identifier (either account number or old name).
func RenameAccountByQuery(ctx context.Context, params RenameAccountParams,
	renameByNumber RenameAccountFunc, renameByName RenameAccountFunc) error {

	err := params.Validate()
	if err != nil {
		return err
	}

	if params.AccountNumber != nil {
		return renameByNumber(ctx, params)
	}

	return renameByName(ctx, params)
}

// RenameAccount is a generic helper that updates an account name using the
// provided update function. It checks rows affected and returns an error if
// the account was not found.
func RenameAccount[Args any](ctx context.Context,
	update func(context.Context, Args) (int64, error), args Args,
	params RenameAccountParams) error {

	rowsAffected, err := update(ctx, args)
	if err != nil {
		return fmt.Errorf("rename account: %w", err)
	}

	if rowsAffected != 0 {
		return nil
	}

	if params.OldName != "" {
		return fmt.Errorf("account %q in scope %d/%d: %w", params.OldName,
			params.Scope.Purpose, params.Scope.Coin, ErrAccountNotFound)
	}

	return fmt.Errorf("account %d in scope %d/%d: %w", *params.AccountNumber,
		params.Scope.Purpose, params.Scope.Coin, ErrAccountNotFound)
}
