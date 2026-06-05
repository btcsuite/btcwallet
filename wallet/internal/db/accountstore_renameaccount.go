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

// RenameAccountFunc defines the selector callback shape used by legacy backend
// adapters while the shared rename-account workflow is being introduced.
type RenameAccountFunc func(context.Context, RenameAccountParams) error

// RenameAccountByQuery validates params and dispatches to the matching rename
// selector.
//
// This compatibility helper keeps the workflow commit buildable against the
// pre-ops backend adapters; the follow-up adapter commit switches those
// backends to RenameAccountWithOps directly.
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

// RenameAccount preserves the pre-ops generic helper used by the existing
// backend adapters while the shared workflow is being introduced.
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

// RenameAccountOps is the backend adapter the shared RenameAccount workflow
// uses.
//
// The shared rename algorithm is intentionally ordered:
//   - validate the public request before any backend step runs
//   - choose the rename path (by account number or by old name)
//   - invoke the selected backend operation
//   - check rows affected and return not-found error if needed
//
// The adapter methods map directly to those paths so the shared helper keeps
// the sequencing and invariants while each backend keeps its sqlc query types,
// binding shapes, and row conversions local.
type RenameAccountOps interface {
	// RenameByNumber renames an account identified by wallet ID, scope, and
	// account number. It returns the number of rows affected.
	RenameByNumber(ctx context.Context, params RenameAccountParams) (int64,
		error)

	// RenameByName renames an account identified by wallet ID, scope, and old
	// account name. It returns the number of rows affected.
	RenameByName(ctx context.Context, params RenameAccountParams) (int64, error)
}

// RenameAccountWithOps runs the backend-independent rename workflow once the
// caller has opened a backend-specific SQL transaction.
//
// The helper owns the ordered sequencing, so postgres and sqlite both validate
// before any backend step, choose the correct rename path based on the
// selector, invoke the backend operation, and return the same not-found error
// shape when the account is not found.
func RenameAccountWithOps(ctx context.Context,
	params RenameAccountParams, ops RenameAccountOps) error {

	err := params.Validate()
	if err != nil {
		return err
	}

	var rowsAffected int64

	if params.AccountNumber != nil {
		rowsAffected, err = ops.RenameByNumber(ctx, params)
	} else {
		rowsAffected, err = ops.RenameByName(ctx, params)
	}

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
