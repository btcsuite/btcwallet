package db

import (
	"context"
	"errors"
	"fmt"
)

// UnusedDerivedAddressOps extends the allocation adapter with the reads that
// reuse-aware allocation needs. The shared workflows below keep the lookup,
// the allocation lock, and the fallback allocation in one sequence so every
// backend gives the same atomicity guarantee.
type UnusedDerivedAddressOps interface {
	NewDerivedAddressOps

	// LockAccount serializes the caller's transaction with every allocation
	// on the account without advancing its derivation counters, so no child
	// address index is used up. Backends whose write transactions are
	// already exclusive may do nothing.
	LockAccount(ctx context.Context, accountID int64) error

	// OldestUnusedAddress returns the unused derived child with the lowest
	// index on one branch of the account. It returns ErrAddressNotFound
	// when the branch has no unused child.
	OldestUnusedAddress(ctx context.Context, accountID int64,
		change bool) (*AddressInfo, error)
}

// OldestUnusedDerivedAddressWithOps is the read-only lookup that lets a reuse
// request skip the write path when an unused child already exists. It applies
// the same account resolution and receiving policy as allocation, and returns
// ErrAddressNotFound when the branch has no unused child.
func OldestUnusedDerivedAddressWithOps(ctx context.Context,
	params NewDerivedAddressParams,
	ops UnusedDerivedAddressOps) (*AddressInfo, error) {

	account, _, err := derivedAddressAccount(ctx, params, ops)
	if err != nil {
		return nil, err
	}

	return ops.OldestUnusedAddress(ctx, account.AccountID, params.Change)
}

// OldestUnusedOrNewDerivedAddressWithOps returns the oldest unused child on
// the selected branch, or allocates exactly one when none exists, within the
// caller's write transaction. The lookup runs after LockAccount, so it sees
// every allocation that committed while the caller waited, and concurrent
// callers on an empty branch allocate once. Exhausted has the same meaning as
// in NewDerivedAddressesWithOps.
func OldestUnusedOrNewDerivedAddressWithOps(ctx context.Context,
	params NewDerivedAddressParams, ops UnusedDerivedAddressOps,
	deriveFn AddressDerivationFunc) (*AddressInfo, bool, error) {

	if deriveFn == nil {
		return nil, false, errNilAddressDerivationFunc
	}

	account, number, err := derivedAddressAccount(ctx, params, ops)
	if err != nil {
		return nil, false, err
	}

	err = ops.LockAccount(ctx, account.AccountID)
	if err != nil {
		return nil, false, fmt.Errorf("lock account: %w", err)
	}

	oldest, err := ops.OldestUnusedAddress(
		ctx, account.AccountID, params.Change,
	)
	switch {
	case err == nil:
		return oldest, false, nil

	case !errors.Is(err, ErrAddressNotFound):
		return nil, false, fmt.Errorf("get oldest unused address: %w", err)
	}

	addresses, exhausted, err := newDerivedAddressesForAccount(
		ctx, params, 1, account, number, ops, deriveFn,
	)
	if err != nil || exhausted {
		return nil, exhausted, err
	}

	return &addresses[0], false, nil
}
