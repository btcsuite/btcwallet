// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package kvdb

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
)

// This file implements the Phase 2A1 address, account, and scope semantic
// operations over walletdb (Bolt), asymmetric to the SQL runtime store: each
// operation commits in one walletdb.Update that revalidates its natural
// precondition from the managers' records and mutates them in place. There is
// no operation journal, so a KV commit is never ambiguous and never replayed;
// idempotency is by full rollback plus re-preparation, exactly as for the
// branch-index and tip operations. The shared runtime.Coordinator drives this
// store and the SQL store identically.

// CommitDerivedAddresses inserts the prepared derived addresses and advances the
// branch's next index in one Bolt write transaction, using the account record's
// stored index as the natural precondition. It returns ErrStaleAccountIndex when
// the stored index no longer matches the caller's expected value, on which the
// whole transaction rolls back and the shared orchestration re-prepares. A KV
// commit is never ambiguous and never replayed from a journal, so Replayed is
// always false.
//
//nolint:cyclop // Guard, failpoint seam, atomic index advance, and inserts.
func (r *runtimeStore) CommitDerivedAddresses(ctx context.Context,
	req walletstore.CommitDerivedAddressesRequest) (
	walletstore.CommitDerivedAddressesResult, error) {

	if err := ctx.Err(); err != nil {
		return walletstore.CommitDerivedAddressesResult{}, err
	}

	if req.FinalIndex < req.ExpectedIndex {
		return walletstore.CommitDerivedAddressesResult{}, fmt.Errorf(
			"final index %d precedes expected index %d",
			req.FinalIndex, req.ExpectedIndex)
	}

	fp := walletstore.FailpointsFromContext(ctx)
	fp.RunOnTxAttempt(0)

	var out walletstore.CommitDerivedAddressesResult

	err := walletdb.Update(r.db, func(tx walletdb.ReadWriteTx) error {
		store := waddrmgr.BindManagerReadWriteStore(
			tx.ReadWriteBucket(addrmgrNamespaceKey),
		)

		acct, err := store.Account(req.Scope, req.Account)
		if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
			return fmt.Errorf("account %d: %w", req.Account,
				walletstore.ErrStaleAccountIndex)
		}

		if err != nil {
			return err
		}

		current, err := branchNextIndex(acct, req.Branch)
		if err != nil {
			return err
		}

		// The natural guard: advance only while the stored index still
		// equals the caller's expected value, so a concurrent advance is
		// rejected exactly as the SQL compare-and-swap would reject it.
		if current != req.ExpectedIndex {
			return fmt.Errorf("account %d branch %d expected index "+
				"%d, have %d: %w", req.Account, req.Branch,
				req.ExpectedIndex, current,
				walletstore.ErrStaleAccountIndex)
		}

		if err := fp.RunBeforeStatement(); err != nil {
			return err
		}

		// Advance the branch index before inserting, mirroring the SQL
		// compare-and-swap-first order so the two backends behave the same.
		external, internal := acct.NextExternalIndex, acct.NextInternalIndex
		if req.Branch == waddrmgr.ExternalBranch {
			external = req.FinalIndex
		} else {
			internal = req.FinalIndex
		}

		err = store.SetAccountIndexes(
			req.Scope, req.Account, external, internal,
		)
		if err != nil {
			return err
		}

		for _, prepared := range req.Addresses {
			err := store.PutAddress(prepared.AddressID, prepared.State)
			if err != nil {
				return err
			}
		}

		out = walletstore.CommitDerivedAddressesResult{
			Addresses:      req.Addresses,
			AllocatedStart: req.ExpectedIndex,
			NextIndex:      req.FinalIndex,
		}

		return fp.RunBeforeCommit()
	})
	if err != nil {
		return walletstore.CommitDerivedAddressesResult{}, err
	}

	if err := fp.RunAfterCommit(); err != nil {
		return walletstore.CommitDerivedAddressesResult{}, err
	}

	return out, nil
}

// LookupDerivedAddresses always reports no committed operation: the KV backend
// keeps no operation journal, so the shared orchestration never needs a durable
// reread here.
func (r *runtimeStore) LookupDerivedAddresses(_ context.Context,
	_ []byte) (walletstore.CommitDerivedAddressesResult, bool, error) {

	return walletstore.CommitDerivedAddressesResult{}, false, nil
}

// CurrentLastAccount reads a durable snapshot of the scope's last allocated
// account from the natural key-scope record in a read transaction.
func (r *runtimeStore) CurrentLastAccount(ctx context.Context,
	scope waddrmgr.KeyScope) (uint32, error) {

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	var last uint32

	err := walletdb.View(r.db, func(tx walletdb.ReadTx) error {
		store := waddrmgr.BindManagerReadStore(
			tx.ReadBucket(addrmgrNamespaceKey),
		)

		state, err := store.KeyScope(scope)
		if err != nil {
			return err
		}

		last = state.LastAccount

		return nil
	})
	if err != nil {
		return 0, err
	}

	return last, nil
}

// EnsureScope creates the key scope if it is absent and is otherwise a no-op, in
// one Bolt write transaction. The created scope uses the same legacy encoding as
// one created through the callback-oriented store.
func (r *runtimeStore) EnsureScope(ctx context.Context,
	req walletstore.EnsureScopeRequest) (walletstore.EnsureScopeResult, error) {

	if err := ctx.Err(); err != nil {
		return walletstore.EnsureScopeResult{}, err
	}

	fp := walletstore.FailpointsFromContext(ctx)
	fp.RunOnTxAttempt(0)

	var out walletstore.EnsureScopeResult

	err := walletdb.Update(r.db, func(tx walletdb.ReadWriteTx) error {
		store := waddrmgr.BindManagerReadWriteStore(
			tx.ReadWriteBucket(addrmgrNamespaceKey),
		)

		_, err := store.KeyScope(req.State.Scope)
		switch {
		case err == nil:
			out = walletstore.EnsureScopeResult{Created: false}

			return nil

		case !waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound):
			return err
		}

		if err := fp.RunBeforeStatement(); err != nil {
			return err
		}

		if err := store.PutKeyScope(req.State); err != nil {
			return err
		}

		out = walletstore.EnsureScopeResult{Created: true}

		return fp.RunBeforeCommit()
	})
	if err != nil {
		return walletstore.EnsureScopeResult{}, err
	}

	if err := fp.RunAfterCommit(); err != nil {
		return walletstore.EnsureScopeResult{}, err
	}

	return out, nil
}

// EnsureAccount ensures an account with the requested name exists in the scope,
// in one Bolt write transaction. An existing account with that name is returned
// unchanged; otherwise the next number is allocated after revalidating the
// scope's last account against the caller's expected value, so a stale allocation
// is rejected with ErrStaleLastAccount exactly as the SQL compare-and-swap would.
//
//nolint:cyclop // Idempotency check, last-account guard, seam, and creation.
func (r *runtimeStore) EnsureAccount(ctx context.Context,
	req walletstore.EnsureAccountRequest) (walletstore.EnsureAccountResult,
	error) {

	if err := ctx.Err(); err != nil {
		return walletstore.EnsureAccountResult{}, err
	}

	fp := walletstore.FailpointsFromContext(ctx)
	fp.RunOnTxAttempt(0)

	var out walletstore.EnsureAccountResult

	err := walletdb.Update(r.db, func(tx walletdb.ReadWriteTx) error {
		store := waddrmgr.BindManagerReadWriteStore(
			tx.ReadWriteBucket(addrmgrNamespaceKey),
		)

		existing, err := store.AccountByName(req.Scope, req.Name)
		switch {
		case err == nil:
			out = walletstore.EnsureAccountResult{
				Account: existing.Account,
				Created: false,
			}

			return nil

		case !waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound):
			return err
		}

		if err := fp.RunBeforeStatement(); err != nil {
			return err
		}

		newAccount, err := walletstore.NextAccountNumber(
			req.ExpectedLastAccount,
		)
		if err != nil {
			return err
		}

		// The natural guard: allocate only while the scope's stored last
		// account still equals the caller's expected value.
		scopeState, err := store.KeyScope(req.Scope)
		if err != nil {
			return err
		}

		if scopeState.LastAccount != req.ExpectedLastAccount {
			return fmt.Errorf("scope %s expected last account %d, "+
				"have %d: %w", req.Scope, req.ExpectedLastAccount,
				scopeState.LastAccount, walletstore.ErrStaleLastAccount)
		}

		if err := store.SetLastAccount(req.Scope, newAccount); err != nil {
			return err
		}

		account := req.Template
		account.Scope = req.Scope
		account.Account = newAccount

		account.Name = req.Name
		if err := store.PutAccount(account); err != nil {
			return err
		}

		out = walletstore.EnsureAccountResult{
			Account: newAccount,
			Created: true,
		}

		return fp.RunBeforeCommit()
	})
	if err != nil {
		return walletstore.EnsureAccountResult{}, err
	}

	if err := fp.RunAfterCommit(); err != nil {
		return walletstore.EnsureAccountResult{}, err
	}

	return out, nil
}

// RenameAccount renames one account in one Bolt write transaction, reusing the
// legacy store's rename, which rejects a name owned by a different account with
// waddrmgr.ErrDuplicateAccount and keeps the name index consistent.
func (r *runtimeStore) RenameAccount(ctx context.Context,
	req walletstore.RenameAccountRequest) (walletstore.RenameAccountResult,
	error) {

	if err := ctx.Err(); err != nil {
		return walletstore.RenameAccountResult{}, err
	}

	fp := walletstore.FailpointsFromContext(ctx)
	fp.RunOnTxAttempt(0)

	err := walletdb.Update(r.db, func(tx walletdb.ReadWriteTx) error {
		store := waddrmgr.BindManagerReadWriteStore(
			tx.ReadWriteBucket(addrmgrNamespaceKey),
		)

		if err := fp.RunBeforeStatement(); err != nil {
			return err
		}

		err := store.RenameAccount(req.Scope, req.Account, req.NewName)
		if err != nil {
			return err
		}

		return fp.RunBeforeCommit()
	})
	if err != nil {
		return walletstore.RenameAccountResult{}, err
	}

	if err := fp.RunAfterCommit(); err != nil {
		return walletstore.RenameAccountResult{}, err
	}

	return walletstore.RenameAccountResult{}, nil
}
