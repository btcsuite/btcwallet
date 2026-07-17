// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import (
	"errors"

	"github.com/btcsuite/btcwallet/waddrmgr"
)

// NextAccountNumber returns the account number that follows a scope's last
// allocated account. The absent-account sentinel (waddrmgr.NoAccountAllocated)
// is the maximum uint32, so the wrap-around yields account zero for the first
// allocation. It refuses to allocate the sentinel itself, which would exhaust
// the account space. Both backends and the coordinator compute the next number
// through it, so the derivation preparation and the allocation agree.
func NextAccountNumber(lastAccount uint32) (uint32, error) {
	next := lastAccount + 1
	if next == waddrmgr.NoAccountAllocated {
		return 0, errors.New("account number space exhausted")
	}

	return next, nil
}

// This file defines the prepared inputs and committed results of the Phase 2A1
// address, account, and scope semantic operations. They follow the Stage 3
// contract: the caller derives, computes, and encrypts outside the write
// transaction and passes the prepared rows here; the runtime store commits one
// short atomic operation with compare-and-swap guards and returns fully
// materialized committed facts so caches publish without another transaction.

// PreparedAddress is one derived address ready to be inserted, prepared outside
// the write transaction. It carries both the legacy address identifier and the
// durable address state so either backend can persist it: the KV backend keys
// its legacy row by AddressID, while the SQL backend stores State.Hash, the
// SHA256 of the same identifier.
type PreparedAddress struct {
	// AddressID is the legacy address identifier, the address's ScriptAddress
	// bytes. The KV backend stores the address row under it; the SQL backend
	// stores its SHA256 in State.Hash.
	AddressID []byte

	// State is the durable address state to persist. For a derived chained
	// address it carries the derivation path (Branch, Index) and no key
	// material, matching the keyless derived-address schema.
	State waddrmgr.AddressState
}

// CommitDerivedAddressesRequest is the prepared input to a derived-address
// commit. The addresses were derived outside the write transaction starting at
// ExpectedIndex; because an invalid child is skipped, the consumed range can
// exceed the address count, so FinalIndex, not ExpectedIndex plus the count, is
// the branch's new next index. The commit inserts the addresses and advances
// the branch from ExpectedIndex to FinalIndex atomically through a
// compare-and-swap.
type CommitDerivedAddressesRequest struct {
	// Scope is the account's key scope.
	Scope waddrmgr.KeyScope

	// Account is the account number within the scope.
	Account uint32

	// Branch is the derivation branch, external or internal.
	Branch uint32

	// ExpectedIndex is the branch's next index observed during preparation.
	// The compare-and-swap advances the branch only while the durable index
	// still equals it.
	ExpectedIndex uint32

	// FinalIndex is the branch's next index after the consumed range, one past
	// the last derived child's index. It is the value the compare-and-swap
	// advances the branch to, and accounts for any skipped invalid children.
	FinalIndex uint32

	// Addresses are the derived address rows to insert, in derivation order.
	// Their indexes lie in [ExpectedIndex, FinalIndex) and need not be
	// contiguous when an invalid child was skipped.
	Addresses []PreparedAddress

	// OperationID keys the durable journal (SQL only) so a replay is served
	// from the journal instead of inserting and advancing again.
	OperationID []byte
}

// CommitDerivedAddressesResult is the committed result of a derived-address
// commit, materialized so cache publication never needs the original write
// transaction. It embeds CommittedFacts; a derived-address commit emits no
// post-commit event, so its Events are always empty.
type CommitDerivedAddressesResult struct {
	CommittedFacts

	// Addresses are the committed address rows, in derivation order.
	Addresses []PreparedAddress

	// AllocatedStart is the first index the caller reserved, the branch's next
	// index before the advance.
	AllocatedStart uint32

	// NextIndex is the branch's new next index after the advance, equal to the
	// request's FinalIndex.
	NextIndex uint32
}

// EnsureScopeRequest is the prepared input to an idempotent scope creation. The
// scope's coin-type keys were derived and encrypted outside the write
// transaction. A scope that already exists is left unchanged.
type EnsureScopeRequest struct {
	// State is the durable key-scope state to create when the scope is absent.
	State waddrmgr.KeyScopeState
}

// EnsureScopeResult is the committed result of an idempotent scope creation.
type EnsureScopeResult struct {
	CommittedFacts

	// Created reports whether this call created the scope. It is false when
	// the scope already existed.
	Created bool
}

// EnsureAccountRequest is the prepared input to an idempotent account creation.
// The account's extended keys were derived and encrypted outside the write
// transaction. An account with the requested name is returned unchanged when it
// already exists; otherwise the next account number is allocated through a
// compare-and-swap against ExpectedLastAccount and the account is created at it.
type EnsureAccountRequest struct {
	// Scope is the account's key scope.
	Scope waddrmgr.KeyScope

	// Name is the account name. It is the idempotency key: an existing account
	// with this name is returned rather than a second account created.
	Name string

	// ExpectedLastAccount is the scope's last allocated account observed during
	// preparation. The compare-and-swap allocates the next number only while
	// the durable last account still equals it. It is waddrmgr.NoAccountAllocated
	// for a scope that has never allocated an account.
	ExpectedLastAccount uint32

	// Template carries the account's durable state except its number and name,
	// which the operation fills from the allocation and Name. It records the
	// account type, encrypted keys, master-key fingerprint, and address schema.
	Template waddrmgr.AccountState
}

// EnsureAccountResult is the committed result of an idempotent account creation.
type EnsureAccountResult struct {
	CommittedFacts

	// Account is the account's number, whether newly allocated or the number
	// of the pre-existing account with the requested name.
	Account uint32

	// Created reports whether this call created the account. It is false when
	// an account with the requested name already existed.
	Created bool
}

// RenameAccountRequest is the prepared input to an account rename. The rename
// is rejected when NewName is already owned by a different account, and renaming
// an account to its own current name is a permitted no-op.
type RenameAccountRequest struct {
	// Scope is the account's key scope.
	Scope waddrmgr.KeyScope

	// Account is the account number to rename.
	Account uint32

	// NewName is the account's new name.
	NewName string
}

// RenameAccountResult is the committed result of an account rename. It embeds
// CommittedFacts; a rename emits no post-commit event.
type RenameAccountResult struct {
	CommittedFacts
}
