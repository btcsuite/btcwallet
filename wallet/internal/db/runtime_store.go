// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import (
	"context"

	"github.com/btcsuite/btcwallet/waddrmgr"
)

// PersistenceStore is the low-level, callback-oriented persistence surface: the
// View/Update transaction boundary retained for migration, compatibility
// conformance, and backend implementation tests. It is an alias of Store so
// existing callers that reference db.Store keep compiling unchanged.
//
// PersistenceStore is deliberately kept separate from RuntimeStore. Runtime
// wallet workflows receive a RuntimeStore and never a PersistenceStore, so a
// path already migrated to the semantic API cannot reach the raw View/Update
// boundary. The package-boundary check in the Phase 1A spike tests asserts a
// concrete RuntimeStore does not satisfy this interface.
type PersistenceStore = Store

// RuntimeStore is the semantic runtime API the wallet orchestration uses in
// Stage 3. Every method owns its own database transaction and exposes no
// callback or raw transaction handle, so a caller cannot smuggle unrelated
// preparation, chain I/O, or cache mutation into a durable runtime commit. It
// deliberately does not embed PersistenceStore.
//
// For the Phase 1A transaction-contract spike it carries a single semantic
// operation, the address-branch index reservation, plus the durable snapshot
// read it prepares from and the durable reread that resolves an ambiguous
// commit. Later phases extend this interface with the remaining semantic
// operations such as scan commit and funding reservation, following the same
// transaction-ownership and conflict contract.
type RuntimeStore interface {
	// CurrentBranchIndex reads a durable snapshot of the account's next
	// index for one branch. It is the prepare-phase read taken before the
	// mutation gate is acquired and never mutates state.
	CurrentBranchIndex(ctx context.Context, scope waddrmgr.KeyScope,
		account, branch uint32) (uint32, error)

	// ReserveNextBranchIndex allocates the account's next index for one
	// branch through an optimistic compare-and-swap and records the
	// committed operation in the operation journal within the same durable
	// transaction, so the index move and its journal entry are atomic.
	//
	// It returns ErrStaleAccountIndex when the expected index no longer
	// matches the durable value, and ErrAmbiguousCommit when the durable
	// outcome is unknown and the caller must resolve it with a durable
	// reread. A retry that reuses the request's operation id is served from
	// the journal instead of advancing the index again.
	ReserveNextBranchIndex(ctx context.Context,
		req ReserveBranchIndexRequest) (ReserveBranchIndexResult, error)

	// LookupBranchIndexReservation reads a previously committed reservation
	// from the operation journal by its operation id. It is the durable
	// reread that resolves an ambiguous commit without repeating the
	// compare-and-swap. The boolean is false when no committed reservation
	// exists for the id.
	LookupBranchIndexReservation(ctx context.Context,
		operationID []byte) (ReserveBranchIndexResult, bool, error)
}

// ReserveBranchIndexRequest is the prepared input to a branch-index
// reservation. ExpectedIndex is the snapshot read during preparation; the
// compare-and-swap advances the branch only while the durable index still
// equals it. OperationID keys the durable journal entry so a replay is served
// from the journal rather than advancing the index a second time.
type ReserveBranchIndexRequest struct {
	// Scope is the account's key scope.
	Scope waddrmgr.KeyScope

	// Account is the account number within the scope.
	Account uint32

	// Branch is the derivation branch, external or internal.
	Branch uint32

	// ExpectedIndex is the next index observed during preparation.
	ExpectedIndex uint32

	// OperationID is the caller-stable identifier of this reservation within
	// the branch-index domain. A retry with the same id is idempotent.
	OperationID []byte
}

// ReserveBranchIndexResult is the committed result of a branch-index
// reservation, materialized so cache publication and any notification never
// need the original write transaction.
type ReserveBranchIndexResult struct {
	// AllocatedIndex is the index the caller reserved, the value the branch's
	// next index held before the advance.
	AllocatedIndex uint32

	// NextIndex is the account's new next index after the advance.
	NextIndex uint32

	// Replayed is true when the result was served from the operation journal
	// because the operation had already committed, rather than by advancing
	// the index in this call.
	Replayed bool
}
