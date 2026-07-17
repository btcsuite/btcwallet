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
// For the Phase 1A transaction-contract spike it carried a single semantic
// operation, the address-branch index reservation. Phase 1B adds the
// representative second operation, the wallet-tip advance, plus the durable
// snapshot reads each operation prepares from and the durable rereads that
// resolve an ambiguous commit. Later phases extend this interface with the
// remaining semantic operations such as scan commit and funding reservation,
// following the same transaction-ownership and conflict contract.
//
// Every method returns fully materialized committed facts, so cache updates and
// notification delivery never need the original write transaction. The SQL
// backend backs the operations with compare-and-swap guards, a runtime-state
// version row, and an operation journal; the KV backend backs them with the
// managers' natural records and Bolt's atomic single-writer transaction. Both
// return the same observable facts and typed errors.
//
//nolint:interfacebloat // The semantic surface owns every runtime operation.
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
	// exists for the id; a backend without a journal, such as KV, always
	// reports false because its commits are never ambiguous.
	LookupBranchIndexReservation(ctx context.Context,
		operationID []byte) (ReserveBranchIndexResult, bool, error)

	// CurrentSyncedTip reads a durable snapshot of the wallet's synced block.
	// It is the prepare-phase read the tip advance guards against and never
	// mutates state.
	CurrentSyncedTip(ctx context.Context) (BlockRef, error)

	// AdvanceWalletTip records the new tip block, if not already present, and
	// advances the wallet's synced tip to it through an optimistic
	// compare-and-swap against the caller's expected tip, all in one durable
	// transaction. The new tip must extend the expected tip by exactly one
	// block.
	//
	// It returns ErrNonContiguousTip when the new tip does not extend the
	// expected tip, ErrStaleTip when the durable synced tip no longer matches
	// the expected tip, and ErrAmbiguousCommit when the durable outcome is
	// unknown and the caller must resolve it with a durable reread. A retry
	// that reuses the request's operation id is served from the journal
	// instead of advancing the tip again.
	AdvanceWalletTip(ctx context.Context,
		req AdvanceTipRequest) (AdvanceTipResult, error)

	// LookupTipAdvance reads a previously committed tip advance from the
	// operation journal by its operation id, resolving an ambiguous commit
	// without repeating the advance. The boolean is false when no committed
	// advance exists for the id; a backend without a journal always reports
	// false.
	LookupTipAdvance(ctx context.Context,
		operationID []byte) (AdvanceTipResult, bool, error)

	// CommitDerivedAddresses inserts the prepared derived addresses and
	// advances the branch's next index from the request's expected index to
	// its final index through an optimistic compare-and-swap, all in one
	// durable transaction, so the address rows and the index advance become
	// durable together. The final index accounts for skipped invalid children,
	// so a blind reservation of the address count is insufficient. The unique
	// derivation-path index rejects a duplicate scope/account/branch/index.
	//
	// It returns ErrStaleAccountIndex when the expected index no longer matches
	// the durable value, and ErrAmbiguousCommit when the durable outcome is
	// unknown and the caller must resolve it with a durable reread. A retry
	// that reuses the request's operation id is served from the journal
	// instead of inserting and advancing again.
	CommitDerivedAddresses(ctx context.Context,
		req CommitDerivedAddressesRequest) (
		CommitDerivedAddressesResult, error)

	// LookupDerivedAddresses reads a previously committed derived-address
	// commit from the operation journal by its operation id, resolving an
	// ambiguous commit without repeating the insert and advance. The boolean
	// is false when no committed operation exists for the id; a backend
	// without a journal always reports false.
	LookupDerivedAddresses(ctx context.Context,
		operationID []byte) (CommitDerivedAddressesResult, bool, error)

	// CurrentLastAccount reads a durable snapshot of the scope's last allocated
	// account. It is the prepare-phase read taken before an account allocation
	// and returns waddrmgr.NoAccountAllocated for a scope that has never
	// allocated an account. It never mutates state.
	CurrentLastAccount(ctx context.Context,
		scope waddrmgr.KeyScope) (uint32, error)

	// EnsureScope creates the key scope if it is absent and is otherwise a
	// no-op, so it is idempotent across retries and re-preparation. The result
	// reports whether the scope was created.
	EnsureScope(ctx context.Context, req EnsureScopeRequest) (
		EnsureScopeResult, error)

	// EnsureAccount ensures an account with the requested name exists in the
	// scope. An existing account with that name is returned unchanged;
	// otherwise the next account number is allocated through an optimistic
	// compare-and-swap against the request's expected last account and the
	// account is created at it. It returns ErrStaleLastAccount when the
	// expected last account no longer matches the durable value, so the caller
	// rereads it and re-prepares.
	EnsureAccount(ctx context.Context, req EnsureAccountRequest) (
		EnsureAccountResult, error)

	// RenameAccount renames one account, rejecting a name already owned by a
	// different account with waddrmgr.ErrDuplicateAccount and treating a rename
	// to the account's own current name as a no-op. The name-index maintenance
	// is atomic with the rename.
	RenameAccount(ctx context.Context, req RenameAccountRequest) (
		RenameAccountResult, error)

	// LoadManagerSnapshot reads the durable manager root state, chain sync
	// state, and every key scope with its accounts in one consistent read, so
	// a restarting wallet reconstructs its in-memory caches from durable state
	// through the semantic runtime contract rather than the low-level
	// PersistenceStore boundary. It never mutates state.
	LoadManagerSnapshot(ctx context.Context) (ManagerSnapshot, error)

	// CommitScanResults commits one prepared recovery scan batch atomically:
	// the discovered addresses, the mined and unmined transaction incidences
	// with their credits and spends, the sticky address-usage marks, the block
	// rows, the branch-index horizon advances, and the wallet synced-tip
	// advance, all in one short transaction. The batch is fully prepared, so no
	// chain I/O, derivation, or parsing happens inside the transaction. It
	// advances the synced tip through an optimistic compare-and-swap against the
	// request's expected base tip and advances each branch index through a
	// compare-and-swap against its expected index.
	//
	// It returns ErrStaleTip when the durable synced tip no longer matches the
	// expected base tip, ErrStaleAccountIndex when a branch's expected index no
	// longer matches, and ErrAmbiguousCommit when the durable outcome is unknown
	// and the caller must resolve it with a durable reread. A retry that reuses
	// the request's operation id is served from the journal instead of
	// reapplying the batch.
	CommitScanResults(ctx context.Context,
		req CommitScanResultsRequest) (CommitScanResultsResult, error)

	// LookupScanResults reads a previously committed scan batch from the
	// operation journal by its operation id, resolving an ambiguous commit
	// without reapplying the batch. The boolean is false when no committed
	// batch exists for the id; a backend without a journal always reports false.
	LookupScanResults(ctx context.Context,
		operationID []byte) (CommitScanResultsResult, bool, error)

	// CommitWalletRewind reconciles the wallet back to a target block after a
	// reorg or startup rollback: it verifies the detached tip, atomically
	// reconciles the transaction incidences, credits, and spends above the
	// target, and moves the synced tip back to the target block, all in one
	// short transaction. It is guarded by an optimistic compare-and-swap against
	// the request's expected current tip.
	//
	// It returns ErrStaleTip when the durable synced tip no longer matches the
	// expected tip, and ErrAmbiguousCommit when the durable outcome is unknown
	// and the caller must resolve it with a durable reread. A retry that reuses
	// the request's operation id is served from the journal instead of
	// reapplying the rewind.
	CommitWalletRewind(ctx context.Context,
		req CommitWalletRewindRequest) (CommitWalletRewindResult, error)

	// LookupWalletRewind reads a previously committed wallet rewind from the
	// operation journal by its operation id, resolving an ambiguous commit
	// without reapplying the rewind. The boolean is false when no committed
	// rewind exists for the id; a backend without a journal always reports
	// false.
	LookupWalletRewind(ctx context.Context,
		operationID []byte) (CommitWalletRewindResult, bool, error)
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
// need the original write transaction. It embeds CommittedFacts; a reservation
// emits no post-commit event, so its Events are always empty.
type ReserveBranchIndexResult struct {
	CommittedFacts

	// AllocatedIndex is the index the caller reserved, the value the branch's
	// next index held before the advance.
	AllocatedIndex uint32

	// NextIndex is the account's new next index after the advance.
	NextIndex uint32
}

// AdvanceTipRequest is the prepared input to a wallet-tip advance. ExpectedTip
// is the synced block observed during preparation; the compare-and-swap
// advances the tip only while the durable synced block still equals it. NewTip
// must extend ExpectedTip by exactly one block.
type AdvanceTipRequest struct {
	// ExpectedTip is the wallet's synced block observed during preparation.
	ExpectedTip BlockRef

	// NewTip is the block to advance the wallet's synced tip to. It is
	// recorded if not already present and must be the block immediately
	// following ExpectedTip.
	NewTip BlockRef

	// Guards declares the optimistic version-domain preconditions applied in
	// the same transaction. It is empty for a plain tip advance; a caller that
	// must also invalidate concurrent preparation (for example a scan) sets
	// the affected version guards. The KV backend has no version row and
	// ignores it.
	Guards Guards

	// OperationID keys the durable journal (SQL only) so a replay is served
	// from the journal instead of advancing the tip again.
	OperationID []byte
}

// AdvanceTipResult is the committed result of a wallet-tip advance, materialized
// so cache publication and notification never need the original write
// transaction. It embeds CommittedFacts, whose single event is the wallet-tip
// advance.
type AdvanceTipResult struct {
	CommittedFacts

	// Tip is the wallet's synced tip after the advance.
	Tip BlockRef
}
