// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import "errors"

// Runtime-state and operation-journal sentinels. The salvage runtime store
// returns these typed errors so the backend-neutral Stage 3 orchestration can
// react to a stale optimistic-concurrency guard or a conflicting operation via
// errors.Is, without depending on a specific backend. They live in this neutral
// contract package because the shared prepare/commit orchestration and both the
// SQL and KV backends reference the same sentinels.
var (
	// ErrStaleWalletState indicates a guarded state-version bump failed
	// because the wallet state version no longer matched the caller's
	// snapshot. The prepared work must be revalidated against the current
	// version before it is retried.
	ErrStaleWalletState = errors.New("stale wallet state version")

	// ErrStaleHistoryEpoch indicates a guarded history-epoch bump failed
	// because the history epoch advanced since the caller's snapshot, for
	// example a concurrent history reset.
	ErrStaleHistoryEpoch = errors.New("stale history epoch")

	// ErrStaleSecretState indicates a guarded secret-version bump failed
	// because the secret version advanced since the caller's snapshot, for
	// example a concurrent passphrase rotation.
	ErrStaleSecretState = errors.New("stale secret version")

	// ErrOperationConflict indicates an operation id was reused with a
	// different request hash or history epoch than the already recorded
	// operation. A committed operation is only replay-safe for the exact
	// request that produced it.
	ErrOperationConflict = errors.New(
		"operation id reused with a different request",
	)

	// ErrStaleAccountIndex indicates a guarded branch-index allocation failed
	// because the account's next index no longer matched the caller's expected
	// value, or the account was missing. The caller rereads the account before
	// preparing the allocation again.
	ErrStaleAccountIndex = errors.New("stale account branch index")

	// ErrStaleLastAccount indicates a guarded account-number allocation failed
	// because the scope's last allocated account no longer matched the
	// caller's expected value, for example a concurrent account creation. The
	// caller rereads the last account before preparing the allocation again.
	ErrStaleLastAccount = errors.New("stale last allocated account")

	// ErrStaleTip indicates a guarded wallet-tip advance failed because the
	// wallet's current synced block no longer matched the caller's expected
	// tip, for example a concurrent advance or a reorg. The caller rereads the
	// synced tip before preparing the advance again.
	ErrStaleTip = errors.New("stale synced tip")

	// ErrNonContiguousTip indicates a wallet-tip advance was rejected because
	// the requested new tip does not extend the caller's expected tip by
	// exactly one block. It is a request-shape error, not an optimistic
	// concurrency conflict, so it never rolls back partial durable state.
	ErrNonContiguousTip = errors.New("new tip does not extend current tip")

	// ErrReservationConflict indicates a funding-plan state transition was
	// rejected because the plan was missing or no longer in the state the
	// transition requires, for example consuming a plan that is not reserved.
	ErrReservationConflict = errors.New("funding reservation conflict")

	// ErrAmbiguousCommit indicates a semantic runtime commit whose durable
	// outcome is unknown to the caller: the transaction may or may not have
	// landed. The caller must resolve it by rereading durable state rather
	// than blindly repeating the operation, since a repeat of a landed commit
	// would either double-apply or fail an optimistic guard.
	ErrAmbiguousCommit = errors.New("ambiguous runtime commit")
)
