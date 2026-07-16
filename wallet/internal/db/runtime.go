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
)
