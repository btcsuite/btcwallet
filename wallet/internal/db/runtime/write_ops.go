package runtime

import "context"

// CommitResult describes the backend result of committing a transaction.
type CommitResult struct {
	// Err is the raw backend error returned by the commit operation.
	Err error

	// Ambiguous reports whether Err left the final transaction outcome unknown.
	Ambiguous bool
}

// WriteTxOps adapts one backend transaction to the shared Write helper.
type WriteTxOps[Tx any, Q any] struct {
	// Begin starts a backend transaction using the caller's context.
	Begin func(context.Context) (Tx, error)

	// Bind returns the query handle bound to a backend transaction.
	Bind func(Tx) Q

	// Commit commits a backend transaction and reports its final outcome.
	Commit func(Tx) CommitResult

	// Rollback performs best-effort cleanup of a backend transaction.
	Rollback func(Tx) error
}
