// Package runtime provides shared SQL execution helpers for split backend
// packages.
package runtime

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
)

// Runtime sentinel errors returned by the shared SQL helpers.
var (
	// ErrAmbiguousTxCommit matches commit failures whose final database outcome
	// is unknown because the commit may already have reached the backend before
	// the client observed the failure.
	ErrAmbiguousTxCommit = errors.New("sql ambiguous tx commit")
)

// AmbiguousTxCommitError wraps a classified commit error returned when Commit
// fails after the final database outcome may already be decided by the
// backend.
//
// This lets callers ask two independent questions about the same failure:
//
//   - errors.Is(err, ErrAmbiguousTxCommit) reports that the transaction outcome
//     is unknown and should not be retried blindly.
//   - errors.As / errors.Unwrap expose the classified backend error for
//     logging, metrics, or backend-specific handling.
type AmbiguousTxCommitError struct {
	// Err is the classified backend error observed during commit.
	Err error
}

// Error returns the wrapped error string.
func (e *AmbiguousTxCommitError) Error() string {
	if e == nil || e.Err == nil {
		return ErrAmbiguousTxCommit.Error()
	}

	return e.Err.Error()
}

// Unwrap returns the wrapped classified commit error.
func (e *AmbiguousTxCommitError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.Err
}

// Is reports whether target matches the ambiguous commit sentinel.
func (e *AmbiguousTxCommitError) Is(target error) bool {
	switch target {
	case ErrAmbiguousTxCommit:
		return true

	default:
		return false
	}
}

// isCommitTransportError reports whether commit failed after the request may
// already have reached the backend.
func isCommitTransportError(err error) bool {
	if errors.Is(err, driver.ErrBadConn) || errors.Is(err, sql.ErrConnDone) ||
		errors.Is(err, io.EOF) {

		return true
	}

	return extractNetError(err) != nil
}

// extractNetError extracts a net.Error used by commit transport checks.
func extractNetError(err error) netError {
	var transportErr netError
	if errors.As(err, &transportErr) {
		return transportErr
	}

	return nil
}

// netError captures the net.Error behavior needed for commit transport checks.
type netError interface {
	error
	Timeout() bool
}
