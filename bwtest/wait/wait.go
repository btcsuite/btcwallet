// Package wait provides polling helpers for integration tests.
package wait

import (
	"errors"
	"time"
)

var (
	// ErrNoResponse is returned when f does not return within the timeout.
	ErrNoResponse = errors.New("method did not return within the timeout")
)

// PollInterval is the default polling interval used by NoError.
const PollInterval = 200 * time.Millisecond

// NoError polls f until it returns nil or the timeout is reached.
//
// If the timeout is reached, the last error returned by f is returned.
func NoError(f func() error, timeout time.Duration) error {
	// f is expected to be cheap and non-blocking. This helper is intended for
	// polling state (e.g. "is the node ready?") rather than performing a long
	// operation.
	//
	// NOTE: NoError does not interrupt f. If f blocks, NoError may block longer
	// than the provided timeout.

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	ticker := time.NewTicker(PollInterval)
	defer ticker.Stop()

	// Call f() immediately to avoid the initial ticker delay.
	lastErr := f()
	if lastErr == nil {
		return nil
	}

	for {
		select {
		case <-deadline.C:
			if lastErr == nil {
				return ErrNoResponse
			}

			return lastErr

		case <-ticker.C:
			err := f()
			if err == nil {
				return nil
			}

			lastErr = err
		}
	}
}
