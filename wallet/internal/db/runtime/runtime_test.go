package runtime

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/stretchr/testify/require"
)

// Test errors used by the runtime helper tests.
var (
	errRuntimeBusy  = errors.New("busy")
	errRuntimeRetry = errors.New("retry")
	errRuntimeOther = errors.New("other")
)

// fakeStore implements the runtime hook interfaces for tests.
type fakeStore struct {
	healthyErr      error
	classifyFn      func(error) error
	errorCount      int
	retryAttempts   int
	retrySuccesses  int
	retryExhausted  int
	ambiguousCommit int
}

// CheckHealthy returns the configured health-check result for fakeStore.
func (s *fakeStore) CheckHealthy() error {
	return s.healthyErr
}

// ClassifyError applies the configured classifier when one is present.
func (s *fakeStore) ClassifyError(err error) error {
	if s.classifyFn != nil {
		return s.classifyFn(err)
	}

	return err
}

// RecordError increments the fake classified-error counter.
func (s *fakeStore) RecordError(error) {
	s.errorCount++
}

// RecordRetryAttempt increments the fake retry-attempt counter.
func (s *fakeStore) RecordRetryAttempt() {
	s.retryAttempts++
}

// RecordRetrySuccess increments the fake retry-success counter.
func (s *fakeStore) RecordRetrySuccess() {
	s.retrySuccesses++
}

// RecordRetryExhausted increments the fake retry-exhausted counter.
func (s *fakeStore) RecordRetryExhausted() {
	s.retryExhausted++
}

// TestAmbiguousTxCommitError verifies the sentinel-matching and unwrap
// behavior of AmbiguousTxCommitError.
func TestAmbiguousTxCommitError(t *testing.T) {
	t.Parallel()

	err := &AmbiguousTxCommitError{Err: io.EOF}
	wrappedSentinel := fmt.Errorf("wrap: %w", ErrAmbiguousTxCommit)

	require.ErrorIs(t, err, ErrAmbiguousTxCommit)
	require.False(t, err.Is(wrappedSentinel))
	require.Equal(t, io.EOF.Error(), err.Error())
	require.ErrorIs(t, err, io.EOF)
	require.Equal(
		t, ErrAmbiguousTxCommit.Error(), (&AmbiguousTxCommitError{}).Error(),
	)
	require.NoError(t, (*AmbiguousTxCommitError)(nil).Unwrap())
}

// TestCommitTransportError verifies that transport-shaped commit failures are
// detected as ambiguous-outcome candidates.
func TestCommitTransportError(t *testing.T) {
	t.Parallel()

	require.True(t, isCommitTransportError(io.EOF))
	require.True(t, isCommitTransportError(driver.ErrBadConn))
	require.True(t, isCommitTransportError(sql.ErrConnDone))
	require.True(t, isCommitTransportError(netTimeoutError{}))
	require.False(t, isCommitTransportError(errRuntimeOther))
	require.NotNil(t, extractNetError(netTimeoutError{}))
	require.Nil(t, extractNetError(errRuntimeOther))
}

// TestReadHealthyCheck verifies that unhealthy stores fail fast.
func TestReadHealthyCheck(t *testing.T) {
	t.Parallel()

	hooks := &fakeStore{healthyErr: ErrStoreUnhealthy}
	_, err := Read(context.Background(), hooks, struct{}{}, ReadConfig{
		MaxAttempts: 1,
		BaseDelay:   time.Millisecond,
		MaxDelay:    time.Millisecond,
	},
		func(context.Context, struct{}) (struct{}, error) {
			return struct{}{}, nil
		})
	require.ErrorIs(t, err, ErrStoreUnhealthy)
}

// TestReadInvalidConfig verifies that invalid retry settings fail fast.
func TestReadInvalidConfig(t *testing.T) {
	t.Parallel()

	_, err := Read(context.Background(), &fakeStore{}, struct{}{},
		ReadConfig{}, func(context.Context, struct{}) (struct{}, error) {
			return struct{}{}, nil
		})
	require.EqualError(t, err,
		"build read config: read max attempts must be positive")
}

// TestReadReturnsValue verifies that successful reads return their value and do
// not force disabled retries to provide unused backoff delays.
func TestReadReturnsValue(t *testing.T) {
	t.Parallel()

	hooks := &fakeStore{}
	result, err := Read(context.Background(), hooks, struct{}{}, ReadConfig{
		MaxAttempts: 1,
	},
		func(context.Context, struct{}) (string, error) {
			return "ok", nil
		})
	require.NoError(t, err)
	require.Equal(t, "ok", result)
}

// TestReadNoRowsPassthrough verifies that no-row results are preserved.
func TestReadNoRowsPassthrough(t *testing.T) {
	t.Parallel()

	hooks := &fakeStore{}
	result, err := Read(context.Background(), hooks, struct{}{}, ReadConfig{
		MaxAttempts: 1,
		BaseDelay:   time.Millisecond,
		MaxDelay:    time.Millisecond,
	},
		func(context.Context, struct{}) (string, error) {
			return "", sql.ErrNoRows
		})
	require.ErrorIs(t, err, sql.ErrNoRows)
	require.Empty(t, result)
	require.Zero(t, hooks.errorCount)
}

// TestReadRetriesTransientError verifies that transient read failures retry,
// record stats, and eventually succeed.
func TestReadRetriesTransientError(t *testing.T) {
	t.Parallel()

	hooks := &fakeStore{classifyFn: func(err error) error {
		return dberr.NewSQLError(
			dberr.BackendSQLite, dberr.ReasonBusy, "5", err,
		)
	}}

	attempts := 0
	result, err := readWithConfig(
		context.Background(), hooks, struct{}{},
		func(context.Context, struct{}) (string, error) {
			attempts++
			if attempts == 1 {
				return "", errRuntimeBusy
			}

			return "ok", nil
		},
		readConfig{
			attempts: 2,
			base:     time.Millisecond,
			max:      time.Millisecond,
			jitter:   func(delay time.Duration) time.Duration { return delay },
			timer:    immediateTimer,
		},
	)
	require.NoError(t, err)
	require.Equal(t, "ok", result)
	require.Equal(t, 1, hooks.retryAttempts)
	require.Equal(t, 1, hooks.retrySuccesses)
	require.Equal(t, 1, hooks.errorCount)
}

// TestReadRetryExhausted verifies that transient reads return the final
// classified error and a zero value after their retry budget is exhausted.
func TestReadRetryExhausted(t *testing.T) {
	t.Parallel()

	hooks := &fakeStore{classifyFn: func(err error) error {
		return dberr.NewSQLError(
			dberr.BackendPostgres, dberr.ReasonSerialization,
			"40001", err,
		)
	}}

	result, err := readWithConfig(
		context.Background(), hooks, struct{}{},
		func(context.Context, struct{}) (string, error) {
			return "", errRuntimeRetry
		},
		readConfig{
			attempts: 1,
			base:     time.Millisecond,
			max:      time.Millisecond,
			jitter:   func(delay time.Duration) time.Duration { return delay },
			timer:    immediateTimer,
		},
	)

	var sqlErr *dberr.SQLError

	require.Empty(t, result)
	require.ErrorAs(t, err, &sqlErr)
	require.Equal(t, dberr.ClassTransient, sqlErr.Class())
	require.Equal(t, 1, hooks.retryExhausted)
}

// TestReadWrappedContextCancellation verifies that wrapped caller cancellation
// is not hidden behind retry logic.
func TestReadWrappedContextCancellation(t *testing.T) {
	t.Parallel()

	hooks := &fakeStore{}
	wrappedCanceled := fmt.Errorf("read accounts: %w", context.Canceled)

	result, err := Read(context.Background(), hooks, struct{}{}, ReadConfig{
		MaxAttempts: 1,
		BaseDelay:   time.Millisecond,
		MaxDelay:    time.Millisecond,
	},
		func(context.Context, struct{}) (string, error) {
			return "", wrappedCanceled
		})
	require.Empty(t, result)
	require.Same(t, wrappedCanceled, err)
	require.ErrorIs(t, err, context.Canceled)
}

// TestReadWaitCancellation verifies that cancellation during backoff returns
// ctx.Err.
func TestReadWaitCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	hooks := &fakeStore{classifyFn: func(err error) error {
		return dberr.NewSQLError(
			dberr.BackendSQLite, dberr.ReasonBusy, "5", err,
		)
	}}

	result, err := readWithConfig(
		ctx, hooks, struct{}{},
		func(context.Context, struct{}) (string, error) {
			return "", errRuntimeBusy
		},
		readConfig{
			attempts: 2,
			base:     time.Millisecond,
			max:      time.Millisecond,
			jitter:   func(delay time.Duration) time.Duration { return delay },
			timer:    time.NewTimer,
		},
	)
	require.Empty(t, result)
	require.ErrorIs(t, err, context.Canceled)
}

// TestReadUtilities verifies the remaining read helper branches.
func TestReadUtilities(t *testing.T) {
	t.Parallel()

	require.Equal(t, 100*time.Millisecond,
		retryDelay(10, 10*time.Millisecond, 100*time.Millisecond))
	require.Equal(t, 100*time.Millisecond,
		retryDelay(63, 10*time.Millisecond, 100*time.Millisecond))
	require.Equal(t, context.DeadlineExceeded,
		unwrapContextError(context.DeadlineExceeded))

	wrappedCanceled := fmt.Errorf("read: %w", context.Canceled)
	require.Same(t, wrappedCanceled, unwrapContextError(wrappedCanceled))
	require.NoError(t, unwrapContextError(sql.ErrNoRows))
}

// immediateTimer returns a timer that fires immediately.
func immediateTimer(time.Duration) *time.Timer {
	return time.NewTimer(0)
}

// netTimeoutError is a test helper that reports a transport timeout.
type netTimeoutError struct{}

// Error returns the static timeout error string.
func (e netTimeoutError) Error() string {
	return "timeout"
}

// Timeout reports that the test error is a timeout.
func (e netTimeoutError) Timeout() bool {
	return true
}
