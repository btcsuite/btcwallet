package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/stretchr/testify/require"
)

const runtimeAppliedResult = "applied"

// Test errors used by the runtime helper tests.
var (
	errRuntimeBusy     = errors.New("busy")
	errRuntimeRetry    = errors.New("retry")
	errRuntimeCallback = errors.New("callback failed")
	errRuntimeOther    = errors.New("other")
	errRuntimeNoRows   = errors.New("no rows")
)

// fakeStore implements the runtime hook interfaces for tests.
type fakeStore struct {
	healthyErr       error
	classifyFn       func(error) error
	errorCount       int
	retryAttempts    int
	retrySuccesses   int
	retryExhausted   int
	ambiguousCommits int
	noRows           error
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

// RecordAmbiguousTxCommit increments the fake ambiguous-commit counter.
func (s *fakeStore) RecordAmbiguousTxCommit() {
	s.ambiguousCommits++
}

// IsNoRows reports whether err matches the configured no-row sentinel.
func (s *fakeStore) IsNoRows(err error) bool {
	return errors.Is(err, s.noRows)
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

	hooks := &fakeStore{noRows: errRuntimeNoRows}
	result, err := Read(context.Background(), hooks, struct{}{}, ReadConfig{
		MaxAttempts: 1,
		BaseDelay:   time.Millisecond,
		MaxDelay:    time.Millisecond,
	},
		func(context.Context, struct{}) (string, error) {
			return "", errRuntimeNoRows
		})
	require.ErrorIs(t, err, errRuntimeNoRows)
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
	require.NoError(t, unwrapContextError(errRuntimeNoRows))
}

// TestWriteHealthyCheck verifies that unhealthy stores fail fast before
// starting a transaction.
func TestWriteHealthyCheck(t *testing.T) {
	t.Parallel()

	hooks := &fakeStore{healthyErr: ErrStoreUnhealthy}
	result, err := Write(
		context.Background(), hooks, fakeTxOps(nil),
		func(struct{}) (string, error) { return "", nil },
	)
	require.Empty(t, result)
	require.ErrorIs(t, err, ErrStoreUnhealthy)
}

// TestWriteReturnsValue verifies that successful writes return their value only
// after commit succeeds.
func TestWriteReturnsValue(t *testing.T) {
	t.Parallel()

	hooks := &fakeStore{}
	tx := &fakeTx{}
	result, err := Write(
		context.Background(), hooks, fakeTxOps(tx),
		func(struct{}) (string, error) { return "ok", nil },
	)
	require.NoError(t, err)
	require.Equal(t, "ok", result)
	require.True(t, tx.committed)
	require.True(t, tx.rolledBack)
}

// TestWriteBeginFailure verifies that begin failures are classified and
// recorded.
func TestWriteBeginFailure(t *testing.T) {
	t.Parallel()

	hooks := &fakeStore{classifyFn: func(err error) error {
		return dberr.NewSQLError(
			dberr.BackendPostgres, dberr.ReasonUnavailable, "", err,
		)
	}}

	result, err := Write(
		context.Background(), hooks, fakeTxOps(nil),
		func(struct{}) (string, error) { return "", nil },
	)

	var sqlErr *dberr.SQLError

	require.Empty(t, result)
	require.ErrorAs(t, err, &sqlErr)
	require.Equal(t, dberr.ReasonUnavailable, sqlErr.Reason)
	require.Equal(t, 1, hooks.errorCount)
}

// TestWriteCallbackErrorPassthrough verifies that non-SQL callback errors pass
// through unchanged and do not leak a result value.
func TestWriteCallbackErrorPassthrough(t *testing.T) {
	t.Parallel()

	hooks := &fakeStore{}
	callbackErr := errRuntimeCallback

	result, err := Write(
		context.Background(), hooks, fakeTxOps(&fakeTx{}),
		func(struct{}) (string, error) { return "", callbackErr },
	)
	require.Empty(t, result)
	require.ErrorIs(t, err, callbackErr)
	require.Zero(t, hooks.errorCount)
}

// TestWriteCallbackErrorClassified verifies that SQL-like callback failures are
// normalized through the backend classifier before they reach callers.
func TestWriteCallbackErrorClassified(t *testing.T) {
	t.Parallel()

	hooks := &fakeStore{classifyFn: func(err error) error {
		return dberr.NewSQLError(
			dberr.BackendPostgres, dberr.ReasonConstraint, "23505", err,
		)
	}}

	result, err := Write(
		context.Background(), hooks, fakeTxOps(&fakeTx{}),
		func(struct{}) (string, error) { return "", errRuntimeCallback },
	)

	var sqlErr *dberr.SQLError

	require.Empty(t, result)
	require.ErrorAs(t, err, &sqlErr)
	require.Equal(t, dberr.ReasonConstraint, sqlErr.Reason)
	require.Equal(t, 1, hooks.errorCount)
}

// TestWriteCanceledBeforeCommit verifies that caller cancellation after the
// callback prevents commit and still invokes transaction cleanup.
func TestWriteCanceledBeforeCommit(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	tx := &fakeTx{}
	result, err := Write(
		ctx, &fakeStore{}, fakeTxOps(tx),
		func(struct{}) (string, error) {
			cancel()

			return runtimeAppliedResult, nil
		},
	)
	require.Empty(t, result)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, tx.committed)
	require.True(t, tx.rolledBack)
}

// TestWriteCommitAmbiguous verifies that transport failures during commit are
// wrapped as ambiguous commit errors, recorded, and return a zero value.
func TestWriteCommitAmbiguous(t *testing.T) {
	t.Parallel()

	hooks := &fakeStore{classifyFn: func(err error) error {
		return dberr.NewSQLError(
			dberr.BackendPostgres, dberr.ReasonUnavailable,
			"08006", err,
		)
	}}

	tx := &fakeTx{commitErr: io.EOF, commitAmbiguous: true}
	result, err := Write(
		context.Background(), hooks, fakeTxOps(tx),
		func(struct{}) (string, error) { return runtimeAppliedResult, nil },
	)
	require.Empty(t, result)
	require.ErrorIs(t, err, ErrAmbiguousTxCommit)

	var sqlErr *dberr.SQLError
	require.ErrorAs(t, err, &sqlErr)
	require.Equal(t, dberr.ReasonUnavailable, sqlErr.Reason)
	require.Equal(t, 1, hooks.ambiguousCommits)
	require.Equal(t, 1, hooks.errorCount)
}

// TestWriteCommitUnavailable verifies that classified availability errors
// without a transport failure stay ordinary commit errors.
func TestWriteCommitUnavailable(t *testing.T) {
	t.Parallel()

	hooks := &fakeStore{classifyFn: func(err error) error {
		return dberr.NewSQLError(
			dberr.BackendPostgres, dberr.ReasonUnavailable,
			"08006", err,
		)
	}}

	tx := &fakeTx{commitErr: errRuntimeOther}
	result, err := Write(
		context.Background(), hooks, fakeTxOps(tx),
		func(struct{}) (string, error) { return runtimeAppliedResult, nil },
	)
	require.Empty(t, result)
	require.NotErrorIs(t, err, ErrAmbiguousTxCommit)

	var sqlErr *dberr.SQLError
	require.ErrorAs(t, err, &sqlErr)
	require.Equal(t, dberr.ReasonUnavailable, sqlErr.Reason)
	require.Zero(t, hooks.ambiguousCommits)
	require.Equal(t, 1, hooks.errorCount)
}

// immediateTimer returns a timer that fires immediately.
func immediateTimer(time.Duration) *time.Timer {
	return time.NewTimer(0)
}

// fakeTx is a driver-neutral transaction test double.
type fakeTx struct {
	commitErr       error
	commitAmbiguous bool
	committed       bool
	rolledBack      bool
}

// fakeTxOps returns transaction operations for tx or an injected begin
// failure when tx is nil.
func fakeTxOps(tx *fakeTx) WriteTxOps[*fakeTx, struct{}] {
	return WriteTxOps[*fakeTx, struct{}]{
		Begin: func(context.Context) (*fakeTx, error) {
			if tx == nil {
				return nil, errRuntimeOther
			}

			return tx, nil
		},
		Bind: func(*fakeTx) struct{} {
			return struct{}{}
		},
		Commit: func(tx *fakeTx) CommitResult {
			tx.committed = true

			return CommitResult{
				Err:       tx.commitErr,
				Ambiguous: tx.commitAmbiguous,
			}
		},
		Rollback: func(tx *fakeTx) error {
			tx.rolledBack = true

			return nil
		},
	}
}
