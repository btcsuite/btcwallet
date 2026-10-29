package runtime

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const runtimeAppliedResult = "applied"

// Test errors used by the runtime helper tests.
var (
	errRuntimeBusy     = errors.New("busy")
	errRuntimeRetry    = errors.New("retry")
	errRuntimeCallback = errors.New("callback failed")
	errRuntimeOther    = errors.New("other")
	errRuntimeNoRows   = sql.ErrNoRows
)

// runtimeHooksMock verifies the public runtime contract without independent
// counters that could disagree with the expected calls.
type runtimeHooksMock struct {
	mock.Mock
}

var (
	_ ReadHooks  = (*runtimeHooksMock)(nil)
	_ WriteHooks = (*runtimeHooksMock)(nil)
)

// newRuntimeHooksMock verifies all arranged runtime calls once at cleanup.
func newRuntimeHooksMock(t *testing.T) *runtimeHooksMock {
	t.Helper()

	hooks := &runtimeHooksMock{}
	hooks.Test(t)
	t.Cleanup(func() {
		hooks.AssertExpectations(t)
	})

	return hooks
}

// CheckHealthy returns the configured admission result.
func (s *runtimeHooksMock) CheckHealthy() error {
	args := s.Called()

	return args.Error(0)
}

// ClassifyError supplies the configured backend normalization.
func (s *runtimeHooksMock) ClassifyError(err error) error {
	args := s.Called(err)

	return args.Error(0)
}

// RecordError records the expected runtime outcome.
func (s *runtimeHooksMock) RecordError(err error) {
	s.Called(err)
}

// RecordRetryAttempt records the expected runtime outcome.
func (s *runtimeHooksMock) RecordRetryAttempt() {
	s.Called()
}

// RecordRetrySuccess records the expected runtime outcome.
func (s *runtimeHooksMock) RecordRetrySuccess() {
	s.Called()
}

// RecordRetryExhausted records the expected runtime outcome.
func (s *runtimeHooksMock) RecordRetryExhausted() {
	s.Called()
}

// RecordAmbiguousTxCommit records the expected runtime outcome.
func (s *runtimeHooksMock) RecordAmbiguousTxCommit() {
	s.Called()
}

// TestReadHealthyCheck verifies that unhealthy stores fail fast.
func TestReadHealthyCheck(t *testing.T) {
	t.Parallel()

	// Arrange: Reject admission before the read callback can execute. Explicit
	// expectations also reject any extra lifecycle or accounting call.
	hooks := newRuntimeHooksMock(t)
	hooks.On("CheckHealthy").Return(ErrStoreUnhealthy).Once()

	// Act: Call Read with an otherwise successful callback; the unhealthy
	// admission result must stop execution before callback work.
	_, err := Read(context.Background(), hooks, struct{}{}, ReadConfig{
		MaxAttempts: 1,
		BaseDelay:   time.Millisecond,
		MaxDelay:    time.Millisecond,
	},
		func(context.Context, struct{}) (struct{}, error) {
			return struct{}{}, nil
		})

	// Assert: Check the returned value and error identity. Cleanup verifies
	// each declared hook once and rejects unplanned retries or accounting.
	require.ErrorIs(t, err, ErrStoreUnhealthy)
}

// TestReadInvalidConfig verifies that invalid retry settings fail fast.
func TestReadInvalidConfig(t *testing.T) {
	t.Parallel()

	// Arrange: Reject invalid retry settings before consulting any runtime
	// hook. Explicit expectations also reject any extra lifecycle or accounting
	// call.
	hooks := newRuntimeHooksMock(t)

	// Act: Call Read with zero attempts and a successful callback, so any hook
	// invocation would expose incorrect validation ordering.
	_, err := Read(context.Background(), hooks, struct{}{},
		ReadConfig{}, func(context.Context, struct{}) (struct{}, error) {
			return struct{}{}, nil
		})

	// Assert: Check the returned value and error identity. Cleanup verifies
	// each declared hook once and rejects unplanned retries or accounting.
	require.EqualError(t, err,
		"build read config: read max attempts must be positive")
}

// TestReadReturnsValue verifies that successful reads return their value and do
// not force disabled retries to provide unused backoff delays.
func TestReadReturnsValue(t *testing.T) {
	t.Parallel()

	// Arrange: Admit one successful read with retries disabled. Explicit
	// expectations also reject any extra lifecycle or accounting call.
	hooks := newRuntimeHooksMock(t)
	hooks.On("CheckHealthy").Return(nil).Once()

	// Act: Return a value with MaxAttempts=1 and zero delays, exercising the
	// existing disabled-retry path through Read.
	result, err := Read(context.Background(), hooks, struct{}{}, ReadConfig{
		MaxAttempts: 1,
	},
		func(context.Context, struct{}) (string, error) {
			return "ok", nil
		})

	// Assert: Check the returned value and error identity. Cleanup verifies
	// each declared hook once and rejects unplanned retries or accounting.
	require.NoError(t, err)
	require.Equal(t, "ok", result)
}

// TestReadNoRowsPassthrough verifies that no-row results are preserved.
func TestReadNoRowsPassthrough(t *testing.T) {
	t.Parallel()

	// Arrange: Return the shared no-row sentinel without classifying or
	// counting it. Explicit expectations also reject any extra lifecycle or
	// accounting call.
	hooks := newRuntimeHooksMock(t)
	hooks.On("CheckHealthy").Return(nil).Once()

	// Act: Return sql.ErrNoRows from the callback. Read must preserve it
	// without consulting the backend classifier or retry accounting.
	result, err := Read(context.Background(), hooks, struct{}{}, ReadConfig{
		MaxAttempts: 1,
		BaseDelay:   time.Millisecond,
		MaxDelay:    time.Millisecond,
	},
		func(context.Context, struct{}) (string, error) {
			return "", errRuntimeNoRows
		})

	// Assert: Check the returned value and error identity. Cleanup verifies
	// each declared hook once and rejects unplanned retries or accounting.
	require.ErrorIs(t, err, errRuntimeNoRows)
	require.Empty(t, result)
}

// TestReadRetriesTransientError verifies that transient read failures retry,
// record stats, and eventually succeed.
func TestReadRetriesTransientError(t *testing.T) {
	t.Parallel()

	// Arrange: Classify the initial busy result, then permit the existing
	// second attempt. Explicit expectations also reject any extra lifecycle or
	// accounting call.
	hooks := newRuntimeHooksMock(t)
	hooks.On("CheckHealthy").Return(nil).Once()

	classified := dberr.NewSQLError(
		dberr.BackendSQLite, dberr.ReasonBusy, "5", errRuntimeBusy,
	)
	hooks.On("ClassifyError", errRuntimeBusy).Return(classified).Once()
	hooks.On("RecordError", classified).Once()
	hooks.On("RecordRetryAttempt").Return().Once()
	hooks.On("RecordRetrySuccess").Return().Once()

	attempts := 0

	// Act: Return busy on the first callback and success on the second;
	// immediateTimer drives the one backoff without a wall-clock delay.
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

	// Assert: Check the returned value and error identity. Cleanup verifies
	// each declared hook once and rejects unplanned retries or accounting.
	require.NoError(t, err)
	require.Equal(t, "ok", result)
}

// TestReadRetryExhausted verifies that transient reads return the final
// classified error and a zero value after their retry budget is exhausted.
func TestReadRetryExhausted(t *testing.T) {
	t.Parallel()

	// Arrange: Exhaust the single-attempt budget on a classified transient
	// error. Explicit expectations also reject any extra lifecycle or
	// accounting call.
	hooks := newRuntimeHooksMock(t)
	hooks.On("CheckHealthy").Return(nil).Once()

	classified := dberr.NewSQLError(
		dberr.BackendPostgres, dberr.ReasonSerialization, "40001",
		errRuntimeRetry,
	)
	hooks.On("ClassifyError", errRuntimeRetry).Return(classified).Once()
	hooks.On("RecordError", classified).Once()
	hooks.On("RecordRetryExhausted").Return().Once()

	// Act: Return the transient cause with a one-attempt budget, forcing the
	// terminal retry path without scheduling another callback.
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

	// Assert: Check the returned value and error identity. Cleanup verifies
	// each declared hook once and rejects unplanned retries or accounting.
	require.Empty(t, result)
	require.ErrorAs(t, err, &sqlErr)
	require.Equal(t, dberr.ClassTransient, sqlErr.Class())
}

// TestReadWrappedContextCancellation verifies that wrapped caller cancellation
// is not hidden behind retry logic.
func TestReadWrappedContextCancellation(t *testing.T) {
	t.Parallel()

	// Arrange: Preserve the wrapped caller cancellation without backend
	// classification. Explicit expectations also reject any extra lifecycle or
	// accounting call.
	hooks := newRuntimeHooksMock(t)
	hooks.On("CheckHealthy").Return(nil).Once()

	wrappedCanceled := fmt.Errorf("read accounts: %w", context.Canceled)

	// Act: Return the wrapped context cancellation from the read callback after
	// successful health admission, exercising error passthrough.
	result, err := Read(context.Background(), hooks, struct{}{}, ReadConfig{
		MaxAttempts: 1,
		BaseDelay:   time.Millisecond,
		MaxDelay:    time.Millisecond,
	},
		func(context.Context, struct{}) (string, error) {
			return "", wrappedCanceled
		})

	// Assert: Check the returned value and error identity. Cleanup verifies
	// each declared hook once and rejects unplanned retries or accounting.
	require.Empty(t, result)
	require.Same(t, wrappedCanceled, err)
	require.ErrorIs(t, err, context.Canceled)
}

// TestReadWaitCancellation verifies that cancellation during backoff returns
// ctx.Err.
func TestReadWaitCancellation(t *testing.T) {
	t.Parallel()

	// Arrange: Cancel before waiting while retaining the first transient
	// attempt accounting. Explicit expectations also reject any extra lifecycle
	// or accounting call.
	hooks := newRuntimeHooksMock(t)
	hooks.On("CheckHealthy").Return(nil).Once()

	classified := dberr.NewSQLError(
		dberr.BackendSQLite, dberr.ReasonBusy, "5", errRuntimeBusy,
	)
	hooks.On("ClassifyError", errRuntimeBusy).Return(classified).Once()
	hooks.On("RecordError", classified).Once()
	hooks.On("RecordRetryAttempt").Return().Once()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Act: Run the busy callback with an already-canceled context, then let the
	// first retry wait observe that cancellation.
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

	// Assert: Check the returned value and error identity. Cleanup verifies
	// each declared hook once and rejects unplanned retries or accounting.
	require.Empty(t, result)
	require.ErrorIs(t, err, context.Canceled)
}

// TestReadUtilities verifies the remaining read helper branches.
func TestReadUtilities(t *testing.T) {
	t.Parallel()

	// Arrange: Fix a capped backoff and a wrapped cancellation so the helper
	// results can be compared without timers or backend access.
	wrapped := fmt.Errorf("read: %w", context.Canceled)

	// Act: Evaluate both saturating delays and the existing context helpers.
	delay := retryDelay(10, 10*time.Millisecond, 100*time.Millisecond)
	overflow := retryDelay(63, 10*time.Millisecond, 100*time.Millisecond)
	deadline := unwrapContextError(context.DeadlineExceeded)
	canceled := unwrapContextError(wrapped)
	ordinary := unwrapContextError(errRuntimeNoRows)

	// Assert: Backoff stays capped and only context causes are extracted,
	// preserving an existing wrapper rather than synthesizing a new error.
	require.Equal(t, 100*time.Millisecond, delay)
	require.Equal(t, 100*time.Millisecond, overflow)
	require.Equal(t, context.DeadlineExceeded, deadline)
	require.Same(t, wrapped, canceled)
	require.NoError(t, ordinary)
}

// TestWriteHealthyCheck verifies that unhealthy stores fail fast before
// starting a transaction.
func TestWriteHealthyCheck(t *testing.T) {
	t.Parallel()

	// Arrange: Reject admission before a transaction can begin. Explicit
	// expectations also reject any extra lifecycle or accounting call.
	hooks := newRuntimeHooksMock(t)
	hooks.On("CheckHealthy").Return(ErrStoreUnhealthy).Once()

	// Act: Invoke Write with no transaction expectations; health rejection must
	// take precedence without beginning a transaction.
	result, err := Write(
		context.Background(), hooks, hooks.writeOps(),
		func(struct{}) (string, error) { return "", nil },
	)

	// Assert: Check the returned value and error identity. Cleanup verifies
	// each declared hook once and rejects unplanned retries or accounting.
	require.Empty(t, result)
	require.ErrorIs(t, err, ErrStoreUnhealthy)
}

// TestWriteReturnsValue verifies that successful writes return their value only
// after commit succeeds.
func TestWriteReturnsValue(t *testing.T) {
	t.Parallel()

	// Arrange: Admit one transaction and expose its value only after commit.
	// Explicit expectations also reject any extra lifecycle or accounting call.
	hooks := newRuntimeHooksMock(t)
	hooks.On("CheckHealthy").Return(nil).Once()

	hooks.On("Begin", mock.Anything).Return(1, nil).Once()
	hooks.On("Bind", 1).Return(struct{}{}).Once()
	hooks.On("Commit", 1).Return(CommitResult{}).Once()
	hooks.On("Rollback", 1).Return(nil).Once()

	// Act: Return a callback value through Write; the mock requires exactly one
	// commit and one deferred cleanup.
	result, err := Write(
		context.Background(), hooks, hooks.writeOps(),
		func(struct{}) (string, error) { return "ok", nil },
	)

	// Assert: Check the returned value and error identity. Cleanup verifies
	// each declared hook once and rejects unplanned retries or accounting.
	require.NoError(t, err)
	require.Equal(t, "ok", result)
}

// TestWriteBeginFailure verifies that begin failures are classified and
// recorded.
func TestWriteBeginFailure(t *testing.T) {
	t.Parallel()

	// Arrange: Classify and count one begin failure without invoking
	// transactional work. Explicit expectations also reject any extra lifecycle
	// or accounting call.
	hooks := newRuntimeHooksMock(t)
	hooks.On("CheckHealthy").Return(nil).Once()

	classified := dberr.NewSQLError(
		dberr.BackendPostgres, dberr.ReasonUnavailable, "",
		errRuntimeOther,
	)
	hooks.On("ClassifyError", errRuntimeOther).Return(classified).Once()
	hooks.On("RecordError", classified).Once()

	hooks.On("Begin", mock.Anything).Return(0, errRuntimeOther).Once()

	// Act: Return the arranged begin failure before invoking callback work and
	// classify that error through the arranged backend hooks.
	result, err := Write(
		context.Background(), hooks, hooks.writeOps(),
		func(struct{}) (string, error) { return "", nil },
	)

	var sqlErr *dberr.SQLError

	// Assert: Check the returned value and error identity. Cleanup verifies
	// each declared hook once and rejects unplanned retries or accounting.
	require.Empty(t, result)
	require.ErrorAs(t, err, &sqlErr)
	require.Equal(t, dberr.ReasonUnavailable, sqlErr.Reason)
}

// TestWriteCallbackErrorPassthrough verifies that non-SQL callback errors pass
// through unchanged and do not leak a result value.
func TestWriteCallbackErrorPassthrough(t *testing.T) {
	t.Parallel()

	// Arrange: Preserve an ordinary callback error and still clean up the
	// transaction. Explicit expectations also reject any extra lifecycle or
	// accounting call.
	hooks := newRuntimeHooksMock(t)
	hooks.On("CheckHealthy").Return(nil).Once()
	hooks.On(
		"ClassifyError", errRuntimeCallback,
	).Return(errRuntimeCallback).Once()

	callbackErr := errRuntimeCallback

	hooks.On("Begin", mock.Anything).Return(1, nil).Once()
	hooks.On("Bind", 1).Return(struct{}{}).Once()
	hooks.On("Rollback", 1).Return(nil).Once()

	// Act: Return an ordinary callback cause after Begin succeeds, so Write
	// must preserve it while running transaction cleanup.
	result, err := Write(
		context.Background(), hooks, hooks.writeOps(),
		func(struct{}) (string, error) { return "", callbackErr },
	)

	// Assert: Check the returned value and error identity. Cleanup verifies
	// each declared hook once and rejects unplanned retries or accounting.
	require.Empty(t, result)
	require.ErrorIs(t, err, callbackErr)
}

// TestWriteCallbackErrorClassified verifies that SQL-like callback failures are
// normalized through the backend classifier before they reach callers.
func TestWriteCallbackErrorClassified(t *testing.T) {
	t.Parallel()

	// Arrange: Normalize a backend callback failure without returning its
	// result. Explicit expectations also reject any extra lifecycle or
	// accounting call.
	hooks := newRuntimeHooksMock(t)
	hooks.On("CheckHealthy").Return(nil).Once()

	classified := dberr.NewSQLError(
		dberr.BackendPostgres, dberr.ReasonConstraint, "23505",
		errRuntimeCallback,
	)
	hooks.On("ClassifyError", errRuntimeCallback).Return(classified).Once()
	hooks.On("RecordError", classified).Once()

	hooks.On("Begin", mock.Anything).Return(1, nil).Once()
	hooks.On("Bind", 1).Return(struct{}{}).Once()
	hooks.On("Rollback", 1).Return(nil).Once()

	// Act: Return the callback failure after Begin and bind; the arranged
	// classifier supplies the constraint error returned by Write.
	result, err := Write(
		context.Background(), hooks, hooks.writeOps(),
		func(struct{}) (string, error) { return "", errRuntimeCallback },
	)

	var sqlErr *dberr.SQLError

	// Assert: Check the returned value and error identity. Cleanup verifies
	// each declared hook once and rejects unplanned retries or accounting.
	require.Empty(t, result)
	require.ErrorAs(t, err, &sqlErr)
	require.Equal(t, dberr.ReasonConstraint, sqlErr.Reason)
}

// TestWriteCanceledBeforeCommit verifies that caller cancellation after the
// callback prevents commit and still invokes transaction cleanup.
func TestWriteCanceledBeforeCommit(t *testing.T) {
	t.Parallel()

	// Arrange: Cancel inside the callback so deferred rollback runs without
	// commit. Explicit expectations also reject any extra lifecycle or
	// accounting call.
	hooks := newRuntimeHooksMock(t)
	hooks.On("CheckHealthy").Return(nil).Once()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	hooks.On("Begin", mock.Anything).Return(1, nil).Once()
	hooks.On("Bind", 1).Return(struct{}{}).Once()
	hooks.On("Rollback", 1).Return(nil).Once()

	// Act: Cancel from the callback after applying its local result; Write must
	// skip Commit and perform its deferred rollback.
	result, err := Write(
		ctx, hooks, hooks.writeOps(),
		func(struct{}) (string, error) {
			cancel()

			return runtimeAppliedResult, nil
		},
	)

	// Assert: Check the returned value and error identity. Cleanup verifies
	// each declared hook once and rejects unplanned retries or accounting.
	require.Empty(t, result)
	require.ErrorIs(t, err, context.Canceled)
}

// TestWriteCommitAmbiguous verifies that transport failures during commit are
// wrapped as ambiguous commit errors, recorded, and return a zero value.
func TestWriteCommitAmbiguous(t *testing.T) {
	t.Parallel()

	// Arrange: Record the supplied ambiguous commit outcome without retrying
	// the write. Explicit expectations also reject any extra lifecycle or
	// accounting call.
	hooks := newRuntimeHooksMock(t)
	hooks.On("CheckHealthy").Return(nil).Once()

	classified := dberr.NewSQLError(
		dberr.BackendPostgres, dberr.ReasonUnavailable, "08006", io.EOF,
	)
	hooks.On("ClassifyError", io.EOF).Return(classified).Once()
	hooks.On("RecordError", classified).Once()
	hooks.On("RecordAmbiguousTxCommit").Return().Once()

	hooks.On("Begin", mock.Anything).Return(1, nil).Once()
	hooks.On("Bind", 1).Return(struct{}{}).Once()
	hooks.On("Commit", 1).Return(CommitResult{
		Err:       io.EOF,
		Ambiguous: true,
	}).Once()
	hooks.On("Rollback", 1).Return(nil).Once()

	// Act: Commit the callback result with the supplied ambiguous EOF outcome,
	// allowing Write to wrap and account for it without retry.
	result, err := Write(
		context.Background(), hooks, hooks.writeOps(),
		func(struct{}) (string, error) { return runtimeAppliedResult, nil },
	)

	// Assert: Check the returned value and error identity. Cleanup verifies
	// each declared hook once and rejects unplanned retries or accounting.
	require.Empty(t, result)
	require.ErrorIs(t, err, ErrAmbiguousTxCommit)

	var sqlErr *dberr.SQLError
	require.ErrorAs(t, err, &sqlErr)
	require.Equal(t, dberr.ReasonUnavailable, sqlErr.Reason)
}

// TestWriteCommitUnavailable verifies that classified availability errors
// without a transport failure stay ordinary commit errors.
func TestWriteCommitUnavailable(t *testing.T) {
	t.Parallel()

	// Arrange: Keep a definite commit error distinct from an ambiguous outcome.
	// Explicit expectations also reject any extra lifecycle or accounting call.
	hooks := newRuntimeHooksMock(t)
	hooks.On("CheckHealthy").Return(nil).Once()

	classified := dberr.NewSQLError(
		dberr.BackendPostgres, dberr.ReasonUnavailable, "08006",
		errRuntimeOther,
	)
	hooks.On("ClassifyError", errRuntimeOther).Return(classified).Once()
	hooks.On("RecordError", classified).Once()

	hooks.On("Begin", mock.Anything).Return(1, nil).Once()
	hooks.On("Bind", 1).Return(struct{}{}).Once()
	hooks.On("Commit", 1).Return(CommitResult{
		Err: errRuntimeOther,
	}).Once()
	hooks.On("Rollback", 1).Return(nil).Once()

	// Act: Commit with a definite backend failure classified as unavailable,
	// keeping classification separate from ambiguity.
	result, err := Write(
		context.Background(), hooks, hooks.writeOps(),
		func(struct{}) (string, error) { return runtimeAppliedResult, nil },
	)

	// Assert: Check the returned value and error identity. Cleanup verifies
	// each declared hook once and rejects unplanned retries or accounting.
	require.Empty(t, result)
	require.NotErrorIs(t, err, ErrAmbiguousTxCommit)

	var sqlErr *dberr.SQLError
	require.ErrorAs(t, err, &sqlErr)
	require.Equal(t, dberr.ReasonUnavailable, sqlErr.Reason)
}

// immediateTimer returns a timer that fires immediately.
func immediateTimer(time.Duration) *time.Timer {
	return time.NewTimer(0)
}

// Begin supplies the transaction token or begin failure arranged by the test.
func (s *runtimeHooksMock) Begin(ctx context.Context) (int, error) {
	args := s.Called(ctx)

	return args.Int(0), args.Error(1)
}

// Bind verifies that Write binds queries to the token returned by Begin.
func (s *runtimeHooksMock) Bind(tx int) struct{} {
	args := s.Called(tx)
	queries, _ := args.Get(0).(struct{})

	return queries
}

// Commit supplies the backend outcome without inferring ambiguity in Write.
func (s *runtimeHooksMock) Commit(tx int) CommitResult {
	args := s.Called(tx)
	result, _ := args.Get(0).(CommitResult)

	return result
}

// Rollback verifies the sole deferred cleanup even when Commit is skipped.
func (s *runtimeHooksMock) Rollback(tx int) error {
	args := s.Called(tx)

	return args.Error(0)
}

// writeOps binds the lifecycle mock methods to the production callback surface.
func (s *runtimeHooksMock) writeOps() WriteTxOps[int, struct{}] {
	return WriteTxOps[int, struct{}]{
		Begin:    s.Begin,
		Bind:     s.Bind,
		Commit:   s.Commit,
		Rollback: s.Rollback,
	}
}
