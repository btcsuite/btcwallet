package runtime

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/stretchr/testify/require"
)

// Test errors used by the runtime helper tests.
var (
	errRuntimeBusy     = errors.New("busy")
	errRuntimeRetry    = errors.New("retry")
	errRuntimeCallback = errors.New("callback failed")
	errRuntimeOther    = errors.New("other")
	errRuntimeUnused   = errors.New("unused")
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
	db               *sql.DB
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

// RawDB returns the fake database handle used by transaction tests.
func (s *fakeStore) RawDB() *sql.DB {
	return s.db
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

// TestWriteHealthyCheck verifies that unhealthy stores fail fast before
// starting a transaction.
func TestWriteHealthyCheck(t *testing.T) {
	t.Parallel()

	hooks := &fakeStore{healthyErr: ErrStoreUnhealthy}
	result, err := Write(context.Background(), hooks, func(*sql.Tx) struct{} {
		return struct{}{}
	}, func(struct{}) (string, error) { return "", nil })
	require.Empty(t, result)
	require.ErrorIs(t, err, ErrStoreUnhealthy)
}

// TestWriteReturnsValue verifies that successful writes return their value only
// after commit succeeds.
func TestWriteReturnsValue(t *testing.T) {
	t.Parallel()

	dbConn := newTestDB(t, beginErrDriver{})
	hooks := &fakeStore{db: dbConn}

	result, err := Write(context.Background(), hooks, func(tx *sql.Tx) *sql.Tx {
		return tx
	}, func(*sql.Tx) (string, error) {
		return "ok", nil
	})
	require.NoError(t, err)
	require.Equal(t, "ok", result)
}

// TestWriteBeginFailure verifies that begin failures are classified and
// recorded.
func TestWriteBeginFailure(t *testing.T) {
	t.Parallel()

	dbConn := newTestDB(t, beginErrDriver{err: driver.ErrBadConn})
	hooks := &fakeStore{db: dbConn, classifyFn: func(err error) error {
		return dberr.NewSQLError(
			dberr.BackendPostgres, dberr.ReasonUnavailable, "", err,
		)
	}}

	result, err := Write(context.Background(), hooks, func(*sql.Tx) struct{} {
		return struct{}{}
	}, func(struct{}) (string, error) { return "", nil })

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

	dbConn := newTestDB(t, beginErrDriver{})
	hooks := &fakeStore{db: dbConn}
	callbackErr := errRuntimeCallback

	result, err := Write(context.Background(), hooks, func(tx *sql.Tx) *sql.Tx {
		return tx
	}, func(*sql.Tx) (string, error) {
		return "", callbackErr
	})
	require.Empty(t, result)
	require.ErrorIs(t, err, callbackErr)
	require.Zero(t, hooks.errorCount)
}

// TestWriteCallbackErrorClassified verifies that SQL-like callback failures are
// normalized through the backend classifier before they reach callers.
func TestWriteCallbackErrorClassified(t *testing.T) {
	t.Parallel()

	dbConn := newTestDB(t, beginErrDriver{})
	hooks := &fakeStore{db: dbConn, classifyFn: func(err error) error {
		return dberr.NewSQLError(
			dberr.BackendPostgres, dberr.ReasonConstraint, "23505", err,
		)
	}}

	result, err := Write(context.Background(), hooks, func(tx *sql.Tx) *sql.Tx {
		return tx
	}, func(*sql.Tx) (string, error) {
		return "", errRuntimeCallback
	})

	var sqlErr *dberr.SQLError

	require.Empty(t, result)
	require.ErrorAs(t, err, &sqlErr)
	require.Equal(t, dberr.ReasonConstraint, sqlErr.Reason)
	require.Equal(t, 1, hooks.errorCount)
}

// TestWriteCommitAmbiguous verifies that transport failures during commit are
// wrapped as ambiguous commit errors, recorded, and return a zero value.
func TestWriteCommitAmbiguous(t *testing.T) {
	t.Parallel()

	dbConn := newTestDB(t, beginErrDriver{commitErr: io.EOF})
	hooks := &fakeStore{db: dbConn, classifyFn: func(err error) error {
		return dberr.NewSQLError(
			dberr.BackendPostgres, dberr.ReasonUnavailable,
			"08006", err,
		)
	}}

	result, err := Write(context.Background(), hooks, func(tx *sql.Tx) *sql.Tx {
		return tx
	}, func(*sql.Tx) (string, error) {
		return "applied", nil
	})
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

	dbConn := newTestDB(t, beginErrDriver{commitErr: errRuntimeOther})
	hooks := &fakeStore{db: dbConn, classifyFn: func(err error) error {
		return dberr.NewSQLError(
			dberr.BackendPostgres, dberr.ReasonUnavailable,
			"08006", err,
		)
	}}

	result, err := Write(context.Background(), hooks, func(tx *sql.Tx) *sql.Tx {
		return tx
	}, func(*sql.Tx) (string, error) {
		return "applied", nil
	})
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

// beginErrDriver is a test SQL driver that injects begin and commit failures.
type beginErrDriver struct {
	err       error
	commitErr error
}

// Open returns a connection that injects the configured failures.
func (d beginErrDriver) Open(string) (driver.Conn, error) {
	return beginErrConn(d), nil
}

// beginErrConn is a test connection that injects begin and commit failures.
type beginErrConn struct {
	err       error
	commitErr error
}

// Prepare returns an unused statement error for the test driver.
func (c beginErrConn) Prepare(string) (driver.Stmt, error) {
	return nil, errRuntimeUnused
}

// Close reports success for the test connection close path.
func (c beginErrConn) Close() error {
	return nil
}

// Begin returns the legacy unused error because tests use BeginTx instead.
func (c beginErrConn) Begin() (driver.Tx, error) {
	return nil, errRuntimeUnused
}

// BeginTx returns the configured begin error or a transaction test double.
func (c beginErrConn) BeginTx(ctx context.Context,
	_ driver.TxOptions) (driver.Tx, error) {

	_ = ctx

	if c.err != nil {
		return nil, c.err
	}

	return beginErrTx{commitErr: c.commitErr}, nil
}

// beginErrTx is a test transaction that injects a commit failure.
type beginErrTx struct {
	commitErr error
}

// Commit returns the configured commit error.
func (tx beginErrTx) Commit() error {
	return tx.commitErr
}

// Rollback reports success for the test rollback path.
func (tx beginErrTx) Rollback() error {
	return nil
}

// testDriverSeq keeps each registered test driver name unique.
var testDriverSeq atomic.Uint64

// newTestDB registers one test driver instance and opens a matching database.
func newTestDB(t *testing.T, drv beginErrDriver) *sql.DB {
	t.Helper()

	name := fmt.Sprintf("runtime-test-%d", testDriverSeq.Add(1))
	sql.Register(name, drv)

	dbConn, err := sql.Open(name, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, dbConn.Close())
	})

	return dbConn
}
