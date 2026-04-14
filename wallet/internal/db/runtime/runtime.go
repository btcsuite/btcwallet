// Package runtime provides shared SQL execution helpers for split backend
// packages.
package runtime

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"time"

	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
)

// Runtime sentinel errors returned by the shared SQL helpers.
var (
	// ErrStoreUnhealthy is returned when a runtime helper operates on an
	// already unhealthy store.
	ErrStoreUnhealthy = errors.New("sql store unhealthy")

	// ErrAmbiguousTxCommit matches commit failures whose final database outcome
	// is unknown because the commit may already have reached the backend before
	// the client observed the failure.
	//
	// Callers should treat this differently from an ordinary commit failure and
	// should not blindly retry the transaction. Write returns this through
	// AmbiguousTxCommitError so callers can use errors.Is(err,
	// ErrAmbiguousTxCommit) for policy checks while still inspecting the
	// underlying classified backend error.
	ErrAmbiguousTxCommit = errors.New("sql ambiguous tx commit")
)

// Read config validation errors returned by Read.
var (
	errReadMaxAttempts = errors.New("read max attempts must be positive")
	errReadBaseDelay   = errors.New("read base delay must be positive")
	errReadMaxDelay    = errors.New("read max delay must be positive")
	errReadDelayOrder  = errors.New("read base delay exceeds max delay")
)

// AmbiguousTxCommitError wraps a classified commit error returned by Write when
// Commit fails after the final database outcome may already be decided by the
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

// ReadHooks defines the runtime hooks needed by the shared read helper.
type ReadHooks interface {
	// CheckHealthy fails fast when the backend has already been marked
	// unhealthy.
	CheckHealthy() error

	// ClassifyError maps backend failures into the shared SQL error model.
	ClassifyError(err error) error

	// RecordError records a classified SQL error.
	RecordError(err error)

	// RecordRetryAttempt records one retry backoff attempt.
	RecordRetryAttempt()

	// RecordRetrySuccess records a successful retry outcome.
	RecordRetrySuccess()

	// RecordRetryExhausted records that retry budget was exhausted.
	RecordRetryExhausted()
}

// WriteHooks defines the runtime hooks needed by the shared transaction helper.
type WriteHooks interface {
	// CheckHealthy fails fast when the backend has already been marked
	// unhealthy.
	CheckHealthy() error

	// ClassifyError maps backend failures into the shared SQL error model.
	ClassifyError(err error) error

	// RecordError records a classified SQL error.
	RecordError(err error)

	// RecordAmbiguousTxCommit records a commit failure with unknown outcome.
	RecordAmbiguousTxCommit()

	// RawDB returns the backend database handle used for transactions.
	RawDB() *sql.DB
}

// ReadConfig holds caller-provided retry settings for Read.
//
// Callers should derive this from backend or wallet configuration so retry
// policy stays outside the shared runtime helper package.
type ReadConfig struct {
	// MaxAttempts is the maximum number of callback attempts, including the
	// first attempt. Set this to 1 to disable retries.
	MaxAttempts int

	// BaseDelay is the starting backoff delay before jitter is applied.
	// Ignored when MaxAttempts is 1.
	BaseDelay time.Duration

	// MaxDelay is the upper bound for the exponential backoff delay.
	// Ignored when MaxAttempts is 1.
	MaxDelay time.Duration
}

// readConfig holds the retry settings used by readWithConfig.
type readConfig struct {
	// attempts is the maximum number of callback attempts.
	attempts int

	// base is the starting backoff delay before jitter is applied.
	base time.Duration

	// max is the upper bound for the exponential backoff delay.
	max time.Duration

	// jitter rewrites one calculated delay before waiting.
	jitter func(time.Duration) time.Duration

	// timer waits for one retry delay.
	timer func(time.Duration) *time.Timer
}

// Read executes a read-only SQL callback with transient retry handling.
//
// Read returns the callback result from the first successful attempt. On any
// failure, it returns the zero value of T together with the final error.
func Read[Q any, T any](ctx context.Context, hooks ReadHooks, queries Q,
	config ReadConfig,
	fn func(context.Context, Q) (T, error)) (T, error) {

	execConfig, err := buildReadConfig(config)
	if err != nil {
		var zero T

		return zero, fmt.Errorf("build read config: %w", err)
	}

	return readWithConfig(ctx, hooks, queries, fn, execConfig)
}

// buildReadConfig converts the caller-facing config into runtime settings.
func buildReadConfig(config ReadConfig) (readConfig, error) {
	switch {
	case config.MaxAttempts <= 0:
		return readConfig{}, errReadMaxAttempts

	case config.MaxAttempts > 1 && config.BaseDelay <= 0:
		return readConfig{}, errReadBaseDelay

	case config.MaxAttempts > 1 && config.MaxDelay <= 0:
		return readConfig{}, errReadMaxDelay

	case config.MaxAttempts > 1 && config.BaseDelay > config.MaxDelay:
		return readConfig{}, errReadDelayOrder
	}

	return readConfig{
		attempts: config.MaxAttempts,
		base:     config.BaseDelay,
		max:      config.MaxDelay,
		jitter: func(delay time.Duration) time.Duration {
			return delay
		},
		timer: time.NewTimer,
	}, nil
}

// readWithConfig executes Read with injected retry settings.
func readWithConfig[Q any, T any](ctx context.Context, hooks ReadHooks,
	queries Q, fn func(context.Context, Q) (T, error),
	config readConfig) (T, error) {

	var zero T

	// Fail fast if a prior fatal backend error already poisoned the store.
	err := hooks.CheckHealthy()
	if err != nil {
		return zero, fmt.Errorf("check store health: %w", err)
	}

	for attempt := range config.attempts {
		result, shouldRetry, err := readAttempt(ctx, hooks, queries, fn)
		if !shouldRetry && err == nil {
			if attempt > 0 {
				hooks.RecordRetrySuccess()
			}

			return result, nil
		}

		if !shouldRetry {
			return zero, err
		}

		if attempt == config.attempts-1 {
			hooks.RecordRetryExhausted()
			return zero, fmt.Errorf("read: %w", err)
		}

		hooks.RecordRetryAttempt()

		// Use exponential backoff with injectable jitter and timer hooks so the
		// helper stays deterministic under test.
		delay := retryDelay(attempt, config.base, config.max)
		delay = config.jitter(delay)

		err = waitForRetry(ctx, config.timer, delay)
		if err != nil {
			return zero, err
		}
	}

	return zero, ErrStoreUnhealthy
}

// readAttempt executes one read callback attempt.
//
// It returns the callback result on success. On failure, it returns the zero
// value of T together with either an immediate return error or a classified
// transient error for the outer retry loop.
func readAttempt[Q any, T any](ctx context.Context, hooks ReadHooks, queries Q,
	fn func(context.Context, Q) (T, error)) (T, bool, error) {

	var zero T

	// Run the read callback first so successful reads never pay any
	// classification or retry overhead.
	result, err := fn(ctx, queries)
	if err == nil {
		return result, false, nil
	}

	// Preserve caller-driven cancellation and no-row results unchanged.
	ctxErr := unwrapContextError(err)
	if ctxErr != nil {
		return zero, false, ctxErr
	}

	if errors.Is(err, sql.ErrNoRows) {
		return zero, false, err
	}

	// Classify the backend failure once before deciding whether the read is
	// safe to retry.
	classifiedErr := hooks.ClassifyError(err)
	hooks.RecordError(classifiedErr)

	// Retry only transient classified failures. Everything else returns to the
	// caller immediately with context.
	var sqlErr *dberr.SQLError
	if !errors.As(classifiedErr, &sqlErr) ||
		sqlErr.Class() != dberr.ClassTransient {

		return zero, false, fmt.Errorf("read: %w", classifiedErr)
	}

	//nolint:wrapcheck
	// We need to return the exact classified error to be wrapped by Read.
	return zero, true, classifiedErr
}

// Write executes a transactional SQL callback without retrying it.
//
// Write returns the callback result only after Commit succeeds. If Begin,
// callback execution, or Commit fails, it returns the zero value of T together
// with the resulting error.
//
// hooks supplies the shared health check, error classification, SQL error
// recording, ambiguous-commit accounting, and raw database handle used by the
// helper.
//
// bind converts the started *sql.Tx into the caller's transactional query
// handle, such as a sqlc Queries value bound to that transaction.
//
// fn performs the transactional work with that bound handle. SQL and backend
// callback failures are normalized through hooks.ClassifyError, while ordinary
// domain errors pass through unchanged.
//
// If Commit fails after the backend may already have applied the transaction,
// Write returns an AmbiguousTxCommitError. Callers should detect that case
// with errors.Is(err, ErrAmbiguousTxCommit) before deciding whether retrying
// or compensating work is safe.
func Write[Q any, T any](ctx context.Context, hooks WriteHooks,
	bind func(*sql.Tx) Q, fn func(Q) (T, error)) (T, error) {

	var zero T

	// Fail fast if a prior fatal backend error already poisoned the store.
	err := hooks.CheckHealthy()
	if err != nil {
		return zero, fmt.Errorf("check store health: %w", err)
	}

	// Begin the transaction before invoking the callback so begin failures are
	// still classified and recorded consistently.
	tx, err := hooks.RawDB().BeginTx(ctx, nil)
	if err != nil {
		classifiedErr := hooks.ClassifyError(err)
		hooks.RecordError(classifiedErr)

		return zero, fmt.Errorf("begin tx: %w", classifiedErr)
	}

	defer func() {
		_ = tx.Rollback()
	}()

	// Callback errors are normalized through the backend classifier so SQL
	// driver failures reach callers consistently while non-SQL domain errors
	// pass through unchanged.
	result, err := fn(bind(tx))
	if err != nil {
		classifiedErr := hooks.ClassifyError(err)
		recordWriteCallbackError(hooks, classifiedErr)

		return zero, normalizeWriteCallbackError(err, classifiedErr)
	}

	// Commit transport failures are wrapped so callers know the final
	// transaction outcome is unknown.
	err = tx.Commit()
	if err != nil {
		classifiedErr := hooks.ClassifyError(err)
		hooks.RecordError(classifiedErr)

		if isCommitTransportError(err) {
			hooks.RecordAmbiguousTxCommit()

			return zero, &AmbiguousTxCommitError{
				Err: fmt.Errorf("commit tx: %w", classifiedErr),
			}
		}

		return zero, fmt.Errorf("commit tx: %w", classifiedErr)
	}

	return result, nil
}

// normalizeWriteCallbackError preserves unchanged callback errors while
// returning normalized SQL backend failures when classification added one.
func normalizeWriteCallbackError(err, classifiedErr error) error {
	var sqlErr *dberr.SQLError
	if !errors.As(classifiedErr, &sqlErr) {
		return err
	}

	return classifiedErr
}

// recordWriteCallbackError records one classified SQL callback error while
// leaving non-SQL callback failures out of SQL error accounting.
func recordWriteCallbackError(hooks WriteHooks, classifiedErr error) {
	var sqlErr *dberr.SQLError
	if !errors.As(classifiedErr, &sqlErr) {
		return
	}

	hooks.RecordError(classifiedErr)
}

// retryDelay applies bounded exponential backoff for retry attempts.
func retryDelay(attempt int, baseDelay, maxDelay time.Duration) time.Duration {
	// The first retry waits for the configured base delay. Each later retry
	// doubles the previous delay until the backoff reaches the configured cap.
	delay := baseDelay

	for range attempt {
		// Saturate before doubling once the next step would reach or exceed the
		// cap. The maxDelay/2 check avoids computing delay*2 when the bounded
		// result must already be maxDelay.
		if delay >= maxDelay || delay > maxDelay/2 {
			return maxDelay
		}

		delay *= 2
	}

	// Keep the helper defensive when called directly with unchecked values.
	if delay > maxDelay {
		return maxDelay
	}

	return delay
}

// waitForRetry waits for the next retry delay or returns ctx.Err when the
// caller cancels first.
func waitForRetry(ctx context.Context,
	timer func(time.Duration) *time.Timer, delay time.Duration) error {

	retryTimer := timer(delay)
	defer stopRetryTimer(retryTimer)

	select {
	case <-retryTimer.C:
		return nil

	case <-ctx.Done():
		return ctx.Err()
	}
}

// stopRetryTimer stops a retry timer and drains a fired value when needed.
func stopRetryTimer(timer *time.Timer) {
	if timer == nil {
		return
	}

	if timer.Stop() {
		return
	}

	select {
	case <-timer.C:
	default:
	}
}

// unwrapContextError preserves caller-driven cancellation and deadlines.
func unwrapContextError(err error) error {
	if errors.Is(err, context.Canceled) {
		return err
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	return nil
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
