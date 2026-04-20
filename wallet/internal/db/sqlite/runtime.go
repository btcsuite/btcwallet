package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	sqlc "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

var (
	// Compile-time interface checks keep Store aligned with the shared runtime
	// hook contracts.
	_ dbruntime.ReadHooks  = (*Store)(nil)
	_ dbruntime.WriteHooks = (*Store)(nil)
)

// Default SQLite read retry settings.
const (
	// defaultReadMaxAttempts keeps retries bounded to one initial attempt plus
	// up to two retries for short-lived lock contention.
	defaultReadMaxAttempts = 3

	// defaultReadBaseDelay starts backoff at 10 ms so brief lock contention can
	// clear without noticeably delaying callers.
	defaultReadBaseDelay = 10 * time.Millisecond

	// defaultReadMaxDelay caps retry backoff at 100 ms so repeated transient
	// errors do not stall wallet operations for too long.
	defaultReadMaxDelay = 100 * time.Millisecond
)

// execRead executes one SQLite read operation through the shared runtime
// helper.
func (s *Store) execRead(ctx context.Context,
	fn func(*sqlc.Queries) error) error {

	_, err := dbruntime.Read(
		ctx,
		s,
		s.queries,
		defaultReadConfig(),
		func(_ context.Context, q *sqlc.Queries) (struct{}, error) {
			return struct{}{}, fn(q)
		},
	)

	return err
}

// execWrite executes one SQLite write operation through the shared runtime
// helper.
func (s *Store) execWrite(ctx context.Context,
	fn func(*sqlc.Queries) error) error {

	_, err := dbruntime.Write(
		ctx,
		s,
		func(tx *sql.Tx) *sqlc.Queries {
			return s.queries.WithTx(tx)
		},
		func(qtx *sqlc.Queries) (struct{}, error) {
			return struct{}{}, fn(qtx)
		},
	)

	return err
}

// defaultReadConfig returns the SQLite read retry policy.
func defaultReadConfig() dbruntime.ReadConfig {
	// TODO(yy): make it configurable.
	return dbruntime.ReadConfig{
		MaxAttempts: defaultReadMaxAttempts,
		BaseDelay:   defaultReadBaseDelay,
		MaxDelay:    defaultReadMaxDelay,
	}
}

// CheckHealthy reports whether a prior fatal SQL backend error poisoned the
// store.
func (s *Store) CheckHealthy() error {
	return s.runtimeStats.CheckHealthy()
}

// ClassifyError normalizes one SQLite backend error into the shared SQL error
// model while preserving ordinary domain errors unchanged.
func (s *Store) ClassifyError(err error) error {
	normalized := dberr.Normalize(dberr.BackendSQLite, mapErr, err)
	if normalized == nil {
		return nil
	}

	var sqlErr *dberr.SQLError
	if !errors.As(normalized, &sqlErr) {
		return err
	}

	if sqlErr.Reason != dberr.ReasonUnknown {
		return normalized
	}

	var origSQLErr *dberr.SQLError
	if errors.As(err, &origSQLErr) {
		return normalized
	}

	return err
}

// RecordError records one classified SQLite backend error and marks the store
// unhealthy after fatal failures.
func (s *Store) RecordError(err error) {
	s.runtimeStats.RecordError(err)
}

// RecordRetryAttempt records one SQLite read retry attempt.
func (s *Store) RecordRetryAttempt() {
	s.runtimeStats.RecordRetryAttempt()
}

// RecordRetrySuccess records one successful SQLite read retry outcome.
func (s *Store) RecordRetrySuccess() {
	s.runtimeStats.RecordRetrySuccess()
}

// RecordRetryExhausted records one exhausted SQLite read retry sequence.
func (s *Store) RecordRetryExhausted() {
	s.runtimeStats.RecordRetryExhausted()
}

// RecordAmbiguousTxCommit records one SQLite commit failure with unknown
// outcome.
func (s *Store) RecordAmbiguousTxCommit() {
	s.runtimeStats.RecordAmbiguousTxCommit()
}

// RawDB returns the SQLite database handle used by shared runtime writes.
func (s *Store) RawDB() *sql.DB {
	return s.db
}

// StatsSnapshot returns the current SQLite runtime counters.
func (s *Store) StatsSnapshot() dbruntime.StatsSnapshot {
	return s.runtimeStats.Snapshot(dberr.BackendSQLite)
}
