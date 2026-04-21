package pg

import (
	"context"
	"database/sql"
	"time"

	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

var (
	// Compile-time interface checks keep Store aligned with the shared runtime
	// hook contracts.
	_ dbruntime.ReadHooks  = (*Store)(nil)
	_ dbruntime.WriteHooks = (*Store)(nil)
)

// Default PostgreSQL read retry settings.
const (
	// defaultReadMaxAttempts keeps retries bounded to one initial attempt plus
	// up to two retries for short-lived serialization or lock failures.
	defaultReadMaxAttempts = 3

	// defaultReadBaseDelay starts backoff at 10 ms so brief transient conflicts
	// can clear without noticeably delaying callers.
	defaultReadBaseDelay = 10 * time.Millisecond

	// defaultReadMaxDelay caps retry backoff at 100 ms so repeated transient
	// errors do not stall wallet operations for too long.
	defaultReadMaxDelay = 100 * time.Millisecond
)

// execRead executes one PostgreSQL read operation through the shared runtime
// helper.
func (s *Store) execRead(ctx context.Context,
	fn func(*sqlc.Queries) error) error {

	_, err := dbruntime.Read(
		ctx, s, s.queries, defaultReadConfig(),
		func(_ context.Context, q *sqlc.Queries) (struct{}, error) {
			return struct{}{}, fn(q)
		},
	)

	return err
}

// execWrite executes one PostgreSQL write operation through the shared runtime
// helper.
func (s *Store) execWrite(ctx context.Context,
	fn func(*sqlc.Queries) error) error {

	_, err := dbruntime.Write(
		ctx, s,
		func(tx *sql.Tx) *sqlc.Queries {
			return s.queries.WithTx(tx)
		},
		func(qtx *sqlc.Queries) (struct{}, error) {
			return struct{}{}, fn(qtx)
		},
	)

	return err
}

// defaultReadConfig returns the PostgreSQL read retry policy.
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

// ClassifyError normalizes one PostgreSQL backend error into the shared SQL
// error model while preserving ordinary domain errors unchanged.
func (s *Store) ClassifyError(err error) error {
	return dberr.Normalize(dberr.BackendPostgres, mapErr, err)
}

// RecordError records one classified PostgreSQL backend error and marks the
// store unhealthy after fatal failures.
func (s *Store) RecordError(err error) {
	s.runtimeStats.RecordError(err)
}

// RecordRetryAttempt records one PostgreSQL read retry attempt.
func (s *Store) RecordRetryAttempt() {
	s.runtimeStats.RecordRetryAttempt()
}

// RecordRetrySuccess records one successful PostgreSQL read retry outcome.
func (s *Store) RecordRetrySuccess() {
	s.runtimeStats.RecordRetrySuccess()
}

// RecordRetryExhausted records one exhausted PostgreSQL read retry sequence.
func (s *Store) RecordRetryExhausted() {
	s.runtimeStats.RecordRetryExhausted()
}

// RecordAmbiguousTxCommit records one PostgreSQL commit failure with unknown
// outcome.
func (s *Store) RecordAmbiguousTxCommit() {
	s.runtimeStats.RecordAmbiguousTxCommit()
}

// RawDB returns the PostgreSQL database handle used by shared runtime writes.
func (s *Store) RawDB() *sql.DB {
	return s.db
}

// StatsSnapshot returns the current PostgreSQL runtime counters.
func (s *Store) StatsSnapshot() dbruntime.StatsSnapshot {
	return s.runtimeStats.Snapshot(dberr.BackendPostgres)
}
