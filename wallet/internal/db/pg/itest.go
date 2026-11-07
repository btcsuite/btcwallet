//go:build itest

package pg

import (
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Pool returns the native PostgreSQL pool for integration test adapters.
func (s *Store) Pool() *pgxpool.Pool {
	// Integration fixtures use NewStore's concrete pool. Reject a fixture
	// wired with another implementation rather than returning a nil adapter.
	pool, ok := s.pool.(*pgxpool.Pool)
	if !ok {
		panic("PostgreSQL integration store has no native pool")
	}

	return pool
}

// Queries returns the underlying sqlc queries for integration testing.
func (s *Store) Queries() *sqlc.Queries {
	return s.queries
}
