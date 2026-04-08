//go:build itest

package pg

import (
	"database/sql"

	sqlc "github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// DB returns the underlying *sql.DB connection for integration testing.
func (s *Store) DB() *sql.DB {
	return s.db
}

// Queries returns the underlying sqlc queries for integration testing.
func (s *Store) Queries() *sqlc.Queries {
	return s.queries
}
