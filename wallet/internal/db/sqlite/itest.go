//go:build itest

package sqlite

import (
	"database/sql"

	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// DB returns the underlying *sql.DB connection for integration testing.
func (s *SqliteStore) DB() *sql.DB {
	return s.db
}

// Queries returns the underlying sqlc queries for integration testing.
func (s *SqliteStore) Queries() *sqlcsqlite.Queries {
	return s.queries
}
