//go:build itest

package db

import (
	"database/sql"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"

	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// DB returns the underlying *sql.DB connection for integration testing.
func (s *PostgresStore) DB() *sql.DB {
	return s.db
}

// Queries returns the underlying sqlc queries for integration testing.
func (s *PostgresStore) Queries() *sqlcpg.Queries {
	return s.queries
}
