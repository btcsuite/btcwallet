//go:build itest

package pg

import (
	"database/sql"

	sqlassetpg "github.com/btcsuite/btcwallet/wallet/internal/sql/pg"
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

// RollbackAllMigrations rolls back all PostgreSQL migrations.
func (s *Store) RollbackAllMigrations() error {
	return sqlassetpg.RollbackMigrations(s.db)
}

// ApplyAllMigrations reapplies all PostgreSQL migrations.
func (s *Store) ApplyAllMigrations() error {
	return sqlassetpg.ApplyMigrations(s.db)
}
