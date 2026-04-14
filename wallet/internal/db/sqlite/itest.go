//go:build itest

package sqlite

import (
	"database/sql"

	sqlassetsqlite "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite"
	sqlc "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// DB returns the underlying *sql.DB connection for integration testing.
func (s *Store) DB() *sql.DB {
	return s.db
}

// Queries returns the underlying sqlc queries for integration testing.
func (s *Store) Queries() *sqlc.Queries {
	return s.queries
}

// RollbackAllMigrations rolls back all SQLite migrations.
func (s *Store) RollbackAllMigrations() error {
	return sqlassetsqlite.RollbackMigrations(s.db)
}

// ApplyAllMigrations reapplies all SQLite migrations.
func (s *Store) ApplyAllMigrations() error {
	return sqlassetsqlite.ApplyMigrations(s.db)
}
