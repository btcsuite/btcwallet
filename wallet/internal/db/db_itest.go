//go:build itest

package db

import "database/sql"

// DB returns the underlying *sql.DB connection for integration testing.
func (s *SqliteStore) DB() *sql.DB {
	return s.db
}

// DB returns the underlying *sql.DB connection for integration testing.
func (s *PostgresStore) DB() *sql.DB {
	return s.db
}
