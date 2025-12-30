//go:build itest && !test_db_postgres

package itest

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// NewSQLiteDB creates a new SQLite database for testing with migrations
// applied. Each test gets its own temporary database file.
func NewSQLiteDB(t *testing.T) *sql.DB {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Enable foreign keys (required for proper constraint enforcement).
	dsn := dbPath + "?_pragma=foreign_keys=on"

	// TODO(gustavostingelin): replace with the real SQLite database
	// connection constructor when available.
	dbConn, err := sql.Open("sqlite", dsn)
	require.NoError(t, err, "failed to open sqlite database")

	err = db.ApplySQLiteMigrations(dbConn)
	require.NoError(t, err, "failed to apply migrations")

	t.Cleanup(func() {
		_ = dbConn.Close()
	})

	return dbConn
}

// NewTestStore creates the SQLite wallet store and returns it along with the
// underlying database connection for tests that also need direct DB access.
func NewTestStore(t *testing.T) (*db.SQLiteWalletDB, *sqlcsqlite.Queries) {
	t.Helper()

	dbConn := NewSQLiteDB(t)

	store, err := db.NewSQLiteWalletDB(dbConn)
	require.NoError(t, err, "failed to create wallet store")

	queries := sqlcsqlite.New(dbConn)

	return store, queries
}
