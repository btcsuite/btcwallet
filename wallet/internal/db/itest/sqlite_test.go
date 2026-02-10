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

	// Enable WAL mode for better concurrency. WAL allows multiple readers and
	// reduces lock contention for concurrent writers.
	dsn = dsn + "&_pragma=journal_mode=WAL"

	// Enable immediate transaction locking to avoid races.
	dsn = dsn + "&_txlock=immediate"

	// Set busy timeout to 5 seconds. This makes SQLite retry acquiring locks
	// instead of immediately returning SQLITE_BUSY errors.
	dsn = dsn + "&_pragma=busy_timeout=5000"

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

// NewTestStoreWithDB creates a SQLite wallet store and also returns the raw
// sql.DB for fixture-level direct SQL setup.
func NewTestStoreWithDB(t *testing.T) (*db.SQLiteWalletDB, *sqlcsqlite.Queries,
	*sql.DB) {

	t.Helper()

	dbConn := NewSQLiteDB(t)

	store, err := db.NewSQLiteWalletDB(dbConn)
	require.NoError(t, err, "failed to create wallet store")

	queries := sqlcsqlite.New(dbConn)

	return store, queries, dbConn
}

// NewTestStore creates the SQLite wallet store and returns it with queries.
func NewTestStore(t *testing.T) (*db.SQLiteWalletDB, *sqlcsqlite.Queries) {
	t.Helper()

	store, queries, _ := NewTestStoreWithDB(t)

	return store, queries
}
