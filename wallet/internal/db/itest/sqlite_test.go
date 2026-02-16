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
func NewSQLiteDB(t *testing.T) *db.SqliteStore {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := db.SqliteConfig{
		DBPath:         dbPath,
		MaxConnections: 0,
	}

	store, err := db.NewSqliteStore(t.Context(), cfg)
	require.NoError(t, err, "failed to create sqlite store")

	t.Cleanup(func() {
		_ = store.Close()
	})

	return store
}

// NewTestStoreWithDB creates a SQLite wallet store and also returns the raw
// sql.DB for fixture-level direct SQL setup.
func NewTestStoreWithDB(t *testing.T) (*db.SqliteStore, *sqlcsqlite.Queries,
	*sql.DB) {

	t.Helper()

	store := NewSQLiteDB(t)
	dbConn := store.DB()
	queries := sqlcsqlite.New(dbConn)

	return store, queries, dbConn
}

// NewTestStore creates the SQLite wallet store and returns it with queries.
func NewTestStore(t *testing.T) (*db.SqliteStore, *sqlcsqlite.Queries) {
	t.Helper()

	store, queries, _ := NewTestStoreWithDB(t)

	return store, queries
}
