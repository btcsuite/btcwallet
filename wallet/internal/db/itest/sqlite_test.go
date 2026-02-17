//go:build itest && !test_db_postgres

package itest

import (
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// NewTestStore creates a new SQLite database for testing with migrations
// applied. Each test gets its own temporary database file.
func NewTestStore(t *testing.T) *db.SqliteStore {
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
