//go:build integration_test

package sqltest

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NewSQLiteDB creates an isolated fresh SQLite database in a temporary
// directory for each test. The database file is named deterministically.
func NewSQLiteDB(t testing.TB) *sql.DB {
	t.Helper()

	dir := t.TempDir()
	dbPath :=
		filepath.Join(dir, "btcwallettest_"+deterministicTestID(t)+".sqlite")

	// Use a file-backed database with read/write/create mode, shared cache
	// and foreign keys enabled.
	dsn := "file:" + dbPath + "?mode=rwc&cache=shared&_fk=1"

	// TODO: Use real SQLite constructor when available.
	db, err := sql.Open("sqlite", dsn)
	require.NoError(t, err, "failed to open SQLite database")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		require.NoError(t, err, "failed to ping SQLite database")
	}

	t.Cleanup(func() {
		err := db.Close()
		assert.NoError(t, err, "failed to close SQLite database")

		err = os.Remove(dbPath)
		assert.NoError(t, err, "failed to remove SQLite database")
	})

	return db
}
