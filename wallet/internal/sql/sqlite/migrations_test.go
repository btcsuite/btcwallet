package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMigrationsRoundTrip verifies that the schema can be applied, removed,
// and applied again on the same database.
func TestMigrationsRoundTrip(t *testing.T) {
	t.Parallel()

	db, err := Open(context.Background(), Config{
		DBPath: filepath.Join(t.TempDir(), "wallet.db"),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})

	require.NoError(t, ApplyMigrations(db))
	requireSchemaTables(t, db, true)

	require.NoError(t, RollbackMigrations(db))
	requireSchemaTables(t, db, false)

	require.NoError(t, ApplyMigrations(db))
	requireSchemaTables(t, db, true)
}

func requireSchemaTables(t *testing.T, db *sql.DB, expected bool) {
	t.Helper()

	tables := []string{
		"blocks", "wallets", "wallet_sync_states", "address_types",
		"key_scopes", "accounts", "addresses",
	}
	for _, table := range tables {
		var count int

		err := db.QueryRowContext(
			context.Background(),
			"SELECT count(*) FROM sqlite_master "+
				"WHERE type = 'table' AND name = ?", table,
		).Scan(&count)
		require.NoError(t, err)
		require.Equal(t, expected, count == 1, table)
	}
}
