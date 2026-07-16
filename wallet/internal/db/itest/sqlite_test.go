package itest

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dbsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite"
	"github.com/stretchr/testify/require"
)

// TestSQLiteManagerStore runs the manager transaction conformance suite
// against SQLite.
//
//nolint:tparallel // The ordered conformance cases share one database.
func TestSQLiteManagerStore(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "wallet.db")
	harness := &managerStoreHarness{
		reconnect: func(t *testing.T) *sql.DB {
			conn, err := sqlite.Open(
				context.Background(), sqlite.Config{DBPath: dbPath},
			)
			require.NoError(t, err)

			return conn
		},
	}
	harness.conn = harness.reconnect(t)
	require.NoError(t, sqlite.ApplyMigrations(harness.conn))
	harness.newStore = func(walletID int64) db.Store {
		return dbsqlite.NewStore(harness.conn, walletID)
	}
	t.Cleanup(func() {
		require.NoError(t, harness.conn.Close())
	})

	testManagerStore(t, harness)
}
