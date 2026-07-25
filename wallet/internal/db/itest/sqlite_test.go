package itest

import (
	"context"
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

	conn, err := sqlite.Open(context.Background(), sqlite.Config{
		DBPath: filepath.Join(t.TempDir(), "wallet.db"),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, conn.Close())
	})
	require.NoError(t, sqlite.ApplyMigrations(conn))

	testManagerStore(t, &managerStoreHarness{
		conn: conn,
		newStore: func(walletID int64) db.Store {
			return dbsqlite.NewStore(conn, walletID)
		},
		newLifecycleStore: func(name string) db.LifecycleStore {
			return dbsqlite.NewNamedStore(conn, name)
		},
	})
}
