//go:build test_db_postgres

package pg

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestMigrationsRoundTrip verifies that the schema can be applied, removed,
// and applied again on the same database.
func TestMigrationsRoundTrip(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	container, err := postgres.Run(
		ctx, "postgres:18-alpine",
		postgres.WithDatabase("btcwallet"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(2*time.Minute),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, container.Terminate(context.Background()))
	})

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := Open(ctx, Config{DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})

	require.NoError(t, ApplyMigrations(db))
	require.Zero(t, db.Stats().InUse)
	require.NoError(t, db.PingContext(ctx))
	requireBlocksTable(t, db, true)

	require.NoError(t, RollbackMigrations(db))
	require.Zero(t, db.Stats().InUse)
	require.NoError(t, db.PingContext(ctx))
	requireBlocksTable(t, db, false)

	require.NoError(t, ApplyMigrations(db))
	requireBlocksTable(t, db, true)
}

func requireBlocksTable(t *testing.T, db *sql.DB, expected bool) {
	t.Helper()

	var exists bool
	err := db.QueryRow(
		"SELECT EXISTS (SELECT 1 FROM information_schema.tables " +
			"WHERE table_schema = 'public' AND table_name = 'blocks')",
	).Scan(&exists)
	require.NoError(t, err)
	require.Equal(t, expected, exists)
}
