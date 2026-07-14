//go:build test_db_postgres

package itest

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dbpg "github.com/btcsuite/btcwallet/wallet/internal/db/pg"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestPostgresManagerStore runs the manager transaction conformance suite
// against PostgreSQL.
//
//nolint:tparallel // The ordered conformance cases share one database.
func TestPostgresManagerStore(t *testing.T) {
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
	conn, err := pg.Open(ctx, pg.Config{DSN: dsn})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, conn.Close())
	})
	require.NoError(t, pg.ApplyMigrations(conn))

	testManagerStore(t, &managerStoreHarness{
		conn:     conn,
		postgres: true,
		newStore: func(walletID int64) db.Store {
			return dbpg.NewStore(conn, walletID)
		},
	})
}
