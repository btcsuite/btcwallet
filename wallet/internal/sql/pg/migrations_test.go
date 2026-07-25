//go:build test_db_postgres

package pg

import (
	"bytes"
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

	requireLeaseUpgrade(t, db)
	require.Zero(t, db.Stats().InUse)
	require.NoError(t, db.PingContext(ctx))
	requireSchemaTables(t, db, true)
	testTransactionSchema(t, db)

	require.NoError(t, RollbackMigrations(db))
	require.Zero(t, db.Stats().InUse)
	require.NoError(t, db.PingContext(ctx))
	requireSchemaTables(t, db, false)

	require.NoError(t, ApplyMigrations(db))
	requireSchemaTables(t, db, true)
}

// requireLeaseUpgrade verifies that the forward precision migration converts
// leases written by migration 000009 before nanosecond comparisons begin.
func requireLeaseUpgrade(t *testing.T, db *sql.DB) {
	t.Helper()

	migration, err := newMigrationInstance(db)
	require.NoError(t, err)
	require.NoError(t, migration.Migrate(11))

	_, err = db.ExecContext(t.Context(), `
		INSERT INTO wallets (
			id, wallet_name, manager_version, manager_created_at,
			is_watch_only, master_pub_params, encrypted_crypto_pub_key
		) VALUES (99, 'lease-upgrade', 1, 1, TRUE, $1, $2)
	`, []byte{1}, []byte{2})
	require.NoError(t, err)

	const expiresSeconds = int64(1_700_000_000)
	_, err = db.ExecContext(t.Context(), `
		INSERT INTO utxo_leases (
			wallet_id, tx_hash, output_index, lock_id, expires_unix
		) VALUES ($1, $2, 0, $3, $4)
	`, 99, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32),
		expiresSeconds)
	require.NoError(t, err)

	require.NoError(t, ApplyMigrations(db))

	var expiresNanoseconds int64
	err = db.QueryRowContext(t.Context(), `
		SELECT expires_unix FROM utxo_leases WHERE wallet_id = 99
	`).Scan(&expiresNanoseconds)
	require.NoError(t, err)
	require.Equal(t, expiresSeconds*int64(1_000_000_000),
		expiresNanoseconds)
}

// requireSchemaTables verifies whether every wallet schema table exists.
func requireSchemaTables(t *testing.T, db *sql.DB, expected bool) {
	t.Helper()

	tables := []string{
		"blocks", "wallet_blocks", "wallets", "wallet_sync_states",
		"address_types",
		"key_scopes", "accounts", "addresses",
		"transactions", "transaction_inputs", "transaction_labels",
		"credits", "active_credit_incidences", "credit_spends",
		"utxo_leases",
	}
	for _, table := range tables {
		var exists bool
		err := db.QueryRow(
			"SELECT EXISTS (SELECT 1 FROM information_schema.tables "+
				"WHERE table_schema = 'public' AND table_name = $1)",
			table,
		).Scan(&exists)
		require.NoError(t, err)
		require.Equal(t, expected, exists, table)
	}
}
