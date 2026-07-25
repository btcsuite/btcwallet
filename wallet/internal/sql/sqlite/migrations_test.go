package sqlite

import (
	"bytes"
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

	requireLeaseUpgrade(t, db)
	requireSchemaTables(t, db, true)
	testTransactionSchema(t, db)

	require.NoError(t, RollbackMigrations(db))
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
		) VALUES (99, 'lease-upgrade', 1, 1, TRUE, x'01', x'02')
	`)
	require.NoError(t, err)

	const expiresSeconds = int64(1_700_000_000)

	_, err = db.ExecContext(t.Context(), `
		INSERT INTO utxo_leases (
			wallet_id, tx_hash, output_index, lock_id, expires_unix
		) VALUES (?, ?, 0, ?, ?)
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
