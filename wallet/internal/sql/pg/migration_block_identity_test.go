//go:build test_db_postgres

package pg

import (
	"context"
	"database/sql"
	"testing"
	"time"

	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// populateHeightKeyedFixture seeds the height-keyed schema (version 11) with
// blocks at distinct heights, mined and unmined transactions, a credit, and a
// full sync state so the forward migration has data to preserve.
func populateHeightKeyedFixture(t *testing.T, db *sql.DB) {
	t.Helper()

	ctx := context.Background()
	exec := func(query string, args ...any) {
		_, err := db.ExecContext(ctx, query, args...)
		require.NoError(t, err)
	}

	for height := int64(100); height <= 102; height++ {
		exec(`INSERT INTO blocks (block_height, header_hash, block_timestamp)
			VALUES ($1, $2, $3)`, height, testHash(byte(height)), 1000+height)
	}

	exec(`INSERT INTO wallets (
		id, wallet_name, manager_version, manager_created_at, is_watch_only,
		master_pub_params, encrypted_crypto_pub_key
	) VALUES (1, 'w', 1, 1, TRUE, $1, $2)`, []byte{1}, []byte{2})

	exec(`INSERT INTO wallet_sync_states (
		wallet_id, start_block_height, synced_block_height, birthday_timestamp,
		birthday_block_height, birthday_block_verified
	) VALUES (1, 100, 101, 1234, 102, TRUE)`)

	exec(`INSERT INTO transactions (
		id, wallet_id, tx_hash, raw_tx, received_unix, block_height,
		confirmed_order, is_coinbase
	) VALUES (1, 1, $1, $2, 5, 100, 0, FALSE)`, testHash(10), []byte{0xaa})
	exec(`INSERT INTO transactions (
		id, wallet_id, tx_hash, raw_tx, received_unix, block_height,
		confirmed_order, is_coinbase
	) VALUES (2, 1, $1, $2, 5, 101, 0, FALSE)`, testHash(11), []byte{0xbb})
	exec(`INSERT INTO transactions (
		id, wallet_id, tx_hash, raw_tx, received_unix, is_coinbase
	) VALUES (3, 1, $1, $2, 5, FALSE)`, testHash(12), []byte{0xcc})

	exec(`INSERT INTO transaction_inputs (
		spending_tx_id, input_index, prev_tx_hash, prev_output_index
	) VALUES (3, 0, $1, 0)`, testHash(99))

	exec(`INSERT INTO credits (
		id, wallet_id, transaction_id, output_index, amount, pk_script, is_change
	) VALUES (50, 1, 1, 0, 7, $1, FALSE)`, []byte{0x51})
	exec(`INSERT INTO active_credit_incidences (
		wallet_id, tx_hash, output_index, credit_id
	) VALUES (1, $1, 0, 50)`, testHash(10))
}

// orphanBlockReferences counts transaction and sync-state block references that
// do not resolve to a block row. It is the PostgreSQL equivalent of the SQLite
// foreign_key_check.
func orphanBlockReferences(t *testing.T, db *sql.DB) int {
	t.Helper()

	var count int
	require.NoError(t, db.QueryRow(`
		SELECT
			(SELECT count(*) FROM transactions t
				WHERE t.block_id IS NOT NULL
				  AND NOT EXISTS (
				      SELECT 1 FROM blocks b WHERE b.id = t.block_id))
			+ (SELECT count(*) FROM wallet_sync_states s
				WHERE NOT EXISTS (
				          SELECT 1 FROM blocks b WHERE b.id = s.start_block_id)
				   OR NOT EXISTS (
				          SELECT 1 FROM blocks b WHERE b.id = s.synced_block_id)
				   OR (s.birthday_block_id IS NOT NULL AND NOT EXISTS (
				          SELECT 1 FROM blocks b WHERE b.id = s.birthday_block_id)))
	`).Scan(&count))

	return count
}

// migrateInstance opens a migration instance and registers its cleanup.
func migrateInstance(t *testing.T, db *sql.DB) *gomigrate.Migrate {
	t.Helper()

	m, err := newMigrationInstance(db)
	require.NoError(t, err)
	t.Cleanup(func() {
		sourceErr, dbErr := m.Close()
		require.NoError(t, sourceErr)
		require.NoError(t, dbErr)
	})

	return m
}

// TestBlockIdentityMigration exercises the block identity migration against a
// real PostgreSQL instance: the forward migration preserves ids and references
// and enables competing same-height blocks, the down migration refuses a fork,
// and a clean down restores the height primary key.
func TestBlockIdentityMigration(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
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

	reset := func() {
		_, err := db.ExecContext(
			ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public",
		)
		require.NoError(t, err)
	}

	t.Run("forward", func(t *testing.T) {
		reset()
		m := migrateInstance(t, db)
		require.NoError(t, m.Migrate(11))
		populateHeightKeyedFixture(t, db)
		require.NoError(t, m.Migrate(12))

		var height int64
		require.NoError(t, db.QueryRow(`
			SELECT b.block_height FROM transactions AS t
			INNER JOIN blocks AS b ON b.id = t.block_id WHERE t.id = 1
		`).Scan(&height))
		require.EqualValues(t, 100, height)

		var blockID sql.NullInt64
		require.NoError(t, db.QueryRow(
			"SELECT block_id FROM transactions WHERE id = 3",
		).Scan(&blockID))
		require.False(t, blockID.Valid)

		var transactionID int64
		require.NoError(t, db.QueryRow(
			"SELECT transaction_id FROM credits WHERE id = 50",
		).Scan(&transactionID))
		require.EqualValues(t, 1, transactionID)

		var start, synced, birthday int64
		require.NoError(t, db.QueryRow(`
			SELECT sb.block_height, yb.block_height, bb.block_height
			FROM wallet_sync_states AS s
			INNER JOIN blocks AS sb ON sb.id = s.start_block_id
			INNER JOIN blocks AS yb ON yb.id = s.synced_block_id
			INNER JOIN blocks AS bb ON bb.id = s.birthday_block_id
			WHERE s.wallet_id = 1
		`).Scan(&start, &synced, &birthday))
		require.EqualValues(t, 100, start)
		require.EqualValues(t, 101, synced)
		require.EqualValues(t, 102, birthday)

		// A competing block at an existing height now coexists.
		_, err = db.ExecContext(ctx, `
			INSERT INTO blocks (block_height, header_hash, block_timestamp)
			VALUES (101, $1, 9999)
		`, testHash(0x5a))
		require.NoError(t, err)

		var atHeight int
		require.NoError(t, db.QueryRow(
			"SELECT count(*) FROM blocks WHERE block_height = 101",
		).Scan(&atHeight))
		require.Equal(t, 2, atHeight)

		require.Zero(t, orphanBlockReferences(t, db))
	})

	t.Run("down guard", func(t *testing.T) {
		reset()
		m := migrateInstance(t, db)
		require.NoError(t, m.Migrate(11))
		populateHeightKeyedFixture(t, db)
		require.NoError(t, m.Migrate(12))

		_, err = db.ExecContext(ctx, `
			INSERT INTO blocks (block_height, header_hash, block_timestamp)
			VALUES (101, $1, 9999)
		`, testHash(0x5a))
		require.NoError(t, err)

		// The rollback refuses the fork and reports the typed sentinel rather
		// than discarding one side of it.
		err = RollbackMigrations(db)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrIrreversibleMigration)
		require.True(t, IsIrreversibleMigration(err))
	})

	t.Run("down clean", func(t *testing.T) {
		reset()
		m := migrateInstance(t, db)
		require.NoError(t, m.Migrate(11))
		populateHeightKeyedFixture(t, db)
		require.NoError(t, m.Migrate(12))
		require.NoError(t, m.Migrate(11))

		var height int64
		require.NoError(t, db.QueryRow(
			"SELECT block_height FROM transactions WHERE id = 1",
		).Scan(&height))
		require.EqualValues(t, 100, height)

		// Height is the primary key again, so a duplicate height is rejected.
		_, err = db.ExecContext(ctx, `
			INSERT INTO blocks (block_height, header_hash, block_timestamp)
			VALUES (101, $1, 1)
		`, testHash(0x5a))
		require.Error(t, err)
	})
}
