package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// blockIdentityBaseVersion is the schema version immediately before the block
// identity migration.
const blockIdentityBaseVersion = 11

// blockIdentityVersion is the schema version that introduces the surrogate
// block identity.
const blockIdentityVersion = 12

// openBlockIdentityDB opens a fresh SQLite database for a block identity
// migration test.
func openBlockIdentityDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := Open(context.Background(), Config{
		DBPath: filepath.Join(t.TempDir(), "wallet.db"),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})

	return db
}

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
			VALUES (?, ?, ?)`, height, testHash(byte(height)), 1000+height)
	}

	exec(`INSERT INTO wallets (
		id, wallet_name, manager_version, manager_created_at, is_watch_only,
		master_pub_params, encrypted_crypto_pub_key
	) VALUES (1, 'w', 1, 1, TRUE, x'01', x'02')`)

	exec(`INSERT INTO wallet_sync_states (
		wallet_id, start_block_height, synced_block_height, birthday_timestamp,
		birthday_block_height, birthday_block_verified
	) VALUES (1, 100, 101, 1234, 102, TRUE)`)

	// Mined transactions at heights 100 and 101 keep ids 1 and 2; the unmined
	// transaction keeps id 3.
	exec(`INSERT INTO transactions (
		id, wallet_id, tx_hash, raw_tx, received_unix, block_height,
		confirmed_order, is_coinbase
	) VALUES (1, 1, ?, x'aa', 5, 100, 0, FALSE)`, testHash(10))
	exec(`INSERT INTO transactions (
		id, wallet_id, tx_hash, raw_tx, received_unix, block_height,
		confirmed_order, is_coinbase
	) VALUES (2, 1, ?, x'bb', 5, 101, 0, FALSE)`, testHash(11))
	exec(`INSERT INTO transactions (
		id, wallet_id, tx_hash, raw_tx, received_unix, is_coinbase
	) VALUES (3, 1, ?, x'cc', 5, FALSE)`, testHash(12))

	exec(`INSERT INTO transaction_inputs (
		spending_tx_id, input_index, prev_tx_hash, prev_output_index
	) VALUES (3, 0, ?, 0)`, testHash(99))

	exec(`INSERT INTO credits (
		id, wallet_id, transaction_id, output_index, amount, pk_script, is_change
	) VALUES (50, 1, 1, 0, 7, x'51', FALSE)`)
	exec(`INSERT INTO active_credit_incidences (
		wallet_id, tx_hash, output_index, credit_id
	) VALUES (1, ?, 0, 50)`, testHash(10))
}

// foreignKeyViolations returns the number of foreign key violations reported by
// PRAGMA foreign_key_check.
func foreignKeyViolations(t *testing.T, db *sql.DB) int {
	t.Helper()

	rows, err := db.QueryContext(
		context.Background(), "PRAGMA foreign_key_check",
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, rows.Close())
	}()

	count := 0
	for rows.Next() {
		count++
	}
	require.NoError(t, rows.Err())

	return count
}

// TestBlockIdentityMigrationForward verifies that the forward migration
// preserves every transaction id and block reference, keeps block metadata, and
// enables competing same-height blocks without leaving a foreign key violation.
func TestBlockIdentityMigrationForward(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openBlockIdentityDB(t)

	m, err := newMigrationInstance(db)
	require.NoError(t, err)
	require.NoError(t, m.Migrate(blockIdentityBaseVersion))

	populateHeightKeyedFixture(t, db)
	require.NoError(t, m.Migrate(blockIdentityVersion))

	count := func(table string) int {
		var n int
		require.NoError(t, db.QueryRowContext(
			ctx, "SELECT count(*) FROM "+table,
		).Scan(&n))

		return n
	}

	// Row counts are preserved across the rebuild.
	require.Equal(t, 3, count("blocks"))
	require.Equal(t, 3, count("transactions"))
	require.Equal(t, 1, count("transaction_inputs"))
	require.Equal(t, 1, count("credits"))
	require.Equal(t, 1, count("active_credit_incidences"))
	require.Equal(t, 1, count("wallet_sync_states"))

	// The mined transaction keeps its id and now references a block id whose
	// height matches the pre-migration height.
	var height int64
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT b.block_height FROM transactions AS t
		INNER JOIN blocks AS b ON b.id = t.block_id
		WHERE t.id = 1
	`).Scan(&height))
	require.EqualValues(t, 100, height)

	// The unmined transaction keeps a null block reference.
	var blockID sql.NullInt64
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT block_id FROM transactions WHERE id = 3",
	).Scan(&blockID))
	require.False(t, blockID.Valid)

	// The credit still references the preserved transaction id.
	var transactionID int64
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT transaction_id FROM credits WHERE id = 50",
	).Scan(&transactionID))
	require.EqualValues(t, 1, transactionID)

	// Start, synced, and birthday state resolve to their original heights.
	var start, synced, birthday int64
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT sb.block_height, yb.block_height, db2.block_height
		FROM wallet_sync_states AS s
		INNER JOIN blocks AS sb ON sb.id = s.start_block_id
		INNER JOIN blocks AS yb ON yb.id = s.synced_block_id
		INNER JOIN blocks AS db2 ON db2.id = s.birthday_block_id
		WHERE s.wallet_id = 1
	`).Scan(&start, &synced, &birthday))
	require.EqualValues(t, 100, start)
	require.EqualValues(t, 101, synced)
	require.EqualValues(t, 102, birthday)

	// Block hash and timestamp are preserved.
	var timestamp int64
	var hash []byte
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT block_timestamp, header_hash FROM blocks WHERE block_height = 100
	`).Scan(&timestamp, &hash))
	require.EqualValues(t, 1100, timestamp)
	require.Equal(t, testHash(100), hash)

	// A competing block at an existing height now coexists as a distinct row.
	_, err = db.ExecContext(ctx, `
		INSERT INTO blocks (block_height, header_hash, block_timestamp)
		VALUES (101, ?, 9999)
	`, testHash(0x5a))
	require.NoError(t, err)

	var atHeight int
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT count(*) FROM blocks WHERE block_height = 101",
	).Scan(&atHeight))
	require.Equal(t, 2, atHeight)

	require.Zero(t, foreignKeyViolations(t, db))
}

// TestBlockIdentityMigrationDownGuard verifies that the down migration refuses
// to run while competing same-height blocks exist rather than discarding a fork.
func TestBlockIdentityMigrationDownGuard(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openBlockIdentityDB(t)

	m, err := newMigrationInstance(db)
	require.NoError(t, err)
	require.NoError(t, m.Migrate(blockIdentityBaseVersion))
	populateHeightKeyedFixture(t, db)
	require.NoError(t, m.Migrate(blockIdentityVersion))

	// Introduce a fork of two blocks at one height.
	_, err = db.ExecContext(ctx, `
		INSERT INTO blocks (block_height, header_hash, block_timestamp)
		VALUES (101, ?, 9999)
	`, testHash(0x5a))
	require.NoError(t, err)

	// The rollback refuses the fork and reports the typed sentinel rather than
	// discarding one side of it.
	err = RollbackMigrations(db)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrIrreversibleMigration)
	require.True(t, IsIrreversibleMigration(err))
}

// TestBlockIdentityMigrationDownClean verifies that the down migration restores
// the height primary key when no fork exists.
func TestBlockIdentityMigrationDownClean(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openBlockIdentityDB(t)

	m, err := newMigrationInstance(db)
	require.NoError(t, err)
	require.NoError(t, m.Migrate(blockIdentityBaseVersion))
	populateHeightKeyedFixture(t, db)
	require.NoError(t, m.Migrate(blockIdentityVersion))
	require.NoError(t, m.Migrate(blockIdentityBaseVersion))

	// The mined transaction is height-keyed again.
	var height int64
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT block_height FROM transactions WHERE id = 1",
	).Scan(&height))
	require.EqualValues(t, 100, height)

	// Height is the primary key again, so a duplicate height is rejected.
	_, err = db.ExecContext(ctx, `
		INSERT INTO blocks (block_height, header_hash, block_timestamp)
		VALUES (101, ?, 1)
	`, testHash(0x5a))
	require.Error(t, err)

	require.Zero(t, foreignKeyViolations(t, db))
}
