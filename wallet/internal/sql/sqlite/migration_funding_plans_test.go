package sqlite

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
)

// fundingPlansBaseVersion is the schema version immediately before the funding
// plans and address/runtime guards migration.
const fundingPlansBaseVersion = 13

// fundingPlansVersion is the schema version that adds funding plans, the lease
// owner columns, and the derived-address derivation-path uniqueness.
const fundingPlansVersion = 14

// seedFundingPlansFixture inserts a wallet and one pre-existing external lease
// under the runtime-journal schema so the forward migration has lease data to
// preserve.
func seedFundingPlansFixture(t *testing.T, db *sql.DB) {
	t.Helper()

	ctx := context.Background()
	exec := func(query string, args ...any) {
		_, err := db.ExecContext(ctx, query, args...)
		require.NoError(t, err)
	}

	exec(`INSERT INTO wallets (
		id, wallet_name, manager_version, manager_created_at, is_watch_only,
		master_pub_params, encrypted_crypto_pub_key
	) VALUES (1, 'w', 1, 1, TRUE, x'01', x'02')`)

	exec(`INSERT INTO utxo_leases (
		wallet_id, tx_hash, output_index, lock_id, expires_unix
	) VALUES (1, ?, 0, ?, 5000)`, testHash(0x10), testHash(0x20))
}

// TestFundingPlansMigrationForward verifies that the forward migration adds the
// funding_plans table and the lease owner columns, preserves the pre-existing
// external lease, enforces the plan and lease constraints, and installs the
// derivation-path uniqueness index without leaving a foreign key violation.
func TestFundingPlansMigrationForward(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openBlockIdentityDB(t)

	m, err := newMigrationInstance(db)
	require.NoError(t, err)
	require.NoError(t, m.Migrate(fundingPlansBaseVersion))

	seedFundingPlansFixture(t, db)
	require.NoError(t, m.Migrate(fundingPlansVersion))

	// The pre-existing lease survived the rebuild as an external, planless
	// lease.
	var ownerType string

	var planID sql.NullInt64

	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT owner_type, funding_plan_id FROM utxo_leases
		WHERE wallet_id = 1 AND tx_hash = ?
	`, testHash(0x10)).Scan(&ownerType, &planID))
	require.Equal(t, "external", ownerType)
	require.False(t, planID.Valid)

	// funding_plans accepts a reserved plan and one of its own leases.
	_, err = db.ExecContext(ctx, `
		INSERT INTO funding_plans (
			id, wallet_id, reservation_id, purpose, status, created_at,
			expires_at
		) VALUES (1, 1, ?, 'construction', 'reserved', 1000, 2000)
	`, testHash(0x30))
	require.NoError(t, err)

	_, err = db.ExecContext(ctx, `
		INSERT INTO utxo_leases (
			wallet_id, tx_hash, output_index, lock_id, expires_unix,
			owner_type, funding_plan_id
		) VALUES (1, ?, 0, ?, 2000, 'funding_plan', 1)
	`, testHash(0x40), testHash(0x30))
	require.NoError(t, err)

	// A duplicate reservation id for the wallet is rejected.
	_, err = db.ExecContext(ctx, `
		INSERT INTO funding_plans (
			wallet_id, reservation_id, purpose, status, created_at, expires_at
		) VALUES (1, ?, 'construction', 'reserved', 1000, 2000)
	`, testHash(0x30))
	require.Error(t, err)

	// A funding-plan lease must name a plan; the owner-type check rejects a
	// null plan id.
	_, err = db.ExecContext(ctx, `
		INSERT INTO utxo_leases (
			wallet_id, tx_hash, output_index, lock_id, expires_unix,
			owner_type, funding_plan_id
		) VALUES (1, ?, 0, ?, 2000, 'funding_plan', NULL)
	`, testHash(0x50), testHash(0x60))
	require.Error(t, err)

	// The derived-address derivation-path unique index exists.
	var indexCount int

	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT count(*) FROM sqlite_master
		WHERE type = 'index' AND name = 'uidx_addresses_derivation_path'
	`).Scan(&indexCount))
	require.Equal(t, 1, indexCount)

	require.Zero(t, foreignKeyViolations(t, db))
}

// TestFundingPlansMigrationDown verifies that the down migration drops the
// funding_plans grouping while preserving every lease outpoint, demoting a
// plan-owned lease to a plain lease rather than discarding exclusion.
func TestFundingPlansMigrationDown(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openBlockIdentityDB(t)

	m, err := newMigrationInstance(db)
	require.NoError(t, err)
	require.NoError(t, m.Migrate(fundingPlansBaseVersion))

	seedFundingPlansFixture(t, db)
	require.NoError(t, m.Migrate(fundingPlansVersion))

	// Add a plan and one plan-owned lease so the down migration has grouping
	// data to demote.
	_, err = db.ExecContext(ctx, `
		INSERT INTO funding_plans (
			id, wallet_id, reservation_id, purpose, status, created_at,
			expires_at
		) VALUES (1, 1, ?, 'construction', 'reserved', 1000, 2000)
	`, testHash(0x30))
	require.NoError(t, err)

	_, err = db.ExecContext(ctx, `
		INSERT INTO utxo_leases (
			wallet_id, tx_hash, output_index, lock_id, expires_unix,
			owner_type, funding_plan_id
		) VALUES (1, ?, 0, ?, 2000, 'funding_plan', 1)
	`, testHash(0x40), testHash(0x30))
	require.NoError(t, err)

	require.NoError(t, m.Migrate(fundingPlansBaseVersion))

	// The funding_plans grouping table is gone.
	var tableCount int

	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT count(*) FROM sqlite_master
		WHERE type = 'table' AND name = 'funding_plans'
	`).Scan(&tableCount))
	require.Zero(t, tableCount)

	// Every lease outpoint survived: the external lease and the demoted
	// plan-owned lease.
	var leaseCount int

	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT count(*) FROM utxo_leases WHERE wallet_id = 1",
	).Scan(&leaseCount))
	require.Equal(t, 2, leaseCount)

	// The owner columns no longer exist on the restored table.
	_, err = db.ExecContext(ctx, "SELECT owner_type FROM utxo_leases")
	require.Error(t, err)

	require.Zero(t, foreignKeyViolations(t, db))
}
