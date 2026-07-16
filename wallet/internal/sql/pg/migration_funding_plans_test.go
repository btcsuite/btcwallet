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
	) VALUES (1, 'w', 1, 1, TRUE, $1, $2)`, []byte{1}, []byte{2})

	exec(`INSERT INTO utxo_leases (
		wallet_id, tx_hash, output_index, lock_id, expires_unix
	) VALUES (1, $1, 0, $2, 5000)`, testHash(0x10), testHash(0x20))
}

// TestFundingPlansMigration exercises the funding plans and address/runtime
// guards migration against a real PostgreSQL instance: the forward migration
// adds the funding_plans table and the lease owner columns while preserving the
// external lease and enforcing the new constraints, and the down migration
// drops the grouping while preserving every lease outpoint.
func TestFundingPlansMigration(t *testing.T) {
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

	exists := func(query string, args ...any) bool {
		var found bool
		require.NoError(t, db.QueryRow(query, args...).Scan(&found))

		return found
	}

	t.Run("forward", func(t *testing.T) {
		reset()
		m := migrateInstance(t, db)
		require.NoError(t, m.Migrate(13))
		seedFundingPlansFixture(t, db)
		require.NoError(t, m.Migrate(14))

		// The pre-existing lease survived as an external, planless lease.
		var ownerType string

		var planID sql.NullInt64

		require.NoError(t, db.QueryRow(`
			SELECT owner_type, funding_plan_id FROM utxo_leases
			WHERE wallet_id = 1 AND tx_hash = $1
		`, testHash(0x10)).Scan(&ownerType, &planID))
		require.Equal(t, "external", ownerType)
		require.False(t, planID.Valid)

		// funding_plans accepts a reserved plan and one of its own leases.
		_, err := db.ExecContext(ctx, `
			INSERT INTO funding_plans (
				id, wallet_id, reservation_id, purpose, status, created_at,
				expires_at
			) VALUES (1, 1, $1, 'construction', 'reserved', 1000, 2000)
		`, testHash(0x30))
		require.NoError(t, err)

		_, err = db.ExecContext(ctx, `
			INSERT INTO utxo_leases (
				wallet_id, tx_hash, output_index, lock_id, expires_unix,
				owner_type, funding_plan_id
			) VALUES (1, $1, 0, $2, 2000, 'funding_plan', 1)
		`, testHash(0x40), testHash(0x30))
		require.NoError(t, err)

		// A duplicate reservation id for the wallet is rejected.
		_, err = db.ExecContext(ctx, `
			INSERT INTO funding_plans (
				wallet_id, reservation_id, purpose, status, created_at,
				expires_at
			) VALUES (1, $1, 'construction', 'reserved', 1000, 2000)
		`, testHash(0x30))
		require.Error(t, err)

		// A funding-plan lease must name a plan; the owner-type check rejects
		// a null plan id.
		_, err = db.ExecContext(ctx, `
			INSERT INTO utxo_leases (
				wallet_id, tx_hash, output_index, lock_id, expires_unix,
				owner_type, funding_plan_id
			) VALUES (1, $1, 0, $2, 2000, 'funding_plan', NULL)
		`, testHash(0x50), testHash(0x60))
		require.Error(t, err)

		// The derived-address derivation-path unique index exists.
		require.True(t, exists(`
			SELECT EXISTS (SELECT 1 FROM pg_indexes
			WHERE indexname = 'uidx_addresses_derivation_path')
		`))
	})

	t.Run("down", func(t *testing.T) {
		reset()
		m := migrateInstance(t, db)
		require.NoError(t, m.Migrate(13))
		seedFundingPlansFixture(t, db)
		require.NoError(t, m.Migrate(14))

		// Add a plan and one plan-owned lease so the down migration has
		// grouping data to demote.
		_, err := db.ExecContext(ctx, `
			INSERT INTO funding_plans (
				id, wallet_id, reservation_id, purpose, status, created_at,
				expires_at
			) VALUES (1, 1, $1, 'construction', 'reserved', 1000, 2000)
		`, testHash(0x30))
		require.NoError(t, err)

		_, err = db.ExecContext(ctx, `
			INSERT INTO utxo_leases (
				wallet_id, tx_hash, output_index, lock_id, expires_unix,
				owner_type, funding_plan_id
			) VALUES (1, $1, 0, $2, 2000, 'funding_plan', 1)
		`, testHash(0x40), testHash(0x30))
		require.NoError(t, err)

		require.NoError(t, m.Migrate(13))

		// The funding_plans grouping table is gone.
		require.False(t, exists(`
			SELECT EXISTS (SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'funding_plans')
		`))

		// Every lease outpoint survived: the external lease and the demoted
		// plan-owned lease.
		var leaseCount int
		require.NoError(t, db.QueryRow(
			"SELECT count(*) FROM utxo_leases WHERE wallet_id = 1",
		).Scan(&leaseCount))
		require.Equal(t, 2, leaseCount)

		// The owner columns no longer exist on the restored table.
		require.False(t, exists(`
			SELECT EXISTS (SELECT 1 FROM information_schema.columns
			WHERE table_name = 'utxo_leases' AND column_name = 'owner_type')
		`))
	})
}
