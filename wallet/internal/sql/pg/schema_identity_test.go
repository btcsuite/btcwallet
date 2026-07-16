//go:build test_db_postgres

package pg

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/sql/schemaid"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// newSchemaTestDB starts a throwaway PostgreSQL container and returns a
// connection pool for a gate test.
func newSchemaTestDB(t *testing.T) *sql.DB {
	t.Helper()

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

	return db
}

// resetPublicSchema drops and recreates the public schema so a shared container
// can be reused across sequential cases with a clean database each time.
func resetPublicSchema(t *testing.T, db *sql.DB) {
	t.Helper()

	execSchema(t, db, "DROP SCHEMA public CASCADE")
	execSchema(t, db, "CREATE SCHEMA public")
}

// hasSchemaTable reports whether the named table exists in the public schema.
func hasSchemaTable(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()

	var exists bool
	err := db.QueryRowContext(
		context.Background(),
		"SELECT EXISTS (SELECT 1 FROM information_schema.tables "+
			"WHERE table_schema = 'public' AND table_name = $1)", name,
	).Scan(&exists)
	require.NoError(t, err)

	return exists
}

// requireMarker asserts that the database carries exactly one identity row with
// the current family and generation.
func requireMarker(t *testing.T, db *sql.DB) {
	t.Helper()

	var (
		count      int
		family     string
		generation int64
	)
	err := db.QueryRowContext(
		context.Background(),
		"SELECT count(*), max(family), max(generation) FROM "+
			schemaid.IdentityTable,
	).Scan(&count, &family, &generation)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Equal(t, schemaid.Family, family)
	require.EqualValues(t, schemaid.Generation, generation)
}

// migrateTo applies migrations up to a specific version, recreating the
// pre-marker salvage state.
func migrateTo(t *testing.T, db *sql.DB, version uint) {
	t.Helper()

	m, err := newMigrationInstance(db)
	require.NoError(t, err)

	require.NoError(t, m.Migrate(version))

	sourceErr, databaseErr := m.Close()
	require.NoError(t, sourceErr)
	require.NoError(t, databaseErr)
}

// TestSchemaIdentityBootstrap verifies that an empty database is migrated and
// marked, and that reopening it is idempotent.
func TestSchemaIdentityBootstrap(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := newSchemaTestDB(t)

	require.NoError(t, EnsureSchemaFamily(ctx, db))
	require.True(t, hasSchemaTable(t, db, schemaid.IdentityTable))
	require.True(t, hasSchemaTable(t, db, "wallets"))
	requireMarker(t, db)

	// A second call must be a no-op that leaves a single marker row.
	require.NoError(t, EnsureSchemaFamily(ctx, db))
	requireMarker(t, db)
}

// TestSchemaIdentityBackfill verifies that a known pre-marker salvage database,
// migrated only to version ten, is migrated forward and backfilled with a
// marker.
func TestSchemaIdentityBackfill(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := newSchemaTestDB(t)

	// Recreate the pre-marker salvage state: migrations one through ten
	// applied, with no identity table yet.
	migrateTo(t, db, 10)
	require.False(t, hasSchemaTable(t, db, schemaid.IdentityTable))

	require.NoError(t, EnsureSchemaFamily(ctx, db))
	require.True(t, hasSchemaTable(t, db, schemaid.IdentityTable))
	requireMarker(t, db)
}

// TestSchemaIdentityUnmarkedRejections verifies that a non-empty, unmarked
// database with a foreign, unknown, or dirty shape is rejected with the correct
// typed error and no identity table is created.
func TestSchemaIdentityUnmarkedRejections(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		setup   func(t *testing.T, db *sql.DB)
		wantErr error
	}{
		{
			name: "foreign utxos table",
			setup: func(t *testing.T, db *sql.DB) {
				execSchema(t, db,
					"CREATE TABLE utxos (id INTEGER PRIMARY KEY)")
			},
			wantErr: schemaid.ErrForeignSchemaFamily,
		},
		{
			name: "normalized foreign schema",
			setup: func(t *testing.T, db *sql.DB) {
				execSchema(t, db,
					"CREATE TABLE utxos (id INTEGER PRIMARY KEY)")
				execSchema(t, db,
					"CREATE TABLE tx_replacements "+
						"(id INTEGER PRIMARY KEY)")
			},
			wantErr: schemaid.ErrForeignSchemaFamily,
		},
		{
			name: "unknown table shape",
			setup: func(t *testing.T, db *sql.DB) {
				execSchema(t, db,
					"CREATE TABLE random_table (id INTEGER PRIMARY KEY)")
			},
			wantErr: schemaid.ErrUnknownSchema,
		},
		{
			name: "dirty in-progress migration",
			setup: func(t *testing.T, db *sql.DB) {
				execSchema(t, db,
					"CREATE TABLE blocks (id INTEGER PRIMARY KEY)")
				execSchema(t, db,
					"CREATE TABLE schema_migrations "+
						"(version BIGINT NOT NULL, "+
						"dirty BOOLEAN NOT NULL)")
				execSchema(t, db,
					"INSERT INTO schema_migrations "+
						"(version, dirty) VALUES (1, TRUE)")
			},
			wantErr: schemaid.ErrDirtySchema,
		},
	}

	ctx := context.Background()
	db := newSchemaTestDB(t)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resetPublicSchema(t, db)
			tc.setup(t, db)

			err := EnsureSchemaFamily(ctx, db)
			require.ErrorIs(t, err, tc.wantErr)

			// A rejected database must never be marked.
			require.False(
				t, hasSchemaTable(t, db, schemaid.IdentityTable),
			)
		})
	}
}

// TestSchemaIdentityMarkedRejections verifies that a marked database with a
// foreign family, dirty state, or out-of-range generation is rejected with the
// correct typed error.
func TestSchemaIdentityMarkedRejections(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		mutate  func(t *testing.T, db *sql.DB)
		wantErr error
	}{
		{
			name: "foreign family marker",
			mutate: func(t *testing.T, db *sql.DB) {
				execSchema(t, db,
					"UPDATE "+schemaid.IdentityTable+
						" SET family = 'other-family'")
			},
			wantErr: schemaid.ErrForeignSchemaFamily,
		},
		{
			name: "newer generation marker",
			mutate: func(t *testing.T, db *sql.DB) {
				execSchema(t, db,
					"UPDATE "+schemaid.IdentityTable+
						" SET generation = generation + 1")
			},
			wantErr: schemaid.ErrNewerGeneration,
		},
		{
			name: "unsupported generation marker",
			mutate: func(t *testing.T, db *sql.DB) {
				execSchema(t, db,
					"UPDATE "+schemaid.IdentityTable+
						" SET generation = 0")
			},
			wantErr: schemaid.ErrUnsupportedGeneration,
		},
		{
			name: "dirty marked database",
			mutate: func(t *testing.T, db *sql.DB) {
				execSchema(t, db,
					"UPDATE schema_migrations SET dirty = TRUE")
			},
			wantErr: schemaid.ErrDirtySchema,
		},
	}

	ctx := context.Background()
	db := newSchemaTestDB(t)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resetPublicSchema(t, db)

			// Start from a valid marked database, then corrupt it.
			require.NoError(t, EnsureSchemaFamily(ctx, db))
			tc.mutate(t, db)

			err := EnsureSchemaFamily(ctx, db)
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// execSchema runs a schema statement and fails the test on error.
func execSchema(t *testing.T, db *sql.DB, query string) {
	t.Helper()

	_, err := db.ExecContext(context.Background(), query)
	require.NoError(t, err)
}
