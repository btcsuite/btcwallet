//go:build integration_test

package sqltest

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

var (
	pgOnce      sync.Once
	pgContainer *postgres.PostgresContainer
	pgAdminDSN  string
)

// getPostgresContainer returns a singleton Postgres container and its admin
// DSN. If the container can't be started (e.g., Docker not running), the test
// is skipped.
func getPostgresContainer(t testing.TB) (*postgres.PostgresContainer, string) {
	t.Helper()

	pgOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		pgContainer, err := postgres.Run(ctx, "postgres:16-alpine",
			postgres.WithDatabase("btcwallet"),
			postgres.WithUsername("postgres"),
			postgres.WithPassword("postgres"),
		)
		require.NoError(t, err, "failed to start Postgres container")

		pgAdminDSN, err =
			pgContainer.ConnectionString(ctx, "sslmode=disable")
		require.NoError(t, err, "failed to get Postgres admin DSN")
	})

	return pgContainer, pgAdminDSN
}

// NewPostgresDB creates an isolated fresh database inside a shared Postgres
// container and returns a connection to it. Automatic drop the database when
// the test ends. Uses deterministic database naming for proper test caching.
func NewPostgresDB(t testing.TB) *sql.DB {
	t.Helper()

	_, adminDSN := getPostgresContainer(t)

	// Create the database using an admin connection.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	admin, err := sql.Open("pgx", adminDSN)
	require.NoError(t, err, "failed to connect to postgres")

	defer func(admin *sql.DB) {
		err := admin.Close()
		assert.NoError(t, err, "failed to close admin connection")
	}(admin)

	admin.SetMaxOpenConns(5)
	admin.SetMaxIdleConns(5)

	// Wait for the admin DB to become ready.
	err = pingUntil(ctx, admin, 45*time.Second)
	require.NoError(t, err, "failed to ping admin DB")

	// Use deterministic database name based on test name
	name := "btcwallet_test_" + deterministicTestID(t)
	createStmt := fmt.Sprintf("CREATE DATABASE %s", name)
	_, err = admin.ExecContext(ctx, createStmt)
	require.NoError(t, err, "failed to create test database")

	// Connect to the test database.
	testDSN, err := setDBNameInDSN(adminDSN, name)
	require.NoError(t, err, "failed to set database name")

	// TODO: Use real PG connection constructor when available.
	db, err := sql.Open("pgx", testDSN)
	require.NoError(t, err, "failed to open test database")

	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(5)
	db.SetConnMaxIdleTime(30 * time.Second)
	db.SetConnMaxLifetime(5 * time.Minute)

	t.Cleanup(
		func() {
			_ = db.Close()

			cctx, ccancel :=
				context.WithTimeout(context.Background(), 30*time.Second)
			defer ccancel()

			admin, err := sql.Open("pgx", adminDSN)
			if err == nil {
				dropStmt :=
					fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)",
						name)
				_, _ = admin.ExecContext(cctx, dropStmt)
				_ = admin.Close()
			}
		},
	)
	return db
}

// pingUntil attempts to ping the DB until it succeeds or the timeout elapses.
func pingUntil(ctx context.Context, db *sql.DB, limit time.Duration) error {
	waitCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()

	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for {
		if err := db.PingContext(waitCtx); err == nil {
			return nil
		}

		select {
		case <-waitCtx.Done():
			return waitCtx.Err()
		case <-ticker.C:
		}
	}
}

// setDBNameInDSN returns a new string with replaced database name in a
// standard postgres DSN (postgres://user:pass@host:port/db?params) with the
// provided dbName.
func setDBNameInDSN(dsn, dbName string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", fmt.Errorf("parse DSN: %w", err)
	}
	u.Path = "/" + dbName
	return u.String(), nil
}
