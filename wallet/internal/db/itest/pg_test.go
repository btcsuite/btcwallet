//go:build itest && test_db_postgres

package itest

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	// Shared container instance, reused across tests for performance.
	// This is safe to use concurrently because we only share the container
	// and not the database inside it. Each test gets its own database.
	pgContainer *postgres.PostgresContainer

	// Ensure the container is created only once.
	pgContainerOnce sync.Once

	// Error returned by the container creation operation. We need to store
	// it to return when the error already occurred during test setup.
	pgContainerErr error

	// Timeout for waiting for the postgres container to start. Needs to
	// consider container image download time.
	pgInitTimeout = 2 * time.Minute

	// Timeout for terminating the postgres container after the test suite.
	pgTerminateTimeout = 1 * time.Minute
)

// TestMain ensures the shared postgres container is terminated after the
// integration test suite completes to avoid leaking docker resources.
func TestMain(m *testing.M) {
	code := m.Run()

	// Terminate the container after the test suite completes.
	if pgContainer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), pgTerminateTimeout)
		defer cancel()

		err := pgContainer.Terminate(ctx)
		if err != nil {
			fmt.Printf("failed to terminate postgres container: %v\n", err)
		}
	}

	os.Exit(code)
}

// PostgresConfig holds configuration for the test PostgreSQL database.
type PostgresConfig struct {
	// Image is the Docker image to use.
	Image string

	// Database is the database name.
	Database string

	// Username is the database user.
	Username string

	// Password is the database password.
	Password string
}

// DefaultPostgresConfig returns the default PostgreSQL test configuration.
func DefaultPostgresConfig() PostgresConfig {
	return PostgresConfig{
		Image:    "postgres:18-alpine",
		Database: "postgres",
		Username: "postgres",
		Password: "postgres",
	}
}

// GetPostgresContainer returns the shared PostgreSQL container instance.
// The container is created once and reused across all tests for performance.
//
// Note: postgres:18-alpine defaults max_connections to 100.
func GetPostgresContainer(ctx context.Context) (*postgres.PostgresContainer, error) {
	pgContainerOnce.Do(func() {
		cfg := DefaultPostgresConfig()

		pgContainer, pgContainerErr = postgres.RunContainer(ctx,
			testcontainers.WithImage(cfg.Image),
			postgres.WithDatabase(cfg.Database),
			postgres.WithUsername(cfg.Username),
			postgres.WithPassword(cfg.Password),
			testcontainers.WithWaitStrategyAndDeadline(
				pgInitTimeout, wait.ForListeningPort("5432/tcp"),
			),
		)
	})

	return pgContainer, pgContainerErr
}

// sanitizedPgDBName converts a test name to a valid PostgreSQL database name.
// It converts to lowercase and replaces special characters with underscores.
func sanitizedPgDBName(t *testing.T) string {
	// Convert to lowercase.
	dbName := strings.ToLower(t.Name())

	// Replace slashes and other special chars with underscores.
	reg := regexp.MustCompile(`[^a-z0-9_]`)
	dbName = reg.ReplaceAllString(dbName, "_")

	// PostgreSQL database names are limited to 63 characters.
	if len(dbName) > 63 {
		dbName = dbName[:63]
		t.Logf("database name truncated to %d characters: %s", 63, dbName)
	}

	return dbName
}

// NewPostgresDB creates a new PostgreSQL database connection with migrations
// applied. Each test gets its own database for isolation.
func NewPostgresDB(t *testing.T) *sql.DB {
	t.Helper()
	ctx := t.Context()

	container, err := GetPostgresContainer(ctx)
	require.NoError(t, err, "failed to get postgres container")

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err, "failed to get connection string")

	// Connect to the default database to create our test database.
	adminDB, err := sql.Open("pgx", connStr)
	require.NoError(t, err, "failed to open admin connection")
	require.NotNil(t, adminDB, "admin connection is nil")

	// Close the connection to avoid leaking an idle connection during tests.
	// The container is reused across all tests, so we explicitly clean this up.
	t.Cleanup(func() {
		_ = adminDB.Close()
	})

	// Create a database name based on the test name.
	dbName := sanitizedPgDBName(t)

	// Create the test database.
	createDBStmt := fmt.Sprintf("CREATE DATABASE %s", dbName)
	_, err = adminDB.ExecContext(ctx, createDBStmt)
	require.NoError(t, err, "failed to create test database")

	// Build the connection string for the test database.
	testConnStr := strings.Replace(connStr, "/postgres?", "/"+dbName+"?", 1)

	// TODO(gustavostingelin): replace with the real PostgreSQL database
	// connection constructor when available.
	dbConn, err := sql.Open("pgx", testConnStr)
	require.NoError(t, err, "failed to open test database connection")
	require.NotNil(t, dbConn, "test database connection is nil")

	// Close the connection to avoid leaking an idle connection during tests.
	// The container is reused across all tests, so we explicitly clean this up.
	t.Cleanup(func() {
		_ = dbConn.Close()
	})

	err = db.ApplyPostgresMigrations(dbConn)
	require.NoError(t, err, "failed to apply migrations")

	return dbConn
}

// NewTestStore creates a PostgreSQL wallet store and returns it along with the
// underlying database connection for tests that also need direct DB access.
func NewTestStore(t *testing.T) (*db.PostgresWalletDB, *sqlcpg.Queries) {
	t.Helper()

	dbConn := NewPostgresDB(t)

	store, err := db.NewPostgresWalletDB(dbConn)
	require.NoError(t, err, "failed to create wallet store")

	queries := sqlcpg.New(dbConn)

	return store, queries
}
