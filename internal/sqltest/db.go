//go:build integration_test

package sqltest

import (
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"
	"testing"
	"time"

	// Register the pgx driver for database/sql under name "pgx".
	_ "github.com/jackc/pgx/v5/stdlib"

	// Register SQLite driver (pure Go) under name "sqlite".
	_ "modernc.org/sqlite"

	"github.com/stretchr/testify/require"
)

// DBFactory is a function type that creates a new database connection for
// testing purposes. It takes a testing.TB interface to allow for test failure
// when cannot create the database connection, add cleanup logic and create a
// unique and isolated database for each test case.
type DBFactory func(t testing.TB) *sql.DB

// DBTestFunc is a function type that defines the signature for database test
// functions that will be run against different database implementations.
type DBTestFunc func(t *testing.T, dbFactory DBFactory)

// RunDatabaseTest runs the same test function against both PostgreSQL and
// SQLite databases. It creates a new database connection for each test case,
// ensuring that tests are isolated and can run in parallel.
func RunDatabaseTest(t *testing.T, testFunc DBTestFunc) {
	t.Helper()

	testCases := []struct {
		name      string
		dbFactory func(t testing.TB) *sql.DB
	}{
		{
			name:      "Postgres",
			dbFactory: NewPostgresDB,
		},
		{
			name:      "SQLite",
			dbFactory: NewSQLiteDB,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testFunc(t, tc.dbFactory)
		})
	}
}

// ApplySQL executes a multi-statement SQL string using Exec. Useful for simple
// ad-hoc migrations or setup tasks in tests.
func ApplySQL(t testing.TB, db *sql.DB, sqlStatements string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := db.ExecContext(ctx, sqlStatements)
	require.NoError(t, err, "cannot apply SQL statements: %s", sqlStatements)
}

// deterministicTestID generates a deterministic identifier based on the test
// name. This ensures that Golang test caching works properly by avoiding
// random generations for the database name.
func deterministicTestID(t testing.TB) string {
	t.Helper()
	h := fnv.New32a()
	_, err := h.Write([]byte(t.Name()))

	// This should never fail, but we handle it just in case.
	require.NoError(t, err)
	return fmt.Sprintf("%08x", h.Sum32())
}
