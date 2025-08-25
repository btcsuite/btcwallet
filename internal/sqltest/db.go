//go:build integration_test

package sqltest

import (
	"database/sql"
	"fmt"
	"hash/fnv"
	"testing"

	// Register the pgx driver under name "pgx".
	_ "github.com/jackc/pgx/v5/stdlib"

	// Register SQLite driver under name "sqlite".
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

// deterministicTestID generates a deterministic identifier based on the test
// name. This ensures that Golang test caching works properly by avoiding
// random generations for the database name. We need to use this hash to avoid
// long database names that can be cropped by some database systems.
func deterministicTestID(t testing.TB) string {
	t.Helper()
	h := fnv.New32a()
	_, err := h.Write([]byte(t.Name()))

	// This should never fail, but we handle it just in case.
	require.NoError(t, err)

	hashed := fmt.Sprintf("%08x", h.Sum32())
	t.Logf("db name hash: %s", hashed)
	return hashed
}
