//go:build integration_test

package sqltest

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// testTable represents a simple table structure for testing.
type testTable struct {
	ID   int
	Name string
}

// Common SQL statements that work identically in both PostgreSQL and SQLite.
const (
	createTableSQL = `
		CREATE TABLE IF NOT EXISTS test_table (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL
		);`
	insertSQL     = `INSERT INTO test_table (id, name) VALUES ($1, $2);`
	selectSQL     = `SELECT id, name FROM test_table ORDER BY id`
	selectByIDSQL = `SELECT id, name FROM test_table WHERE id = $1`
	countSQL      = `SELECT COUNT(*) FROM test_table`
)

// TestDatabaseIsolation tests that each test gets a fresh isolated database
// instance. It runs multiple subtests in parallel, each creating its own
// database, applying migrations, inserting data, and querying it.
func TestDatabaseIsolation(t *testing.T) {
	RunDatabaseTest(t, func(t *testing.T, dbFactory DBFactory) {
		// Create subtests to test isolation
		for i := range 3 {
			t.Run(fmt.Sprintf("TestIsolationDB%d", i), func(t *testing.T) {
				t.Parallel()

				// Create DB and apply migration
				db := dbFactory(t)
				require.NotNil(t, db)
				_, err := db.Exec(createTableSQL)
				require.NoError(t, err)

				// Ensure that the table is empty
				row := db.QueryRow(selectSQL)
				err = row.Scan()
				require.ErrorIs(t, err, sql.ErrNoRows)

				// Insert some rows
				for j := range 10 {
					_, err = db.Exec(insertSQL, j, "db")
					require.NoError(t, err, "insert failed")
				}

				// Select the first row
				var result testTable
				row = db.QueryRow(selectSQL)
				err = row.Scan(&result.ID, &result.Name)
				require.NoError(t, err, "select failed")

				// Check if the row is as expected
				require.Equal(t, 0, result.ID, "expected ID to be 0")
				require.Equal(t, "db", result.Name, "expected Name to be 'db'")
			})
		}
	})
}

// TestDatabaseMultipleRecordsOps tests inserting, selecting, and counting
// multiple records in the database. It verifies that simple multiple operations
// work correctly.
func TestDatabaseMultipleRecordsOps(t *testing.T) {
	RunDatabaseTest(t, func(t *testing.T, dbFactory DBFactory) {
		// Create DB and apply migration
		db := dbFactory(t)
		require.NotNil(t, db)
		_, err := db.Exec(createTableSQL)
		require.NoError(t, err)

		// Test data
		testData := []testTable{
			{100, "test1"},
			{200, "test2"},
			{300, "test3"},
		}

		// Insert test records
		for _, data := range testData {
			_, err := db.Exec(insertSQL, data.ID, data.Name)
			require.NoError(t, err, "insert failed")
		}

		// Verify each record exists
		for _, data := range testData {
			var result testTable
			row := db.QueryRow(selectByIDSQL, data.ID)
			err := row.Scan(&result.ID, &result.Name)
			require.NoError(t, err, "select failed")

			require.Equal(t, data.ID, result.ID, "ID mismatch")
			require.Equal(t, data.Name, result.Name, "Name mismatch")
		}

		// Verify total count
		var count int
		row := db.QueryRow(countSQL)
		err = row.Scan(&count)
		require.NoError(t, err, "count failed")
		require.Equal(t, len(testData), count, "expected count to match inserted records")
	})
}
