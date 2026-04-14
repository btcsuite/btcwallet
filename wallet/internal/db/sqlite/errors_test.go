package sqlite

import (
	"database/sql"
	"path/filepath"
	"testing"

	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/stretchr/testify/require"
	sqlite3 "modernc.org/sqlite/lib"
)

// TestMapErrConstraint verifies that SQLite constraint violations are mapped to
// permanent constraint failures.
func TestMapErrConstraint(t *testing.T) {
	t.Parallel()

	dbConn, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "wallet.db"))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, dbConn.Close())
	})

	ctx := t.Context()

	_, err = dbConn.ExecContext(
		ctx, `CREATE TABLE demo (id INTEGER PRIMARY KEY, val TEXT UNIQUE)`,
	)
	require.NoError(t, err)

	_, err = dbConn.ExecContext(ctx, `INSERT INTO demo (val) VALUES ('dup')`)
	require.NoError(t, err)

	_, err = dbConn.ExecContext(ctx, `INSERT INTO demo (val) VALUES ('dup')`)
	require.Error(t, err)

	sqlErr := mapErr(err)
	require.NotNil(t, sqlErr)
	require.Equal(t, dberr.BackendSQLite, sqlErr.Backend)
	require.Equal(t, dberr.ReasonConstraint, sqlErr.Reason)
	require.Equal(t, dberr.ClassPermanent, sqlErr.Class())
	require.NotEmpty(t, sqlErr.Code)
}

// TestMapErrReadOnly verifies that SQLite query-only failures are mapped to
// fatal read-only backend errors.
func TestMapErrReadOnly(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "wallet.db")
	dbConn, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)

	ctx := t.Context()

	_, err = dbConn.ExecContext(
		ctx, `CREATE TABLE demo (id INTEGER PRIMARY KEY, val TEXT)`,
	)
	require.NoError(t, err)
	require.NoError(t, dbConn.Close())

	roDB, err := sql.Open("sqlite", dbPath+"?_pragma=query_only=on")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, roDB.Close())
	})

	_, err = roDB.ExecContext(ctx, `INSERT INTO demo (val) VALUES ('x')`)
	require.Error(t, err)

	sqlErr := mapErr(err)
	require.NotNil(t, sqlErr)
	require.Equal(t, dberr.BackendSQLite, sqlErr.Backend)
	require.Equal(t, dberr.ReasonReadOnly, sqlErr.Reason)
	require.Equal(t, dberr.ClassFatal, sqlErr.Class())
}

// TestHelpers verifies the SQLite-specific helper paths.
func TestHelpers(t *testing.T) {
	t.Parallel()

	require.Equal(t, "5", codeString(5))
	require.Equal(t, dberr.ReasonUnavailable,
		reasonByCode[sqlite3.SQLITE_PROTOCOL])
	require.Equal(t, dberr.ReasonUnknown,
		reasonByCode[sqlite3.SQLITE_NOTFOUND])
	require.Equal(t, sqlite3.SQLITE_CONSTRAINT,
		primaryCode(sqlite3.SQLITE_CONSTRAINT_UNIQUE))
}
