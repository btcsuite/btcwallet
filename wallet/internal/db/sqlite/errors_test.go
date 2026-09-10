package sqlite

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/stretchr/testify/require"
	sqlite3 "modernc.org/sqlite/lib"
)

// TestMapErrConstraint verifies that SQLite constraint violations are mapped to
// permanent constraint failures.
func TestMapErrConstraint(t *testing.T) {
	t.Parallel()

	// Arrange: Create both unique keys so real driver diagnostics distinguish
	// account-name collisions from account-number collisions.
	dbConn, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "wallet.db"))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, dbConn.Close())
	})

	ctx := t.Context()

	_, err = dbConn.ExecContext(ctx, `CREATE TABLE accounts (
		wallet_id INTEGER,
		scope_id INTEGER,
		account_name TEXT,
		account_number INTEGER,
		UNIQUE (wallet_id, scope_id, account_name)
	)`)
	require.NoError(t, err)

	// Match the migrated partial index so the negative control produces the
	// same account-number diagnostic as a persisted derived account.
	_, err = dbConn.ExecContext(ctx, `CREATE UNIQUE INDEX
		uidx_accounts_scope_account_number
		ON accounts (scope_id, account_number)
		WHERE account_number IS NOT NULL`)
	require.NoError(t, err)

	_, err = dbConn.ExecContext(
		ctx, `INSERT INTO accounts VALUES (1, 2, 'first', 3)`,
	)
	require.NoError(t, err)

	// Act: Violate only the account-name key and map its driver error.
	_, err = dbConn.ExecContext(
		ctx, `INSERT INTO accounts VALUES (1, 2, 'first', 4)`,
	)
	require.Error(t, err)

	sqlErr := mapErr(err)

	// Assert: Keep permanent SQL classification and add the name sentinel.
	require.Equal(t, dberr.ReasonConstraint, sqlErr.Reason)
	require.Equal(t, dberr.ClassPermanent, sqlErr.Class())
	require.ErrorIs(t, sqlErr, db.ErrAccountNameConflict)

	// Act: Violate the other unique key with a different account name.
	_, err = dbConn.ExecContext(
		ctx, `INSERT INTO accounts VALUES (1, 2, 'second', 3)`,
	)
	require.Error(t, err)

	// Assert: A number collision must not claim the name is occupied.
	require.NotErrorIs(t, mapErr(err), db.ErrAccountNameConflict)
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
