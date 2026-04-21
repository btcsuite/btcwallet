package sqlite

import (
	"database/sql"
	"path/filepath"
	"testing"

	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/stretchr/testify/require"
)

// TestClassifyErrorReturnsOriginalErrors verifies that SQLite classification
// preserves domain and already-classified errors unchanged.
func TestClassifyErrorReturnsOriginalErrors(t *testing.T) {
	t.Parallel()

	store := &Store{}
	errDup := dberr.NewSQLError(
		dberr.BackendSQLite, dberr.ReasonConstraint, "19", sql.ErrTxDone,
	)
	tests := []struct {
		name string
		err  error
	}{
		{name: "wallet not found", err: db.ErrWalletNotFound},
		{name: "tx not found", err: db.ErrTxNotFound},
		{name: "generic error", err: sql.ErrNoRows},
		{name: "existing sql error", err: errDup},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			require.Same(t, test.err, store.ClassifyError(test.err))
		})
	}
}

// TestClassifyErrorTransportError verifies that SQLite transport failures are
// classified as shared unavailable SQL errors.
func TestClassifyErrorTransportError(t *testing.T) {
	t.Parallel()

	store := &Store{}
	classifiedErr := store.ClassifyError(sql.ErrConnDone)

	var sqlErr *dberr.SQLError
	require.ErrorAs(t, classifiedErr, &sqlErr)
	require.Equal(t, dberr.ReasonUnavailable, sqlErr.Reason)
}

// TestClassifyErrorBackendConstraint verifies that SQLite constraint failures
// are classified as shared SQL constraint errors.
func TestClassifyErrorBackendConstraint(t *testing.T) {
	t.Parallel()

	store := &Store{}
	dbPath := filepath.Join(t.TempDir(), "wallet.db")
	dbConn, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, dbConn.Close())
	})

	ctx := t.Context()
	_, err = dbConn.ExecContext(
		ctx, `CREATE TABLE demo (id INTEGER PRIMARY KEY, val TEXT UNIQUE)`,
	)
	require.NoError(t, err)

	_, err = dbConn.ExecContext(
		ctx, `INSERT INTO demo (val) VALUES ('dup')`,
	)
	require.NoError(t, err)

	_, err = dbConn.ExecContext(
		ctx, `INSERT INTO demo (val) VALUES ('dup')`,
	)
	require.Error(t, err)

	classifiedErr := store.ClassifyError(err)

	var sqlErr *dberr.SQLError
	require.ErrorAs(t, classifiedErr, &sqlErr)
	require.Equal(t, dberr.ReasonConstraint, sqlErr.Reason)
}

// TestClassifyErrorUnknownBackendError verifies that unmapped SQLite-native
// errors still remain wrapped as shared SQL errors with ReasonUnknown.
func TestClassifyErrorUnknownBackendError(t *testing.T) {
	t.Parallel()

	store := &Store{}
	dbPath := filepath.Join(t.TempDir(), "wallet.db")
	dbConn, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, dbConn.Close())
	})

	ctx := t.Context()
	_, err = dbConn.ExecContext(
		ctx, `CREATE TABLE demo (id INTEGER PRIMARY KEY, val TEXT)`,
	)
	require.NoError(t, err)

	_, err = dbConn.ExecContext(ctx, `SELECT * FROM demo WHERE`)
	require.Error(t, err)

	classifiedErr := store.ClassifyError(err)

	var sqlErr *dberr.SQLError
	require.ErrorAs(t, classifiedErr, &sqlErr)
	require.Equal(t, dberr.ReasonUnknown, sqlErr.Reason)
	require.Equal(t, dberr.BackendSQLite, sqlErr.Backend)
}
