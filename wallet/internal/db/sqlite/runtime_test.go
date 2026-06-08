package sqlite

import (
	"database/sql"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
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

// TestListSyncedBlocksReadsStoredBlock verifies that SQLite returns persisted
// block metadata for the requested sync range.
func TestListSyncedBlocksReadsStoredBlock(t *testing.T) {
	t.Parallel()

	store, cleanup := newTestStore(t)
	t.Cleanup(cleanup)

	block := &db.Block{
		Hash:      chainhash.Hash{8, 9, 10},
		Height:    144,
		Timestamp: time.Unix(1710003500, 0),
	}
	err := store.execWrite(t.Context(), func(qtx *sqlc.Queries) error {
		return ensureBlockExists(t.Context(), qtx, block)
	})
	require.NoError(t, err)

	blocks, err := store.ListSyncedBlocks(
		t.Context(), db.ListSyncedBlocksQuery{
			StartHeight: block.Height,
			EndHeight:   block.Height,
		},
	)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	require.Equal(t, *block, blocks[0])
}

// TestEnsureBlockExistsRejectsConflictingBlock verifies that insert-or-ignore
// block writes still reject a same-height block with different metadata.
func TestEnsureBlockExistsRejectsConflictingBlock(t *testing.T) {
	t.Parallel()

	store, cleanup := newTestStore(t)
	t.Cleanup(cleanup)

	block := &db.Block{
		Hash:      chainhash.Hash{8, 9, 10},
		Height:    144,
		Timestamp: time.Unix(1710003500, 0),
	}
	conflict := &db.Block{
		Hash:      chainhash.Hash{10, 9, 8},
		Height:    block.Height,
		Timestamp: block.Timestamp,
	}
	err := store.execWrite(t.Context(), func(qtx *sqlc.Queries) error {
		err := ensureBlockExists(t.Context(), qtx, block)
		if err != nil {
			return err
		}

		return ensureBlockExists(t.Context(), qtx, conflict)
	})
	require.ErrorIs(t, err, db.ErrBlockMismatch)
}

// TestListSyncedBlocksRejectsHugeRange verifies that a span that overflows the
// int32 slice-capacity domain fails with a clear casting error before any
// query or allocation, rather than converting to a negative or unbounded make
// capacity on 32-bit platforms.
func TestListSyncedBlocksRejectsHugeRange(t *testing.T) {
	t.Parallel()

	store, cleanup := newTestStore(t)
	t.Cleanup(cleanup)

	// A full uint32 window is a valid ordered range, but its inclusive span
	// exceeds math.MaxInt32, so the span range-check must reject it before
	// touching the database.
	_, err := store.ListSyncedBlocks(t.Context(), db.ListSyncedBlocksQuery{
		StartHeight: 0,
		EndHeight:   math.MaxUint32,
	})
	require.ErrorIs(t, err, db.ErrCastingOverflow)
}
