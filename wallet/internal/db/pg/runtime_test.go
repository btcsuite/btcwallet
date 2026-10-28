package pg

import (
	"database/sql"
	"io"
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// TestClassifyErrorReturnsOriginalErrors verifies that PostgreSQL
// classification preserves domain and already-classified errors unchanged.
func TestClassifyErrorReturnsOriginalErrors(t *testing.T) {
	t.Parallel()

	store := &Store{}
	errDup := dberr.NewSQLError(
		dberr.BackendPostgres,
		dberr.ReasonConstraint,
		codeUniqueViolation,
		sql.ErrTxDone,
	)
	tests := []struct {
		name string
		err  error
	}{
		{name: "wallet not found", err: db.ErrWalletNotFound},
		{name: "tx not found", err: db.ErrTxNotFound},
		{name: "generic error", err: io.ErrClosedPipe},
		{name: "existing sql error", err: errDup},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			require.Same(t, test.err, store.ClassifyError(test.err))
		})
	}
}

// TestClassifyErrorTransportError verifies that PostgreSQL transport failures
// are classified as shared unavailable SQL errors.
func TestClassifyErrorTransportError(t *testing.T) {
	t.Parallel()

	store := &Store{}
	classifiedErr := store.ClassifyError(&pgconn.ConnectError{})

	var sqlErr *dberr.SQLError
	require.ErrorAs(t, classifiedErr, &sqlErr)
	require.Equal(t, dberr.ReasonUnavailable, sqlErr.Reason)
}

// TestClassifyErrorBackendErrors verifies that PostgreSQL backend-native
// errors stay wrapped as shared SQL errors for both known and unknown codes.
func TestClassifyErrorBackendErrors(t *testing.T) {
	t.Parallel()

	store := &Store{}
	tests := []struct {
		name       string
		err        error
		wantReason dberr.Reason
	}{
		{
			name: "known code",
			err: &pgconn.PgError{
				Code:    codeUniqueViolation,
				Message: "duplicate key",
			},
			wantReason: dberr.ReasonConstraint,
		},
		{
			name: "unknown code",
			err: &pgconn.PgError{
				Code:    "99999",
				Message: "unknown error",
			},
			wantReason: dberr.ReasonUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			classifiedErr := store.ClassifyError(test.err)

			var sqlErr *dberr.SQLError
			require.ErrorAs(t, classifiedErr, &sqlErr)
			require.Equal(t, test.wantReason, sqlErr.Reason)
			require.Equal(t, dberr.BackendPostgres, sqlErr.Backend)
		})
	}
}

// TestListSyncedBlocksBuildsBlock verifies that PostgreSQL maps one block row
// into the shared db.Block shape.
func TestListSyncedBlocksBuildsBlock(t *testing.T) {
	t.Parallel()

	blockHash := chainhash.Hash{11, 12, 13}
	timestamp := time.Unix(1710003600, 0)

	// A single-row range result drives the :many GetBlocksInRange scan path
	// without standing up a real postgres store.
	rows := newSQLiteRows(
		t, "SELECT ?, ?, ?", int32(144), blockHash[:], timestamp.Unix(),
	)
	require.NoError(t, rows.Err())

	store := &Store{
		queries: sqlc.New(rowDBTX{queryRows: rows}),
	}

	blocks, err := store.ListSyncedBlocks(
		t.Context(), db.ListSyncedBlocksQuery{
			StartHeight: 144,
			EndHeight:   144,
		},
	)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	require.Equal(t, db.Block{
		Hash:      blockHash,
		Height:    144,
		Timestamp: timestamp,
	}, blocks[0])
}

// TestEnsureBlockExistsRejectsConflictingBlock verifies that insert-or-ignore
// block writes still reject a same-height block with different metadata.
func TestEnsureBlockExistsRejectsConflictingBlock(t *testing.T) {
	t.Parallel()

	block := &db.Block{
		Hash:      chainhash.Hash{8, 9, 10},
		Height:    144,
		Timestamp: time.Unix(1710003500, 0),
	}
	conflictingHash := chainhash.Hash{10, 9, 8}
	qtx := sqlc.New(rowDBTX{
		row: newSQLiteRow(
			t, "SELECT ?, ?, ?", int32(block.Height),
			conflictingHash[:], block.Timestamp.Unix(),
		),
	})

	err := ensureBlockExists(t.Context(), qtx, block)
	require.ErrorIs(t, err, db.ErrBlockMismatch)
}

// TestListSyncedBlocksRejectsHugeRange verifies that a span that overflows the
// int32 slice-capacity domain fails with a clear casting error before any
// query or allocation. The span range-check returns before execRead, so no
// real postgres store is required.
func TestListSyncedBlocksRejectsHugeRange(t *testing.T) {
	t.Parallel()

	store := &Store{}

	// A full uint32 window is a valid ordered range, but its inclusive span
	// exceeds math.MaxInt32, so the span range-check must reject it before
	// touching the database.
	_, err := store.ListSyncedBlocks(t.Context(), db.ListSyncedBlocksQuery{
		StartHeight: 0,
		EndHeight:   math.MaxInt32 + 1,
	})
	require.ErrorIs(t, err, db.ErrCastingOverflow)
}
