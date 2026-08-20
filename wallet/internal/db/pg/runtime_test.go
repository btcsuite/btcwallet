package pg

import (
	"context"
	"io"
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/mock"
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
		pgx.ErrTxClosed,
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

// TestRollbackTxUsesFreshContext verifies that PostgreSQL rollback cleanup is
// bounded independently of the caller's context.
func TestRollbackTxUsesFreshContext(t *testing.T) {
	t.Parallel()

	callerCtx, cancelCaller := context.WithCancel(context.Background())
	cancelCaller()
	require.ErrorIs(t, callerCtx.Err(), context.Canceled)

	var (
		cleanupErr  error
		deadline    time.Time
		hasDeadline bool
	)

	err := rollbackTx(func(ctx context.Context) error {
		cleanupErr = ctx.Err()
		deadline, hasDeadline = ctx.Deadline()

		return nil
	})
	require.NoError(t, err)
	require.NoError(t, cleanupErr)
	require.True(t, hasDeadline)
	require.WithinDuration(
		t, time.Now().Add(db.DefaultConnectionTimeout), deadline,
		time.Second,
	)
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
	rows := &mockRows{}
	rows.On("Next").Return(true).Once()
	rows.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		dest, ok := args.Get(0).([]any)
		require.True(t, ok)
		require.NoError(t, scanValues([]any{
			int32(144), blockHash[:], timestamp.Unix(),
		}, dest))
	}).Return(nil).Once()
	rows.On("Next").Return(false).Once()
	rows.On("Err").Return(nil).Once()
	rows.On("Close").Return().Once()

	queryDB := &mockDBTX{}
	queryDB.On(
		"Query", mock.Anything, mock.Anything, mock.Anything,
	).Return(rows, nil).Once()

	store := &Store{
		queries: sqlc.New(queryDB),
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
	rows.AssertExpectations(t)
	queryDB.AssertExpectations(t)
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
	row := &mockRow{}
	row.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		dest, ok := args.Get(0).([]any)
		require.True(t, ok)
		require.NoError(t, scanValues([]any{
			int32(block.Height), conflictingHash[:],
			block.Timestamp.Unix(),
		}, dest))
	}).Return(nil).Once()

	dbtx := &mockDBTX{}
	dbtx.On(
		"Exec", mock.Anything, mock.Anything, mock.Anything,
	).Return(pgconn.NewCommandTag("INSERT 0 0"), nil).Once()
	dbtx.On(
		"QueryRow", mock.Anything, mock.Anything, mock.Anything,
	).Return(row).Once()
	qtx := sqlc.New(dbtx)

	err := ensureBlockExists(t.Context(), qtx, block)
	require.ErrorIs(t, err, db.ErrBlockMismatch)
	row.AssertExpectations(t)
	dbtx.AssertExpectations(t)
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
