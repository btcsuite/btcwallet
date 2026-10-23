package pg

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
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

// TestExecWriteErrors checks that SQL errors keep their code, class, and cause.
// It checks that cancellation reaches the caller. Each callback runs once.
func TestExecWriteErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		cause  error
		code   string
		reason dberr.Reason
	}{
		{
			name:   "serialization failure",
			cause:  &pgconn.PgError{Code: codeSerializationFailure},
			code:   codeSerializationFailure,
			reason: dberr.ReasonSerialization,
		},
		{
			name:  "callback cancellation",
			cause: fmt.Errorf("callback canceled: %w", context.Canceled),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Configure the SQL mock for one read committed
			// transaction. Expect one rollback. A commit or a second begin
			// must fail the test.
			ctx := t.Context()
			store, sqlMock := newMockWalletSecretsStore(t)
			sqlMock.On("Open", "").Return(sqlMock, nil).Once()
			sqlMock.On("BeginTx", ctx, driver.TxOptions{
				Isolation: driver.IsolationLevel(sql.LevelReadCommitted),
			}).Return(sqlMock, nil).Once()
			sqlMock.On("Rollback").Return(nil).Once()
			sqlMock.On("Close").Return(nil).Once()

			calls := 0

			// Act: Return the test error from execWrite's callback. Count
			// each call to detect a retry that the SQL mock does not observe.
			err := store.execWrite(ctx, func(*sqlc.Queries) error {
				calls++

				return test.cause
			})

			// Assert: Check the original cause and one callback call. SQL
			// errors must keep their code, reason, and class. Cancellation
			// must remain a context error.
			require.ErrorIs(t, err, test.cause)
			require.Equal(t, 1, calls)

			var sqlErr *dberr.SQLError
			if test.code == "" {
				require.ErrorIs(t, err, context.Canceled)
				require.NotErrorAs(t, err, &sqlErr)
			} else {
				require.ErrorAs(t, err, &sqlErr)
				require.Equal(t, test.code, sqlErr.Code)
				require.Equal(t, test.reason, sqlErr.Reason)
				require.Equal(t, dberr.ClassTransient, sqlErr.Class())
			}

			require.NoError(t, store.Close())
			sqlMock.AssertExpectations(t)
		})
	}
}

// TestExecWriteCanceledContext checks that a canceled context stops the write
// before the runtime opens a connection or calls the callback.
func TestExecWriteCanceledContext(t *testing.T) {
	t.Parallel()

	// Arrange: Cancel the context before the SQL pool gets a connection.
	// Give the strict mock no expected calls so any driver call fails the test.
	store, sqlMock := newMockWalletSecretsStore(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	called := false

	// Act: Request a Store write. Record whether the runtime calls the
	// callback.
	err := store.execWrite(ctx, func(*sqlc.Queries) error {
		called = true

		return nil
	})

	// Assert: Check the context error and the absence of a callback call.
	// Check the mock expectations to detect any driver call.
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, called)
	require.NoError(t, store.Close())
	sqlMock.AssertExpectations(t)
}

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
