package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
	"github.com/stretchr/testify/mock"
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

// mockUpdateWalletSQL drives the public Store through a real sql.Tx, so the
// backend commit classifier cannot be bypassed by an injected ambiguity flag.
type mockUpdateWalletSQL struct {
	mock.Mock
}

var (
	_ driver.Connector     = (*mockUpdateWalletSQL)(nil)
	_ driver.Conn          = (*mockUpdateWalletSQL)(nil)
	_ driver.ConnBeginTx   = (*mockUpdateWalletSQL)(nil)
	_ driver.ExecerContext = (*mockUpdateWalletSQL)(nil)
	_ driver.Tx            = (*mockUpdateWalletSQL)(nil)
)

// Connect supplies the configured connection without global driver
// registration.
func (m *mockUpdateWalletSQL) Connect(
	ctx context.Context) (driver.Conn, error) {

	args := m.Called(ctx)
	conn, _ := args.Get(0).(driver.Conn)

	return conn, args.Error(1)
}

// Driver exposes the connector's driver if database/sql requests it.
func (m *mockUpdateWalletSQL) Driver() driver.Driver {
	args := m.Called()
	drv, _ := args.Get(0).(driver.Driver)

	return drv
}

// Prepare records any unexpected fallback from the context-aware execution
// path.
func (m *mockUpdateWalletSQL) Prepare(query string) (driver.Stmt, error) {
	args := m.Called(query)
	stmt, _ := args.Get(0).(driver.Stmt)

	return stmt, args.Error(1)
}

// Close records the separate connection and connector cleanup owned by sql.DB.
func (m *mockUpdateWalletSQL) Close() error {
	args := m.Called()

	return args.Error(0)
}

// Begin records an unexpected fallback from BeginTx.
func (m *mockUpdateWalletSQL) Begin() (driver.Tx, error) {
	args := m.Called()
	tx, _ := args.Get(0).(driver.Tx)

	return tx, args.Error(1)
}

// BeginTx supplies the configured transaction to the production SQL runtime.
func (m *mockUpdateWalletSQL) BeginTx(ctx context.Context,
	opts driver.TxOptions) (driver.Tx, error) {

	args := m.Called(ctx, opts)
	tx, _ := args.Get(0).(driver.Tx)

	return tx, args.Error(1)
}

// ExecContext supplies a successful write so the test isolates the following
// commit outcome rather than generated query details.
func (m *mockUpdateWalletSQL) ExecContext(ctx context.Context, query string,
	queryArgs []driver.NamedValue) (driver.Result, error) {

	args := m.Called(ctx, query, queryArgs)
	result, _ := args.Get(0).(driver.Result)

	return result, args.Error(1)
}

// Commit returns the driver failure whose ambiguity the Store must classify.
func (m *mockUpdateWalletSQL) Commit() error {
	args := m.Called()

	return args.Error(0)
}

// Rollback records any unexpected driver rollback after sql.Tx has completed.
func (m *mockUpdateWalletSQL) Rollback() error {
	args := m.Called()

	return args.Error(0)
}

// TestUpdateWalletCommitOutcome retains SQLite's public commit-error contract
// after transport classification moves out of the shared transaction runtime.
func TestUpdateWalletCommitOutcome(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		commitErr error
		ambiguous bool
	}{
		{
			name:      "lost commit reply",
			commitErr: io.EOF,
			ambiguous: true,
		},
		{
			name:      "definite commit failure",
			commitErr: errors.New("commit rejected"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Open a mock.Mock connector through database/sql and
			// require one real transaction containing the generated update.
			// Only Commit varies, so both paths prove the same Store wiring.
			driverMock := &mockUpdateWalletSQL{}
			driverMock.Test(t)
			sqlDB := sql.OpenDB(driverMock)
			store := &Store{db: sqlDB, queries: sqlc.New(sqlDB)}

			driverMock.On(
				"Connect", mock.Anything,
			).Return(driverMock, nil).Once()
			driverMock.On("BeginTx", mock.Anything, driver.TxOptions{}).
				Return(driverMock, nil).Once()
			driverMock.On(
				"ExecContext", mock.Anything, mock.Anything, mock.Anything,
			).Return(driver.RowsAffected(1), nil).Once()
			driverMock.On("Commit").Return(test.commitErr).Once()
			// The shared mock is both an io.Closer connector and a connection;
			// database/sql closes each resource once.
			driverMock.On("Close").Return(nil).Twice()
			t.Cleanup(func() {
				require.NoError(t, store.Close())
				driverMock.AssertExpectations(t)
			})

			// Act: Call the public update with no optional block mutations; the
			// generated update succeeds and the driver fails at Commit.
			err := store.UpdateWallet(t.Context(), db.UpdateWalletParams{
				WalletID: 7,
			})

			// Assert: Both errors retain their cause, but only transport loss
			// gains the ambiguity identity and exactly one ambiguity count.
			// Cleanup verifies the sole write and every driver call once.
			require.ErrorIs(t, err, test.commitErr)
			require.Equal(t, test.ambiguous, errors.Is(
				err, dbruntime.ErrAmbiguousTxCommit,
			))

			wantCount := uint64(0)
			if test.ambiguous {
				wantCount = 1
			}

			require.Equal(
				t, wantCount, store.StatsSnapshot().AmbiguousTxCommits,
			)
		})
	}
}
