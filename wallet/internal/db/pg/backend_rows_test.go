package pg

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	_ sqlc.DBTX = (*mockDBTX)(nil)
	_ pgx.Row   = (*mockRow)(nil)
	_ pgx.Rows  = (*mockRows)(nil)
)

// mockDBTX forwards pgx-native sqlc DBTX calls to mock.Mock expectations.
type mockDBTX struct {
	mock.Mock
}

// Exec implements the sqlc DBTX interface.
func (m *mockDBTX) Exec(ctx context.Context, query string,
	queryArgs ...any) (pgconn.CommandTag, error) {

	args := m.Called(ctx, query, queryArgs)
	tag, _ := args.Get(0).(pgconn.CommandTag)

	return tag, args.Error(1)
}

// Query implements the sqlc DBTX interface.
func (m *mockDBTX) Query(ctx context.Context, query string,
	queryArgs ...any) (pgx.Rows, error) {

	args := m.Called(ctx, query, queryArgs)
	rows, _ := args.Get(0).(pgx.Rows)

	return rows, args.Error(1)
}

// QueryRow implements the sqlc DBTX interface.
func (m *mockDBTX) QueryRow(ctx context.Context, query string,
	queryArgs ...any) pgx.Row {

	args := m.Called(ctx, query, queryArgs)
	row, _ := args.Get(0).(pgx.Row)

	return row
}

// mockRow forwards pgx.Row calls to mock.Mock expectations.
type mockRow struct {
	mock.Mock
}

// Scan implements pgx.Row.
func (m *mockRow) Scan(dest ...any) error {
	args := m.Called(dest)

	return args.Error(0)
}

// mockRows forwards pgx.Rows calls to mock.Mock expectations.
type mockRows struct {
	mock.Mock
}

// Close implements pgx.Rows.
func (m *mockRows) Close() {
	m.Called()
}

// Err implements pgx.Rows.
func (m *mockRows) Err() error {
	args := m.Called()

	return args.Error(0)
}

// CommandTag implements pgx.Rows.
func (m *mockRows) CommandTag() pgconn.CommandTag {
	args := m.Called()
	tag, _ := args.Get(0).(pgconn.CommandTag)

	return tag
}

// FieldDescriptions implements pgx.Rows.
func (m *mockRows) FieldDescriptions() []pgconn.FieldDescription {
	args := m.Called()
	descriptions, _ := args.Get(0).([]pgconn.FieldDescription)

	return descriptions
}

// Next implements pgx.Rows.
func (m *mockRows) Next() bool {
	args := m.Called()

	return args.Bool(0)
}

// Scan implements pgx.Rows.
func (m *mockRows) Scan(dest ...any) error {
	args := m.Called(dest)

	return args.Error(0)
}

// Values implements pgx.Rows.
func (m *mockRows) Values() ([]any, error) {
	args := m.Called()
	values, _ := args.Get(0).([]any)

	return values, args.Error(1)
}

// RawValues implements pgx.Rows.
func (m *mockRows) RawValues() [][]byte {
	args := m.Called()
	values, _ := args.Get(0).([][]byte)

	return values
}

// Conn implements pgx.Rows.
func (m *mockRows) Conn() *pgx.Conn {
	args := m.Called()
	conn, _ := args.Get(0).(*pgx.Conn)

	return conn
}

// scanValues copies fixed row values into sqlc scan destinations.
func scanValues(values []any, dest []any) error {
	if len(values) != len(dest) {
		return fmt.Errorf("scan values: got %d values for %d destinations",
			len(values), len(dest))
	}

	for i := range values {
		target := reflect.ValueOf(dest[i])
		if target.Kind() != reflect.Pointer || target.IsNil() {
			return fmt.Errorf("scan destination %d is not a pointer", i)
		}

		source := reflect.ValueOf(values[i])
		if !source.IsValid() {
			target.Elem().SetZero()
			continue
		}

		if source.Type().AssignableTo(target.Elem().Type()) {
			target.Elem().Set(source)
			continue
		}

		// Match native pgx's standard Scanner support for overridden SQL
		// nullable values while leaving fixture data at the callsite.
		if scanner, ok := dest[i].(sql.Scanner); ok {
			err := scanner.Scan(values[i])
			if err != nil {
				return fmt.Errorf("scan value %d: %w", i, err)
			}

			continue
		}

		if source.Type().ConvertibleTo(target.Elem().Type()) {
			target.Elem().Set(source.Convert(target.Elem().Type()))
			continue
		}

		return fmt.Errorf("scan value %d: cannot assign %T to %T", i,
			values[i], dest[i])
	}

	return nil
}

// TestPgCreateTxOpsAdditionalBranches covers remaining postgres CreateTx helper
// branches that are hard to reach through public integration tests alone.
func TestPgCreateTxOpsAdditionalBranches(t *testing.T) {
	t.Parallel()

	// Arrange: Fail the metadata row scan to exercise LoadExisting's query
	// error wrapper before it can build an existing transaction target.
	req := testCreateTxRequest(t)
	ctx := context.Background()
	loadRow := &mockRow{}
	loadRow.On("Scan", mock.Anything).Return(errDummy).Once()

	loadDB := &mockDBTX{}
	loadDB.On(
		"QueryRow", mock.Anything, mock.Anything, mock.Anything,
	).Return(loadRow).Once()
	loadOps := &createTxOps{
		invalidateUnminedTxOps: invalidateUnminedTxOps{
			qtx: sqlc.New(loadDB),
		},
	}

	// Act: Load the transaction metadata through the generated native query.
	_, err := loadOps.LoadExisting(ctx, req)

	// Assert: The adapter identifies the failed metadata lookup and performs
	// exactly one query and one scan.
	require.ErrorContains(t, err, "get tx metadata")
	loadRow.AssertExpectations(t)
	loadDB.AssertExpectations(t)

	// Arrange: Supply matching block metadata, then report no transaction row
	// updated so confirmation must identify the missing transaction.
	block := &db.Block{
		Hash:      chainhash.Hash{3},
		Height:    7,
		Timestamp: time.Unix(77, 0),
	}
	confirmRow := &mockRow{}
	confirmRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		dest, ok := args.Get(0).([]any)
		require.True(t, ok)
		require.NoError(t, scanValues([]any{
			int32(block.Height), block.Hash[:], block.Timestamp.Unix(),
		}, dest))
	}).Return(nil).Once()

	confirmDB := &mockDBTX{}
	confirmDB.On(
		"QueryRow", mock.Anything, mock.Anything, mock.Anything,
	).Return(confirmRow).Once()
	confirmDB.On(
		"Exec", mock.Anything, mock.Anything, mock.Anything,
	).Return(pgconn.NewCommandTag("UPDATE 0"), nil).Once()
	confirmOps := &createTxOps{
		invalidateUnminedTxOps: invalidateUnminedTxOps{
			qtx: sqlc.New(confirmDB),
		},
	}

	// Act: Confirm the transaction against the stored block with UPDATE 0.
	err = confirmOps.ConfirmExisting(ctx, db.CreateTxRequest{
		Params: db.CreateTxParams{WalletID: 1, Block: block},
		TxHash: chainhash.Hash{9},
	}, db.CreateTxExistingTarget{})

	// Assert: A successful statement that updates no row returns the Store's
	// missing-transaction sentinel, after the matching block was inspected.
	require.ErrorIs(t, err, db.ErrTxNotFound)
	confirmRow.AssertExpectations(t)
	confirmDB.AssertExpectations(t)

	// Arrange: Resolve the wallet's input, then fail the unmined conflict query
	// to exercise the later lookup's contextual error path.
	conflictRow := &mockRow{}
	conflictRow.On("Scan", mock.Anything).Run(func(args mock.Arguments) {
		dest, ok := args.Get(0).([]any)
		require.True(t, ok)
		require.NoError(
			t, scanValues([]any{int64(5), []byte{1}}, dest),
		)
	}).Return(nil).Once()

	conflictDB := &mockDBTX{}
	conflictDB.On(
		"QueryRow", mock.Anything, mock.Anything, mock.Anything,
	).Return(conflictRow).Once()
	conflictDB.On(
		"Query", mock.Anything, mock.Anything, mock.Anything,
	).Return(nil, errDummy).Once()
	conflictOps := &createTxOps{
		invalidateUnminedTxOps: invalidateUnminedTxOps{
			qtx: sqlc.New(conflictDB),
		},
	}

	// Act: List conflicts after the input lookup succeeds.
	_, _, err = conflictOps.ListConflictTxns(ctx, req)

	// Assert: The failure identifies the unmined lookup rather than the
	// successful input scan, and neither query is retried.
	require.ErrorContains(t, err, "list unmined txns")
	conflictRow.AssertExpectations(t)
	conflictDB.AssertExpectations(t)
}

// TestPgUpdateTxOpsAdditionalBranches covers the remaining postgres UpdateTx
// helper branches that are hard to reach through public integration tests
// alone.
func TestPgUpdateTxOpsAdditionalBranches(t *testing.T) {
	t.Parallel()

	// Arrange: Fail the coinbase metadata scan and make both state and label
	// updates affect zero rows, covering their distinct missing-row paths.
	ctx := context.Background()
	txHash := chainhash.Hash{9}
	loadRow := &mockRow{}
	loadRow.On("Scan", mock.Anything).Return(errDummy).Once()

	loadDB := &mockDBTX{}
	loadDB.On(
		"QueryRow", mock.Anything, mock.Anything, mock.Anything,
	).Return(loadRow).Once()
	loadOps := &updateTxOps{qtx: sqlc.New(loadDB)}

	stateDB := &mockDBTX{}
	stateDB.On(
		"Exec", mock.Anything, mock.Anything, mock.Anything,
	).Return(pgconn.NewCommandTag("UPDATE 0"), nil).Once()
	stateOps := &updateTxOps{
		qtx:         sqlc.New(stateDB),
		blockHeight: sql.NullInt32{},
		status:      int16(db.TxStatusPublished),
	}

	labelDB := &mockDBTX{}
	labelDB.On(
		"Exec", mock.Anything, mock.Anything, mock.Anything,
	).Return(pgconn.NewCommandTag("UPDATE 0"), nil).Once()
	labelOps := &updateTxOps{qtx: sqlc.New(labelDB)}

	// Act: Load coinbase metadata through the failing native row scan.
	_, err := loadOps.LoadIsCoinbase(ctx, 1, txHash)

	// Assert: The adapter identifies the metadata lookup failure.
	require.ErrorContains(t, err, "get tx metadata")
	loadRow.AssertExpectations(t)
	loadDB.AssertExpectations(t)

	// Act: Update the transaction state with a statement affecting no row.
	err = stateOps.UpdateState(ctx, 1, txHash, db.UpdateTxState{
		Status: db.TxStatusPublished,
	})

	// Assert: No updated state row maps to the missing-transaction sentinel.
	require.ErrorIs(t, err, db.ErrTxNotFound)
	stateDB.AssertExpectations(t)

	// Act: Update the label through its separate zero-row statement.
	err = labelOps.UpdateLabel(ctx, 1, txHash, "note")

	// Assert: The label adapter preserves the same missing-row contract.
	require.ErrorIs(t, err, db.ErrTxNotFound)
	labelDB.AssertExpectations(t)
}
