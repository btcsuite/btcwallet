package pg

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
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
		handled, err := scanPGType(values[i], dest[i])
		if err != nil {
			return fmt.Errorf("scan value %d: %w", i, err)
		}

		if handled {
			continue
		}

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

		if source.Type().ConvertibleTo(target.Elem().Type()) {
			target.Elem().Set(source.Convert(target.Elem().Type()))
			continue
		}

		return fmt.Errorf("scan value %d: cannot assign %T to %T", i,
			values[i], dest[i])
	}

	return nil
}

// scanPGType copies one integer fixture into a nullable pgx destination.
func scanPGType(value any, dest any) (bool, error) {
	integer, ok := integerValue(value)

	switch target := dest.(type) {
	case *pgtype.Int8:
		if !ok {
			return true, fmt.Errorf("cannot assign %T to %T", value, dest)
		}

		*target = pgtype.Int8{Int64: integer, Valid: true}

		return true, nil

	case *pgtype.Int4:
		if !ok {
			return true, fmt.Errorf("cannot assign %T to %T", value, dest)
		}

		*target = pgtype.Int4{Int32: int32(integer), Valid: true}

		return true, nil

	default:
		return false, nil
	}
}

// integerValue converts the integer fixture types used by backend tests.
func integerValue(value any) (int64, bool) {
	source := reflect.ValueOf(value)
	if !source.IsValid() {
		return 0, false
	}

	target := reflect.TypeFor[int64]()
	if !source.Type().ConvertibleTo(target) {
		return 0, false
	}

	return source.Convert(target).Int(), true
}

// TestPgCreateTxOpsAdditionalBranches covers remaining postgres CreateTx helper
// branches that are hard to reach through public integration tests alone.
func TestPgCreateTxOpsAdditionalBranches(t *testing.T) {
	t.Parallel()

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

	_, err := loadOps.LoadExisting(ctx, req)
	require.ErrorContains(t, err, "get tx metadata")
	loadRow.AssertExpectations(t)
	loadDB.AssertExpectations(t)

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
	err = confirmOps.ConfirmExisting(ctx, db.CreateTxRequest{
		Params: db.CreateTxParams{WalletID: 1, Block: block},
		TxHash: chainhash.Hash{9},
	}, db.CreateTxExistingTarget{})
	require.ErrorIs(t, err, db.ErrTxNotFound)
	confirmRow.AssertExpectations(t)
	confirmDB.AssertExpectations(t)

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
	_, _, err = conflictOps.ListConflictTxns(ctx, req)
	require.ErrorContains(t, err, "list unmined txns")
	conflictRow.AssertExpectations(t)
	conflictDB.AssertExpectations(t)
}

// TestPgUpdateTxOpsAdditionalBranches covers the remaining postgres UpdateTx
// helper branches that are hard to reach through public integration tests
// alone.
func TestPgUpdateTxOpsAdditionalBranches(t *testing.T) {
	t.Parallel()

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
		blockHeight: pgtype.Int4{},
		status:      int16(db.TxStatusPublished),
	}

	labelDB := &mockDBTX{}
	labelDB.On(
		"Exec", mock.Anything, mock.Anything, mock.Anything,
	).Return(pgconn.NewCommandTag("UPDATE 0"), nil).Once()
	labelOps := &updateTxOps{qtx: sqlc.New(labelDB)}

	_, err := loadOps.LoadIsCoinbase(ctx, 1, txHash)
	require.ErrorContains(t, err, "get tx metadata")
	loadRow.AssertExpectations(t)
	loadDB.AssertExpectations(t)

	err = stateOps.UpdateState(ctx, 1, txHash, db.UpdateTxState{
		Status: db.TxStatusPublished,
	})
	require.ErrorIs(t, err, db.ErrTxNotFound)
	stateDB.AssertExpectations(t)

	err = labelOps.UpdateLabel(ctx, 1, txHash, "note")
	require.ErrorIs(t, err, db.ErrTxNotFound)
	labelDB.AssertExpectations(t)
}
