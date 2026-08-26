package pg

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockWalletSecretsSQL drives Store through its production database/sql path
// while retaining strict mock.Mock call expectations.
type mockWalletSecretsSQL struct {
	mock.Mock
}

// Compile-time assertions cover every database/sql driver seam used here.
var (
	_ driver.Driver         = (*mockWalletSecretsSQL)(nil)
	_ driver.Conn           = (*mockWalletSecretsSQL)(nil)
	_ driver.ConnBeginTx    = (*mockWalletSecretsSQL)(nil)
	_ driver.ExecerContext  = (*mockWalletSecretsSQL)(nil)
	_ driver.QueryerContext = (*mockWalletSecretsSQL)(nil)
	_ driver.Tx             = (*mockWalletSecretsSQL)(nil)
)

// Open returns the one connection registered for this isolated test.
func (m *mockWalletSecretsSQL) Open(name string) (driver.Conn, error) {
	args := m.Called(name)
	conn, _ := args.Get(0).(driver.Conn)

	return conn, args.Error(1)
}

// Prepare rejects unused statements so tests cannot bypass context
// expectations.
func (m *mockWalletSecretsSQL) Prepare(query string) (driver.Stmt, error) {
	args := m.Called(query)
	stmt, _ := args.Get(0).(driver.Stmt)

	return stmt, args.Error(1)
}

// Close succeeds because database/sql owns the mock connection lifecycle.
func (m *mockWalletSecretsSQL) Close() error {
	args := m.Called()

	return args.Error(0)
}

// Begin supplies the legacy interface; database/sql selects BeginTx instead.
func (m *mockWalletSecretsSQL) Begin() (driver.Tx, error) {
	args := m.Called()
	tx, _ := args.Get(0).(driver.Tx)

	return tx, args.Error(1)
}

// BeginTx records the sole transaction and returns this mock for Commit.
func (m *mockWalletSecretsSQL) BeginTx(ctx context.Context,
	opts driver.TxOptions) (driver.Tx, error) {

	args := m.Called(ctx, opts)
	tx, _ := args.Get(0).(driver.Tx)

	return tx, args.Error(1)
}

// ExecContext records the generated update through the real SQL transaction.
func (m *mockWalletSecretsSQL) ExecContext(ctx context.Context, query string,
	args []driver.NamedValue) (driver.Result, error) {

	result := m.Called(ctx, query, args)
	rows, _ := result.Get(0).(driver.Result)

	return rows, result.Error(1)
}

// QueryContext records either the wallet lookup or verification read.
func (m *mockWalletSecretsSQL) QueryContext(ctx context.Context, query string,
	args []driver.NamedValue) (driver.Rows, error) {

	result := m.Called(ctx, query, args)
	rows, _ := result.Get(0).(driver.Rows)

	return rows, result.Error(1)
}

// Commit exposes its configured result to the shared runtime classifier.
func (m *mockWalletSecretsSQL) Commit() error {
	args := m.Called()

	return args.Error(0)
}

// Rollback permits defensive cleanup without another behavioral expectation.
func (m *mockWalletSecretsSQL) Rollback() error {
	args := m.Called()

	return args.Error(0)
}

// mockWalletSecretsRows supplies one generated-query row and then EOF.
type mockWalletSecretsRows struct {
	mock.Mock
}

// Columns returns the scanner shape associated with the configured SQL query.
func (r *mockWalletSecretsRows) Columns() []string {
	args := r.Called()
	columns, _ := args.Get(0).([]string)

	return columns
}

// Close succeeds because the single in-memory row owns no external resource.
func (r *mockWalletSecretsRows) Close() error {
	args := r.Called()

	return args.Error(0)
}

// Next copies the configured row once and then reports EOF.
func (r *mockWalletSecretsRows) Next(dest []driver.Value) error {
	args := r.Called(dest)

	return args.Error(0)
}

// testWalletSecretsUpdate builds distinct field values so mismatch tests prove
// that every credential fact participates in exact commit verification.
func testWalletSecretsUpdate() db.UpdateWalletSecretsParams {
	return db.UpdateWalletSecretsParams{
		WalletID:                 7,
		MasterPrivParams:         []byte{1, 2},
		EncryptedCryptoPrivKey:   []byte{3, 4},
		EncryptedCryptoScriptKey: []byte{5, 6},
		EncryptedMasterHdPrivKey: []byte{7, 8},
	}
}

// walletSecretsDriverSeq keeps database/sql registration names unique across
// parallel subtests and repeated -count runs because drivers cannot be removed.
var walletSecretsDriverSeq atomic.Uint64

// newMockWalletSecretsStore binds both Store SQL paths to one test driver.
func newMockWalletSecretsStore(t *testing.T) (*Store, *mockWalletSecretsSQL) {
	t.Helper()

	sqlMock := &mockWalletSecretsSQL{}
	driverName := fmt.Sprintf(
		"wallet-secrets-%s-%d", t.Name(), walletSecretsDriverSeq.Add(1),
	)
	sql.Register(driverName, sqlMock)

	dbConn, err := sql.Open(driverName, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, dbConn.Close())
	})

	return &Store{
		db:      dbConn,
		queries: sqlc.New(dbConn),
	}, sqlMock
}

// newMockWalletSecretsRows configures one scanner row entirely through
// mock.Mock so its lifecycle and returned values remain explicit expectations.
func newMockWalletSecretsRows(t *testing.T,
	values []driver.Value) *mockWalletSecretsRows {

	t.Helper()

	rows := &mockWalletSecretsRows{}
	rows.On("Columns").Return(make([]string, len(values))).Once()
	rows.On("Next", mock.Anything).Run(func(args mock.Arguments) {
		// Populate database/sql's destination inside the declared mock action
		// so the mock remains the sole authority for scanner behavior.
		dest, ok := args.Get(0).([]driver.Value)
		require.True(t, ok)
		copy(dest, values)
	}).Return(nil).Once()
	rows.On("Close").Return(nil).Once()

	return rows
}

// testWalletRow returns one non-watch-only generated-query row.
func testWalletRow(t *testing.T, walletID uint32) *mockWalletSecretsRows {
	t.Helper()

	return newMockWalletSecretsRows(t, []driver.Value{
		int64(walletID), "wallet", false, int64(1), false, []byte{1},
		nil, nil, nil, nil, nil, nil, nil, nil,
	})
}

// testWalletSecretsRow returns the exact persisted scanner tuple.
func testWalletSecretsRow(t *testing.T,
	params db.UpdateWalletSecretsParams) *mockWalletSecretsRows {

	t.Helper()

	return newMockWalletSecretsRows(t, []driver.Value{
		int64(params.WalletID), params.MasterPrivParams,
		params.EncryptedCryptoPrivKey,
		params.EncryptedCryptoScriptKey,
		params.EncryptedMasterHdPrivKey,
	})
}

// TestStoreUpdateWalletSecretsBypassesRead verifies the public Store method
// performs one authoritative transaction and no verification read for ordinary
// binary results.
func TestStoreUpdateWalletSecretsBypassesRead(t *testing.T) {
	t.Parallel()

	errDefinite := errors.New("definite commit failure")
	tests := []struct {
		name      string
		commitErr error
	}{
		{name: "successful commit"},
		{name: "definite commit failure", commitErr: errDefinite},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Bind the public Store to a mock.Mock-backed SQL driver.
			// Every required connection, transaction, query, row, and cleanup
			// call is declared once; no secret-read expectation is present, so
			// verification would fail immediately as an unexpected call.
			params := testWalletSecretsUpdate()
			store, sqlMock := newMockWalletSecretsStore(t)
			walletRow := testWalletRow(t, params.WalletID)

			sqlMock.On("Open", "").Return(sqlMock, nil).Once()
			sqlMock.On(
				"BeginTx", mock.Anything, driver.TxOptions{},
			).Return(sqlMock, nil).Once()
			sqlMock.On(
				"QueryContext", mock.Anything, sqlc.GetWalletByID,
				[]driver.NamedValue{{
					Ordinal: 1, Value: int64(params.WalletID),
				}},
			).Return(walletRow, nil).Once()
			sqlMock.On(
				"ExecContext", mock.Anything, sqlc.UpdateWalletSecrets,
				[]driver.NamedValue{
					{Ordinal: 1, Value: params.MasterPrivParams},
					{Ordinal: 2, Value: params.EncryptedCryptoPrivKey},
					{Ordinal: 3, Value: params.EncryptedCryptoScriptKey},
					{Ordinal: 4, Value: params.EncryptedMasterHdPrivKey},
					{Ordinal: 5, Value: int64(params.WalletID)},
				},
			).Return(driver.RowsAffected(1), nil).Once()
			sqlMock.On("Commit").Return(test.commitErr).Once()
			sqlMock.On("Close").Return(nil).Once()

			// Act: Call the public API so transaction construction, generated
			// queries, runtime commit classification, and result policy all run
			// through their production authorities.
			err := store.UpdateWalletSecrets(t.Context(), params)

			// Assert: A successful commit remains success and a definite
			// commit failure remains an error. Closing the Store completes its
			// lifecycle; the two direct expectation checks then prove every SQL
			// and row call occurred exactly once with no retry or extra read.
			if test.commitErr == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, test.commitErr)
			}

			require.NoError(t, store.Close())
			sqlMock.AssertExpectations(t)
			walletRow.AssertExpectations(t)
		})
	}
}
