package db

import (
	"database/sql"
	"database/sql/driver"
	"sync"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const testDriverName = "wallet-test-driver"

var (
	registerDriverOnce sync.Once
	testDriver         *mockDriver
)

// newMockedTestDB returns a *sql.DB backed by a mock driver. It avoids any
// network or disk usage, so it works well for constructor tests that only
// need a non nil database handle. It should be used only in very simple
// scenarios, since it does not implement real behavior and cannot confirm
// that the issued queries works as expected.
func newMockedTestDB(t *testing.T) *sql.DB {
	t.Helper()

	registerDriverOnce.Do(func() {
		testDriver = &mockDriver{}
		testDriver.On("Open", mock.Anything).Return(mockConn{}, nil)

		sql.Register(testDriverName, testDriver)
	})

	db, err := sql.Open(testDriverName, "")
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = db.Close()
	})

	return db
}

// TestNewPostgresWalletDB checks that the PostgresWalletDB constructor
// properly guards against nil *sql.DB inputs and wires up the queries
// correctly.
func TestNewPostgresWalletDB(t *testing.T) {
	t.Parallel()

	t.Run("nil db", func(t *testing.T) {
		t.Parallel()

		db, err := NewPostgresWalletDB(nil)
		require.ErrorIs(t, err, ErrNilDB)
		require.Nil(t, db)
	})

	t.Run("valid db", func(t *testing.T) {
		t.Parallel()

		sqlDB := newMockedTestDB(t)

		db, err := NewPostgresWalletDB(sqlDB)
		require.NoError(t, err)
		require.NotNil(t, db)
		require.Equal(t, sqlDB, db.db)
		require.NotNil(t, db.queries)
	})
}

// TestNewSQLiteWalletDB checks that the SQLiteWalletDB constructor
// properly guards against nil *sql.DB inputs and wires up the queries
// correctly.
func TestNewSQLiteWalletDB(t *testing.T) {
	t.Parallel()

	t.Run("nil db", func(t *testing.T) {
		t.Parallel()

		db, err := NewSQLiteWalletDB(nil)
		require.ErrorIs(t, err, ErrNilDB)
		require.Nil(t, db)
	})

	t.Run("valid db", func(t *testing.T) {
		t.Parallel()

		sqlDB := newMockedTestDB(t)

		db, err := NewSQLiteWalletDB(sqlDB)
		require.NoError(t, err)
		require.NotNil(t, db)
		require.Equal(t, sqlDB, db.db)
		require.NotNil(t, db.queries)
	})
}

// mockDriver implements a bare-bones SQL driver so tests can obtain a *sql.DB
// without depending on an external database.
type mockDriver struct {
	mock.Mock
}

func (m *mockDriver) Open(name string) (driver.Conn, error) {
	args := m.Called(name)
	conn, _ := args.Get(0).(driver.Conn)

	return conn, args.Error(1)
}

// mockConn is a mock implementation of a database connection. It does not
// implement any real behavior. Used to be returned by the mockDriver.
type mockConn struct {
	mock.Mock
}
