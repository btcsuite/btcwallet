package db_test

import (
	"path/filepath"
	"testing"

	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	dbpg "github.com/btcsuite/btcwallet/wallet/internal/db/pg"
	dbsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	"github.com/stretchr/testify/require"
)

func TestPostgresNewStoreValidateConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     dbpg.Config
		wantErr error
	}{
		{
			name: "empty DSN",
			cfg: dbpg.Config{
				Dsn: "",
			},
			wantErr: db.ErrEmptyDSN,
		},
		{
			name: "negative max connections",
			cfg: dbpg.Config{
				Dsn:            "postgres://test",
				MaxConnections: -1,
			},
			wantErr: db.ErrNegativeMaxConns,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store, err := dbpg.NewStore(t.Context(), tc.cfg)
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, store)
		})
	}
}

func TestPostgresNewStoreConnectionFailure(t *testing.T) {
	t.Parallel()

	// Valid config, but hits a connection failure.
	cfg := dbpg.Config{
		Dsn: "postgres://localhost:1/testdb",
	}

	store, err := dbpg.NewStore(t.Context(), cfg)
	require.Error(t, err)
	require.ErrorContains(t, err, "ping database")
	require.NotErrorIs(t, err, db.ErrEmptyDSN)
	require.NotErrorIs(t, err, db.ErrNegativeMaxConns)

	// We are asserting nil here because it's not an integration test, so we
	// are not able to create a postgres database and connect to it.
	require.Nil(t, store)
}

func TestSQLiteNewStoreValidateConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     dbsqlite.Config
		wantErr error
	}{
		{
			name: "empty DB path",
			cfg: dbsqlite.Config{
				DBPath: "",
			},
			wantErr: db.ErrEmptyDBPath,
		},
		{
			name: "negative max connections",
			cfg: dbsqlite.Config{
				DBPath:         "/tmp/test.db",
				MaxConnections: -1,
			},
			wantErr: db.ErrNegativeMaxConns,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store, err := dbsqlite.NewStore(t.Context(), tc.cfg)
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, store)
		})
	}
}

func TestSQLiteNewStoreSuccess(t *testing.T) {
	t.Parallel()

	cfg := dbsqlite.Config{
		DBPath: filepath.Join(t.TempDir(), "wallet.db"),
	}

	store, err := dbsqlite.NewStore(t.Context(), cfg)
	require.NoError(t, err)
	require.NotNil(t, store)

	require.NoError(t, store.Close())
}
