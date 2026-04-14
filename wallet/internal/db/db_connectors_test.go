package db_test

import (
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/pg"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	"github.com/stretchr/testify/require"
)

func TestPostgresNewStoreValidateConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     pg.Config
		wantErr error
	}{
		{
			name: "empty DSN",
			cfg: pg.Config{
				Dsn: "",
			},
			wantErr: db.ErrEmptyDSN,
		},
		{
			name: "negative max connections",
			cfg: pg.Config{
				Dsn:            "postgres://test",
				MaxConnections: -1,
			},
			wantErr: db.ErrNegativeMaxConns,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store, err := pg.NewStore(t.Context(), tc.cfg)
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, store)
		})
	}
}

func TestPostgresNewStoreConnectionFailure(t *testing.T) {
	t.Parallel()

	// Valid config, but hits a connection failure.
	cfg := pg.Config{
		Dsn: "postgres://localhost:1/testdb",
	}

	store, err := pg.NewStore(t.Context(), cfg)
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
		cfg     sqlite.Config
		wantErr error
	}{
		{
			name: "empty DB path",
			cfg: sqlite.Config{
				DBPath: "",
			},
			wantErr: db.ErrEmptyDBPath,
		},
		{
			name: "negative max connections",
			cfg: sqlite.Config{
				DBPath:         "/tmp/test.db",
				MaxConnections: -1,
			},
			wantErr: db.ErrNegativeMaxConns,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store, err := sqlite.NewStore(t.Context(), tc.cfg)
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, store)
		})
	}
}

func TestSQLiteNewStoreSuccess(t *testing.T) {
	t.Parallel()

	cfg := sqlite.Config{
		DBPath: filepath.Join(t.TempDir(), "wallet.db"),
	}

	store, err := sqlite.NewStore(t.Context(), cfg)
	require.NoError(t, err)
	require.NotNil(t, store)

	require.NoError(t, store.Close())
}
