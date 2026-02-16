package db

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewPostgresStoreValidateConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     PostgresConfig
		wantErr error
	}{
		{
			name: "empty DSN",
			cfg: PostgresConfig{
				Dsn: "",
			},
			wantErr: ErrEmptyDSN,
		},
		{
			name: "negative max connections",
			cfg: PostgresConfig{
				Dsn:            "postgres://test",
				MaxConnections: -1,
			},
			wantErr: ErrNegativeMaxConns,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store, err := NewPostgresStore(t.Context(), tc.cfg)
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, store)
		})
	}
}

func TestNewPostgresStoreConnectionFailure(t *testing.T) {
	t.Parallel()

	// Valid config, but hits a connection failure.
	cfg := PostgresConfig{
		Dsn: "postgres://localhost:1/testdb",
	}

	store, err := NewPostgresStore(t.Context(), cfg)
	require.Error(t, err)
	require.ErrorContains(t, err, "ping database")
	require.NotErrorIs(t, err, ErrEmptyDSN)
	require.NotErrorIs(t, err, ErrNegativeMaxConns)

	// We are asserting nil here because it's not an integration test, so we
	// are not able to create a postgres database and connect to it.
	require.Nil(t, store)
}

func TestNewSqliteStoreValidateConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     SqliteConfig
		wantErr error
	}{
		{
			name: "empty DB path",
			cfg: SqliteConfig{
				DBPath: "",
			},
			wantErr: ErrEmptyDBPath,
		},
		{
			name: "negative max connections",
			cfg: SqliteConfig{
				DBPath:         "/tmp/test.db",
				MaxConnections: -1,
			},
			wantErr: ErrNegativeMaxConns,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store, err := NewSqliteStore(t.Context(), tc.cfg)
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, store)
		})
	}
}

func TestNewSqliteStoreSuccess(t *testing.T) {
	t.Parallel()

	cfg := SqliteConfig{
		DBPath: filepath.Join(t.TempDir(), "wallet.db"),
	}

	store, err := NewSqliteStore(t.Context(), cfg)
	require.NoError(t, err)
	require.NotNil(t, store)

	require.NoError(t, store.Close())
}
