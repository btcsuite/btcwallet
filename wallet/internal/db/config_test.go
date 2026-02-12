package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSqliteConfigValidateSuccess tests valid SqliteConfig scenarios.
func TestSqliteConfigValidateSuccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config SqliteConfig
	}{
		{
			name: "valid config with zero max connections",
			config: SqliteConfig{
				DBPath:         "/tmp/test.db",
				MaxConnections: 0,
			},
		},
		{
			name: "valid config with positive max connections",
			config: SqliteConfig{
				DBPath:         "/tmp/test.db",
				MaxConnections: 10,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.config.Validate()
			require.NoError(t, err)
		})
	}
}

// TestSqliteConfigValidateErrors tests SqliteConfig validation errors.
func TestSqliteConfigValidateErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      SqliteConfig
		expectedErr error
	}{
		{
			name: "empty DB path",
			config: SqliteConfig{
				DBPath:         "",
				MaxConnections: 0,
			},
			expectedErr: ErrEmptyDBPath,
		},
		{
			name: "negative max connections",
			config: SqliteConfig{
				DBPath:         "/tmp/test.db",
				MaxConnections: -1,
			},
			expectedErr: ErrNegativeMaxConns,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.config.Validate()
			require.ErrorIs(t, err, tc.expectedErr)
		})
	}
}

// TestPostgresConfigValidateSuccess tests valid PostgresConfig scenarios.
func TestPostgresConfigValidateSuccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config PostgresConfig
	}{
		{
			name: "valid config with all fields set",
			config: PostgresConfig{
				Dsn:            "postgres://user:pass@localhost/db",
				MaxConnections: 25,
			},
		},
		{
			name: "valid config with zero max connections",
			config: PostgresConfig{
				Dsn:            "postgres://localhost/db",
				MaxConnections: 0,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.config.Validate()
			require.NoError(t, err)
		})
	}
}

// TestPostgresConfigValidateErrors tests PostgresConfig validation errors.
func TestPostgresConfigValidateErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		config         PostgresConfig
		expectedErr    error
		expectAnyError bool
	}{
		{
			name: "empty DSN",
			config: PostgresConfig{
				Dsn:            "",
				MaxConnections: 10,
			},
			expectedErr: ErrEmptyDSN,
		},
		{
			name: "invalid DSN format",
			config: PostgresConfig{
				Dsn:            "://invalid",
				MaxConnections: 10,
			},
			expectAnyError: true,
		},
		{
			name: "negative max connections",
			config: PostgresConfig{
				Dsn:            "postgres://localhost/db",
				MaxConnections: -5,
			},
			expectedErr: ErrNegativeMaxConns,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.config.Validate()
			if tc.expectAnyError {
				require.Error(t, err)
			} else {
				require.ErrorIs(t, err, tc.expectedErr)
			}
		})
	}
}
