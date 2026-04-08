package db

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
