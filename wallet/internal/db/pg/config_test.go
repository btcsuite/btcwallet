package pg

import (
	"testing"

	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestConfigValidateSuccess tests valid Config scenarios.
func TestConfigValidateSuccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "valid config with all fields set",
			config: Config{
				Dsn:            "postgres://user:pass@localhost/db",
				MaxConnections: 25,
			},
		},
		{
			name: "valid config with zero max connections",
			config: Config{
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

// TestConfigValidateErrors tests Config validation errors.
func TestConfigValidateErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		config         Config
		expectedErr    error
		expectAnyError bool
	}{
		{
			name: "empty DSN",
			config: Config{
				Dsn:            "",
				MaxConnections: 10,
			},
			expectedErr: db.ErrEmptyDSN,
		},
		{
			name: "invalid DSN format",
			config: Config{
				Dsn:            "://invalid",
				MaxConnections: 10,
			},
			expectAnyError: true,
		},
		{
			name: "negative max connections",
			config: Config{
				Dsn:            "postgres://localhost/db",
				MaxConnections: -5,
			},
			expectedErr: db.ErrNegativeMaxConns,
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
