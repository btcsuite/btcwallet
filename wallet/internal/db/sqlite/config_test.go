package sqlite

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
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
			name: "valid config with zero max connections",
			config: Config{
				DBPath:         "/tmp/test.db",
				MaxConnections: 0,
			},
		},
		{
			name: "valid config with positive max connections",
			config: Config{
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

// TestConfigValidateErrors tests Config validation errors.
func TestConfigValidateErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		config      Config
		expectedErr error
	}{
		{
			name: "empty DB path",
			config: Config{
				DBPath:         "",
				MaxConnections: 0,
			},
			expectedErr: db.ErrEmptyDBPath,
		},
		{
			name: "negative max connections",
			config: Config{
				DBPath:         "/tmp/test.db",
				MaxConnections: -1,
			},
			expectedErr: db.ErrNegativeMaxConns,
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
