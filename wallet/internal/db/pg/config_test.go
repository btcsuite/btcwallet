package pg

import (
	"context"
	"math"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// TestDatabaseIdentityCancellationPreservesCause proves startup failures do
// not masquerade as persisted identity mismatches.
func TestDatabaseIdentityCancellationPreservesCause(t *testing.T) {
	t.Parallel()

	// Arrange: Cancel before BeginTx so no identity state can be inspected.
	identity, err := db.NewDatabaseIdentity(&chaincfg.RegressionNetParams, nil)
	require.NoError(t, err)
	pool, err := pgxpool.New(t.Context(), "postgres://localhost/unused")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Act: Attempt initialization and close the unused database handle.
	initErr := initializeDatabaseIdentity(ctx, pool, identity)
	pool.Close()

	// Assert: Cancellation remains detectable without the mismatch sentinel.
	require.ErrorIs(t, initErr, context.Canceled)
	require.NotErrorIs(t, initErr, db.ErrDatabaseIdentityMismatch)
}

// TestConfigValidateSuccess isolates DSN and pool rules with fixed identity.
func TestConfigValidateSuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Fix identity so each case isolates DSN and pool validation.
	identity, err := db.NewDatabaseIdentity(&chaincfg.RegressionNetParams, nil)
	require.NoError(t, err)

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

			tc.config.Identity = identity

			// Act: Validate each fully assembled PostgreSQL configuration.
			err := tc.config.Validate()

			// Assert: Default and bounded pools both accept the identity.
			require.NoError(t, err)
		})
	}
}

// TestConfigValidateErrors tests Config validation errors.
func TestConfigValidateErrors(t *testing.T) {
	t.Parallel()

	// Arrange: Isolate DSN and pool-limit failures before identity validation,
	// including limits that cannot fit the native pool's int32 field.
	tests := []struct {
		name           string
		config         Config
		expectedErr    error
		expectAnyError bool
	}{
		{
			name: "max connections exceeds native limit",
			config: Config{
				Dsn:            "postgres://localhost/db",
				MaxConnections: math.MaxInt32 + 1,
			},
			expectedErr: db.ErrCastingOverflow,
		},
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

			// Act: Validate the configuration before opening any pool.
			err := tc.config.Validate()

			// Assert: Malformed DSNs fail, while known configuration
			// violations retain their specific caller-visible sentinel.
			if tc.expectAnyError {
				require.Error(t, err)
			} else {
				require.ErrorIs(t, err, tc.expectedErr)
			}
		})
	}
}
