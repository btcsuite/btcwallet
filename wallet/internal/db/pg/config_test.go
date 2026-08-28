package pg

import (
	"context"
	"database/sql"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestDatabaseIdentityCancellationPreservesCause proves startup failures do
// not masquerade as persisted identity mismatches.
func TestDatabaseIdentityCancellationPreservesCause(t *testing.T) {
	t.Parallel()

	// Arrange: Cancel before BeginTx so no identity state can be inspected.
	identity, err := db.NewDatabaseIdentity(&chaincfg.RegressionNetParams, nil)
	require.NoError(t, err)
	dbConn, err := sql.Open("pgx", "postgres://localhost/unused")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Act: Attempt initialization and close the unused database handle.
	initErr := initializeDatabaseIdentity(ctx, dbConn, identity)
	closeErr := dbConn.Close()

	// Assert: Cancellation remains detectable without the mismatch sentinel.
	require.ErrorIs(t, initErr, context.Canceled)
	require.NotErrorIs(t, initErr, db.ErrDatabaseIdentityMismatch)
	require.NoError(t, closeErr)
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
