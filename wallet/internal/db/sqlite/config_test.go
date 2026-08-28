package sqlite

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
	dbConn, err := sql.Open("sqlite", ":memory:")
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

// TestConfigValidateSuccess isolates pool rules with fixed path and identity.
func TestConfigValidateSuccess(t *testing.T) {
	t.Parallel()

	// Arrange: Fix path and identity so each case isolates pool validation.
	identity, err := db.NewDatabaseIdentity(&chaincfg.RegressionNetParams, nil)
	require.NoError(t, err)

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

			tc.config.Identity = identity

			// Act: Validate each fully assembled SQLite configuration.
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
