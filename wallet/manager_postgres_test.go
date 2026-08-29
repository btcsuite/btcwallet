package wallet

import (
	"testing"

	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/stretchr/testify/require"
)

// TestManagerPostgresRejectsInvalidDSN verifies that NewManager passes a
// PostgreSQL data source to the Store and preserves its validation context.
func TestManagerPostgresRejectsInvalidDSN(t *testing.T) {
	t.Parallel()

	// Arrange: Supply every Manager runtime requirement while keeping only
	// the PostgreSQL data source malformed, so validation reaches the Store.
	// Act: Construct the Manager and let the backend parse the invalid DSN.
	m, err := NewManager(t.Context(), ManagerConfig{
		Backend:     DBBackendPostgres,
		DataSource:  "://invalid",
		ChainParams: chainParams,
		ChainSource: &bwmock.Chain{},
	})

	// Assert: Verify construction failed at the PostgreSQL boundary and no
	// partially initialized Manager escaped to the caller.
	require.Error(t, err)
	require.ErrorContains(t, err, "open postgres store")
	require.ErrorContains(t, err, "invalid config")
	require.ErrorContains(t, err, "invalid DSN")
	require.Nil(t, m)
}
