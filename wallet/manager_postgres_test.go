package wallet

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestManagerPostgresRejectsInvalidDSN verifies that NewManager passes a
// PostgreSQL data source to the Store and preserves its validation context.
func TestManagerPostgresRejectsInvalidDSN(t *testing.T) {
	t.Parallel()

	m, err := NewManager(t.Context(), ManagerConfig{
		Backend:     DBBackendPostgres,
		DataSource:  "://invalid",
		ChainParams: &chainParams,
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "open postgres store")
	require.ErrorContains(t, err, "invalid config")
	require.ErrorContains(t, err, "invalid DSN")
	require.Nil(t, m)
}
