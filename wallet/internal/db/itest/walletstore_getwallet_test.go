//go:build itest

package itest

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestGetWallet verifies that GetWallet retrieves a wallet by name.
func TestGetWallet(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	params := CreateWalletParamsFixture("get-test-wallet")
	created, err := store.CreateWallet(t.Context(), params)
	require.NoError(t, err)

	retrieved, err := store.GetWallet(t.Context(), params.Name)
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	require.Equal(t, created.ID, retrieved.ID)
	require.Equal(t, created.Name, retrieved.Name)
	require.Equal(t, created.IsImported, retrieved.IsImported)
	require.Equal(t, created.ManagerVersion, retrieved.ManagerVersion)
	require.Equal(t, created.IsWatchOnly, retrieved.IsWatchOnly)
}

// TestGetWalletNotFound verifies that GetWallet returns ErrWalletNotFound
// when the wallet doesn't exist.
func TestGetWalletNotFound(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	before := store.StatsSnapshot()

	_, err := store.GetWallet(t.Context(), "non-existent-wallet")
	require.Error(t, err)
	require.ErrorIs(t, err, db.ErrWalletNotFound)

	after := store.StatsSnapshot()
	require.Equal(t, before, after)
}
