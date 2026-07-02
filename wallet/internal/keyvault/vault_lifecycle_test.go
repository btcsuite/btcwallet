package keyvault

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestWalletVaultIsLockedInitialState verifies that a new vault starts locked.
func TestWalletVaultIsLockedInitialState(t *testing.T) {
	t.Parallel()

	vault := NewWalletVault(nil, 1)
	require.True(t, vault.IsLocked())
}

// TestWalletVaultIsLockedUnlockedState verifies that populated runtime state is
// reported as unlocked.
func TestWalletVaultIsLockedUnlockedState(t *testing.T) {
	t.Parallel()

	vault := NewWalletVault(nil, 1)
	vault.unlockedState = &unlockedState{}
	require.False(t, vault.IsLocked())
}
