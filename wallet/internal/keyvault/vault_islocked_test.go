package keyvault

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDBVaultIsLockedInitialState verifies that a new vault starts locked.
func TestDBVaultIsLockedInitialState(t *testing.T) {
	t.Parallel()

	vault := NewDBVault(nil, 1)
	require.True(t, vault.IsLocked())
}

// TestDBVaultIsLockedUnlockedState verifies that populated runtime state is
// reported as unlocked.
func TestDBVaultIsLockedUnlockedState(t *testing.T) {
	t.Parallel()

	vault := NewDBVault(nil, 1)
	vault.unlockedState = &unlockedState{}
	require.False(t, vault.IsLocked())
}
