package keyvault

import (
	"testing"

	"github.com/btcsuite/btcwallet/snacl"
	"github.com/stretchr/testify/require"
)

// TestWalletVaultLockClearsUnlockedState verifies that Lock returns the
// vault to the locked state and wipes runtime secrets.
func TestWalletVaultLockClearsUnlockedState(t *testing.T) {
	t.Parallel()

	vault := NewWalletVault(nil, 1)
	state := makeUnlockedState(t)
	vault.unlockedState = state

	require.False(t, vault.IsLocked())

	vault.Lock()

	require.True(t, vault.IsLocked())
	require.Nil(t, vault.unlockedState)
	require.Equal(t, snacl.CryptoKey{}, state.cryptoKeyPrivate)
	require.Equal(t, snacl.CryptoKey{}, state.cryptoKeyScript)
	require.Nil(t, state.hdRootKey)
}

// TestWalletVaultLockIdempotent verifies that Lock stays a no-op when already
// locked.
func TestWalletVaultLockIdempotent(t *testing.T) {
	t.Parallel()

	vault := NewWalletVault(nil, 1)
	require.True(t, vault.IsLocked())

	vault.Lock()

	require.True(t, vault.IsLocked())
	require.Nil(t, vault.unlockedState)

	vault.Lock()
	require.True(t, vault.IsLocked())
	require.Nil(t, vault.unlockedState)
}

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
