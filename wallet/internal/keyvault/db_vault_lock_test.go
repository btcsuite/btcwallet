package keyvault

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/stretchr/testify/require"
)

// makeUnlockedState builds runtime state with distinct secret material for
// Lock tests.
func makeUnlockedState(t *testing.T) *unlockedState {
	t.Helper()

	cryptoKeyPrivate := snacl.CryptoKey{1, 2}
	cryptoKeyScript := snacl.CryptoKey{3, 4}
	seed := []byte("0123456789abcdef0123456789abcdef")
	hdRootKey, err := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	require.NoError(t, err)

	return &unlockedState{
		cryptoKeyPrivate: cryptoKeyPrivate,
		cryptoKeyScript:  cryptoKeyScript,
		hdRootKey:        hdRootKey,
	}
}

// TestDBVaultLockClearsUnlockedState verifies that Lock returns the vault to
// the locked state and wipes runtime secrets.
func TestDBVaultLockClearsUnlockedState(t *testing.T) {
	t.Parallel()

	vault := NewDBVault(nil, 1)
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

// TestDBVaultLockIdempotent verifies that Lock stays a no-op when already
// locked.
func TestDBVaultLockIdempotent(t *testing.T) {
	t.Parallel()

	vault := NewDBVault(nil, 1)
	require.True(t, vault.IsLocked())

	vault.Lock()

	require.True(t, vault.IsLocked())
	require.Nil(t, vault.unlockedState)

	vault.Lock()
	require.True(t, vault.IsLocked())
	require.Nil(t, vault.unlockedState)
}

// TestDBVaultScheduleLockingDefaultTimeoutAndCancel verifies that a zero
// timeout schedules the default auto-lock timeout and that Lock cancels it.
func TestDBVaultScheduleLockingDefaultTimeoutAndCancel(t *testing.T) {
	t.Parallel()

	vault := NewDBVault(nil, 1)
	vault.unlockedState = &unlockedState{}

	vault.mtx.Lock()
	vault.scheduleLocking(0)
	require.NotNil(t, vault.timer.timer)
	vault.mtx.Unlock()

	require.False(t, vault.IsLocked())
	require.Never(
		t, func() bool {
			return vault.IsLocked()
		}, 20*time.Millisecond, time.Millisecond,
		"default timeout should not fire immediately",
	)

	vault.Lock()
	require.True(t, vault.IsLocked())
	require.Nil(t, vault.timer.timer)
	require.Nil(t, vault.unlockedState)
}

