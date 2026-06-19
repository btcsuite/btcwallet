package keyvault

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/snacl"
	bwmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/stretchr/testify/mock"
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

// TestDBVaultLockWaitsForInFlightUnlock verifies that explicit Lock calls are
// ordered after an Unlock that has already entered the vault lifecycle.
func TestDBVaultLockWaitsForInFlightUnlock(t *testing.T) {
	t.Parallel()

	secrets, _ := makeWalletSecrets(t, correctPassphrase)

	const walletID = uint32(12)

	unlockStarted := make(chan struct{})
	releaseUnlock := make(chan struct{})

	store := new(bwmock.Store)
	store.On("GetWalletSecrets", mock.Anything, walletID).Run(
		func(_ mock.Arguments) {
			// close unlockStarted to signal that Unlock has entered the store
			// call and is now in-flight.
			close(unlockStarted)

			// wait for releaseUnlock to be closed before returning, simulating
			// a long-running store call that holds the vault lifecycle lock
			// until completion.
			<-releaseUnlock
		},
	).Return(secrets, nil).Once()
	t.Cleanup(func() {
		store.AssertExpectations(t)
	})

	vault := NewDBVault(store, walletID)

	unlockDone := make(chan error, 1)

	// run Unlock in a goroutine so Lock can contend with an in-flight unlock.
	go func() {
		unlockDone <- vault.Unlock(t.Context(), correctPassphrase, -1)
	}()

	require.Eventually(
		t, func() bool {
			select {
			case <-unlockStarted:
				return true
			default:
				return false
			}
		}, time.Second, time.Millisecond, "Unlock did not start",
	)

	// start Lock while Unlock is blocked so we can verify Lock waits for the
	// in-flight Unlock to finish.
	lockDone := make(chan struct{})
	go func() {
		vault.Lock()
		close(lockDone)
	}()

	require.Never(
		t, func() bool {
			select {
			case <-lockDone:
				return true
			default:
				return false
			}
		}, time.Second, time.Millisecond,
		"Lock completed before the in flight Unlock finished",
	)

	// releasing the in-flight Unlock should allow both the Unlock and Lock to
	// complete in order.
	close(releaseUnlock)

	require.Eventually(t, func() bool {
		select {
		case err := <-unlockDone:
			require.NoError(t, err)
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond,
		"Unlock did not complete after being released")

	require.Eventually(t, func() bool {
		select {
		case <-lockDone:
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond,
		"Lock did not complete after the in flight Unlock finished")

	require.True(t, vault.IsLocked())
	require.Nil(t, vault.unlockedState)
}
