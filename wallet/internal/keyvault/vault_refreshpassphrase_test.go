package keyvault

import (
	"testing"

	bwmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestDBVaultRefreshPrivatePassphraseLockedRequiresUnlockedState verifies that
// refreshing private passphrase state requires an already unlocked vault.
func TestDBVaultRefreshPrivatePassphraseLockedRequiresUnlockedState(
	t *testing.T) {

	t.Parallel()

	vault := NewDBVault(nil, 1)
	err := vault.RefreshPrivatePassphrase(t.Context(), correctPassphrase)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrVaultLocked)
	require.True(t, vault.IsLocked())
	require.Nil(t, vault.unlockedState)
}

// TestDBVaultRefreshPrivatePassphraseUpdateErrorPreservesState verifies that
// persistence failures leave the vault unlocked with existing runtime state.
func TestDBVaultRefreshPrivatePassphraseUpdateErrorPreservesState(
	t *testing.T) {

	t.Parallel()

	oldSecrets, oldExpected := makeWalletSecrets(t, correctPassphrase)
	newPassphrase := []byte("new-passphrase")

	const walletID = uint32(15)

	var capturedUpdate db.UpdateWalletSecretsParams

	store := new(bwmock.Store)
	store.On("GetWalletSecrets", mock.Anything, walletID).Return(
		oldSecrets, nil,
	).Once()
	store.On("GetWalletSecrets", mock.Anything, walletID).Return(
		oldSecrets, nil,
	).Once()
	store.On("UpdateWalletSecrets", mock.Anything, mock.MatchedBy(
		func(params db.UpdateWalletSecretsParams) bool {
			capturedUpdate = params
			return true
		},
	)).Return(errStoreUnavailable).Once()
	t.Cleanup(func() {
		store.AssertExpectations(t)
	})

	vault := NewDBVault(store, walletID)
	require.NoError(t, vault.Unlock(t.Context(), correctPassphrase))
	t.Cleanup(vault.Lock)

	oldState := vault.unlockedState
	err := vault.RefreshPrivatePassphrase(t.Context(), newPassphrase)
	require.Error(t, err)
	require.ErrorIs(t, err, errStoreUnavailable)

	require.Equal(t, walletID, capturedUpdate.WalletID)
	require.Same(t, oldState, vault.unlockedState)
	require.Equal(
		t, oldExpected.cryptoKeyPrivate[:], oldState.cryptoKeyPrivate[:],
	)
	require.Equal(
		t, oldExpected.cryptoKeyScript[:], oldState.cryptoKeyScript[:],
	)
	require.Equal(
		t, oldExpected.hdRootKey.String(), oldState.hdRootKey.String(),
	)
	require.False(t, vault.IsLocked())
}

// TestDBVaultRefreshPrivatePassphraseSuccessPersistsRotation verifies that a
// refresh persists wallet secrets encrypted by the new passphrase while keeping
// unlocked runtime state unchanged.
func TestDBVaultRefreshPrivatePassphraseSuccessPersistsRotation(
	t *testing.T) {

	t.Parallel()

	oldSecrets, oldExpected := makeWalletSecrets(t, correctPassphrase)
	newPassphrase := []byte("new-passphrase")

	const walletID = uint32(16)

	var capturedUpdate db.UpdateWalletSecretsParams

	store := new(bwmock.Store)
	store.On("GetWalletSecrets", mock.Anything, walletID).Return(
		oldSecrets, nil,
	).Once()
	store.On("GetWalletSecrets", mock.Anything, walletID).Return(
		oldSecrets, nil,
	).Once()
	store.On("UpdateWalletSecrets", mock.Anything, mock.MatchedBy(
		func(params db.UpdateWalletSecretsParams) bool {
			capturedUpdate = params
			return true
		},
	)).Return(nil).Once()
	t.Cleanup(func() {
		store.AssertExpectations(t)
	})

	vault := NewDBVault(store, walletID)
	require.NoError(t, vault.Unlock(t.Context(), correctPassphrase))
	t.Cleanup(vault.Lock)

	oldState := vault.unlockedState

	require.NoError(
		t, vault.RefreshPrivatePassphrase(t.Context(), newPassphrase),
	)
	require.Same(t, oldState, vault.unlockedState)
	require.Equal(
		t, oldExpected.cryptoKeyPrivate[:],
		vault.unlockedState.cryptoKeyPrivate[:],
	)
	require.Equal(
		t, oldExpected.cryptoKeyScript[:],
		vault.unlockedState.cryptoKeyScript[:],
	)
	require.Equal(
		t, oldExpected.hdRootKey.String(),
		vault.unlockedState.hdRootKey.String(),
	)
	require.False(t, vault.IsLocked())

	updatedSecrets := &db.WalletSecrets{
		MasterPrivParams:         capturedUpdate.MasterPrivParams,
		EncryptedCryptoPrivKey:   capturedUpdate.EncryptedCryptoPrivKey,
		EncryptedCryptoScriptKey: capturedUpdate.EncryptedCryptoScriptKey,
		EncryptedMasterHdPrivKey: capturedUpdate.EncryptedMasterHdPrivKey,
	}

	newState, err := decryptWalletSecrets(updatedSecrets, newPassphrase)
	require.NoError(t, err)
	t.Cleanup(newState.zero)
	require.Equal(
		t, oldExpected.cryptoKeyPrivate[:], newState.cryptoKeyPrivate[:],
	)
	require.Equal(
		t, oldExpected.cryptoKeyScript[:], newState.cryptoKeyScript[:],
	)
	require.Equal(
		t, oldExpected.hdRootKey.String(), newState.hdRootKey.String(),
	)

	_, err = decryptWalletSecrets(updatedSecrets, correctPassphrase)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPassphrase)
}
