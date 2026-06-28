package keyvault

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/waddrmgr"
	bwmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestDBVaultUnlockSuccess verifies that Unlock loads persisted secrets and
// reconstructs the runtime crypto and HD root key state.
func TestDBVaultUnlockSuccess(t *testing.T) {
	t.Parallel()

	secrets, expected := makeWalletSecrets(t, correctPassphrase)

	const walletID = uint32(7)

	store := new(bwmock.Store)
	store.On("GetWalletSecrets", mock.Anything, walletID).Return(
		secrets, nil,
	).Once()
	t.Cleanup(func() {
		store.AssertExpectations(t)
	})

	vault := NewDBVault(store, walletID)
	require.NoError(t, vault.Unlock(t.Context(), correctPassphrase))
	t.Cleanup(vault.Lock)

	require.False(t, vault.IsLocked())
	require.NotNil(t, vault.unlockedState)
	require.Equal(
		t, expected.cryptoKeyPrivate[:],
		vault.unlockedState.cryptoKeyPrivate[:],
	)
	require.Equal(
		t, expected.cryptoKeyScript[:], vault.unlockedState.cryptoKeyScript[:],
	)
	require.Equal(
		t, expected.hdRootKey.String(), vault.unlockedState.hdRootKey.String(),
	)
}

// TestDBVaultUnlockWrongPassphraseKeepsLocked verifies that an invalid
// passphrase preserves the vault sentinel error and leaves no runtime state.
func TestDBVaultUnlockWrongPassphraseKeepsLocked(t *testing.T) {
	t.Parallel()

	secrets, _ := makeWalletSecrets(t, correctPassphrase)

	const walletID = uint32(8)

	store := new(bwmock.Store)
	store.On("GetWalletSecrets", mock.Anything, walletID).Return(
		secrets, nil,
	).Once()
	t.Cleanup(func() {
		store.AssertExpectations(t)
	})

	vault := NewDBVault(store, walletID)
	err := vault.Unlock(t.Context(), wrongPassphrase)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPassphrase)
	require.True(t, vault.IsLocked())
	require.Nil(t, vault.unlockedState)
}

// TestDBVaultUnlockIdempotentWhenAlreadyUnlocked verifies that Unlock is a
// no-op once the vault has been unlocked and leaves runtime state unchanged.
func TestDBVaultUnlockIdempotentWhenAlreadyUnlocked(t *testing.T) {
	t.Parallel()

	secrets, expected := makeWalletSecrets(t, correctPassphrase)

	const walletID = uint32(10)

	store := new(bwmock.Store)
	store.On("GetWalletSecrets", mock.Anything, walletID).Return(
		secrets, nil,
	).Once()
	t.Cleanup(func() {
		store.AssertExpectations(t)
	})

	vault := NewDBVault(store, walletID)
	require.NoError(t, vault.Unlock(t.Context(), correctPassphrase))

	previousState := vault.unlockedState
	previousPrivate := vault.unlockedState.cryptoKeyPrivate
	previousScript := vault.unlockedState.cryptoKeyScript
	previousHDRoot := vault.unlockedState.hdRootKey.String()

	require.NoError(t, vault.Unlock(t.Context(), wrongPassphrase))
	require.False(t, vault.IsLocked())
	require.Same(t, previousState, vault.unlockedState)
	require.Equal(
		t, expected.cryptoKeyPrivate[:],
		vault.unlockedState.cryptoKeyPrivate[:],
	)
	require.Equal(
		t, expected.cryptoKeyScript[:], vault.unlockedState.cryptoKeyScript[:],
	)
	require.Equal(
		t, expected.hdRootKey.String(), vault.unlockedState.hdRootKey.String(),
	)
	require.Equal(t, previousPrivate, vault.unlockedState.cryptoKeyPrivate)
	require.Equal(t, previousScript, vault.unlockedState.cryptoKeyScript)
	require.Equal(t, previousHDRoot, vault.unlockedState.hdRootKey.String())
}

// TestDBVaultUnlockStoreErrorPropagates verifies that store failures are
// wrapped with wallet context without creating unlocked runtime state.
func TestDBVaultUnlockStoreErrorPropagates(t *testing.T) {
	t.Parallel()

	const walletID = uint32(9)

	store := new(bwmock.Store)
	store.On("GetWalletSecrets", mock.Anything, walletID).Return(
		(*db.WalletSecrets)(nil), errStoreUnavailable,
	).Once()
	t.Cleanup(func() {
		store.AssertExpectations(t)
	})

	vault := NewDBVault(store, walletID)
	err := vault.Unlock(t.Context(), correctPassphrase)
	require.Error(t, err)
	require.ErrorIs(t, err, errStoreUnavailable)
	require.True(t, vault.IsLocked())
}

// TestDBVaultUnlockMalformedScriptKeyLocksVault verifies that a failure after
// partial runtime state allocation leaves the vault locked.
func TestDBVaultUnlockMalformedScriptKeyLocksVault(t *testing.T) {
	t.Parallel()

	secrets, _ := makeWalletSecrets(t, correctPassphrase)
	secrets.EncryptedCryptoScriptKey = []byte("malformed")

	const walletID = uint32(13)

	store := new(bwmock.Store)
	store.On("GetWalletSecrets", mock.Anything, walletID).Return(
		secrets, nil,
	).Once()
	t.Cleanup(func() {
		store.AssertExpectations(t)
	})

	vault := NewDBVault(store, walletID)
	err := vault.Unlock(t.Context(), correctPassphrase)
	require.Error(t, err)
	require.ErrorIs(t, err, errUnexpectedState)
	require.ErrorIs(t, err, snacl.ErrMalformed)
	require.True(t, vault.IsLocked())
	require.Nil(t, vault.unlockedState)
}

// makeWalletSecrets creates encrypted wallet secret material for unlock tests.
func makeWalletSecrets(t *testing.T, passphrase []byte) (*db.WalletSecrets,
	unlockedState) {

	t.Helper()

	masterPrivateKey, err := snacl.NewSecretKey(
		&passphrase, waddrmgr.FastScryptOptions.N,
		waddrmgr.FastScryptOptions.R, waddrmgr.FastScryptOptions.P,
	)
	require.NoError(t, err)
	t.Cleanup(masterPrivateKey.Zero)

	privateKey, err := snacl.GenerateCryptoKey()
	require.NoError(t, err)
	scriptKey, err := snacl.GenerateCryptoKey()
	require.NoError(t, err)

	seed := []byte("0123456789abcdef0123456789abcdef")
	hdRootKey, err := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	require.NoError(t, err)

	encryptedPrivateKey, err := masterPrivateKey.Encrypt(privateKey[:])
	require.NoError(t, err)
	encryptedScriptKey, err := masterPrivateKey.Encrypt(scriptKey[:])
	require.NoError(t, err)
	encryptedHDRootKey, err := privateKey.Encrypt([]byte(hdRootKey.String()))
	require.NoError(t, err)

	secrets := &db.WalletSecrets{
		MasterPrivParams:         masterPrivateKey.Marshal(),
		EncryptedCryptoPrivKey:   encryptedPrivateKey,
		EncryptedCryptoScriptKey: encryptedScriptKey,
		EncryptedMasterHdPrivKey: encryptedHDRootKey,
	}

	return secrets, unlockedState{
		cryptoKeyPrivate: *privateKey,
		cryptoKeyScript:  *scriptKey,
		hdRootKey:        hdRootKey,
	}
}
