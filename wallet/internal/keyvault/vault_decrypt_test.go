package keyvault

import (
	"testing"

	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// TestDBVaultDecryptSelectedRuntimeKeys verifies that Decrypt uses the selected
// runtime crypto key and preserves snacl plaintext semantics.
func TestDBVaultDecryptSelectedRuntimeKeys(t *testing.T) {
	t.Parallel()

	privateKey, err := snacl.GenerateCryptoKey()
	require.NoError(t, err)
	scriptKey, err := snacl.GenerateCryptoKey()
	require.NoError(t, err)

	vault := NewDBVault(nil, 1)
	vault.unlockedState = &unlockedState{
		cryptoKeyPrivate: *privateKey,
		cryptoKeyScript:  *scriptKey,
	}
	t.Cleanup(vault.Lock)

	tests := []struct {
		name    string
		keyType waddrmgr.CryptoKeyType
		key     *snacl.CryptoKey
	}{
		{
			name:    "private key",
			keyType: waddrmgr.CKTPrivate,
			key:     privateKey,
		},
		{
			name:    "script key",
			keyType: waddrmgr.CKTScript,
			key:     scriptKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			plaintext := []byte("key material for " + test.name)
			ciphertext, err := test.key.Encrypt(plaintext)
			require.NoError(t, err)
			require.NotEqual(t, plaintext, ciphertext)

			decrypted, err := vault.Decrypt(test.keyType, ciphertext)
			require.NoError(t, err)
			require.Equal(t, plaintext, decrypted)
		})
	}
}

// TestDBVaultDecryptLocked verifies that missing runtime state reports the
// vault locked sentinel with wallet and method context.
func TestDBVaultDecryptLocked(t *testing.T) {
	t.Parallel()

	vault := NewDBVault(nil, 1)
	plaintext, err := vault.Decrypt(waddrmgr.CKTPrivate, []byte("ciphertext"))
	require.Nil(t, plaintext)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrVaultLocked)
	require.ErrorContains(t, err, "wallet 1 vault Decrypt")
}

// TestDBVaultDecryptUnsupportedKeyTypes verifies that WalletVault only exposes
// the runtime crypto keys it holds in unlockedState.
func TestDBVaultDecryptUnsupportedKeyTypes(t *testing.T) {
	t.Parallel()

	state := makeUnlockedState(t)
	vault := NewDBVault(nil, 1)
	vault.unlockedState = state
	t.Cleanup(vault.Lock)

	tests := []struct {
		name    string
		keyType waddrmgr.CryptoKeyType
		message string
	}{
		{
			name:    "public key",
			keyType: waddrmgr.CKTPublic,
			message: "public crypto key",
		},
		{
			name:    "invalid key type",
			keyType: waddrmgr.CryptoKeyType(0xff),
			message: "255",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			plaintext, err := vault.Decrypt(test.keyType, []byte("ciphertext"))
			require.Nil(t, plaintext)
			require.Error(t, err)
			require.ErrorIs(t, err, errUnsupportedCryptoKeyType)
			require.ErrorContains(t, err, "wallet 1 vault Decrypt")
			require.ErrorContains(t, err, test.message)
		})
	}
}

// TestDBVaultDecryptMalformedCiphertext verifies that snacl decrypt errors are
// returned with wallet and method context.
func TestDBVaultDecryptMalformedCiphertext(t *testing.T) {
	t.Parallel()

	state := makeUnlockedState(t)
	vault := NewDBVault(nil, 1)
	vault.unlockedState = state
	t.Cleanup(vault.Lock)

	plaintext, err := vault.Decrypt(waddrmgr.CKTPrivate, []byte("short"))
	require.Nil(t, plaintext)
	require.Error(t, err)
	require.ErrorIs(t, err, snacl.ErrMalformed)
	require.ErrorContains(t, err, "wallet 1 vault Decrypt: decrypt")
}
