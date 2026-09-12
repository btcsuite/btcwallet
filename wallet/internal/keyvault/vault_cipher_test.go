package keyvault

import (
	"testing"

	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// TestWalletVaultEncryptSelectedRuntimeKeys verifies that Encrypt uses the
// selected runtime crypto key and preserves snacl ciphertext semantics.
func TestWalletVaultEncryptSelectedRuntimeKeys(t *testing.T) {
	t.Parallel()

	privateKey, err := snacl.GenerateCryptoKey()
	require.NoError(t, err)
	scriptKey, err := snacl.GenerateCryptoKey()
	require.NoError(t, err)

	vault := NewWalletVault(nil, 1, false)
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
			ciphertext, err := vault.Encrypt(test.keyType, plaintext)
			require.NoError(t, err)
			require.NotEqual(t, plaintext, ciphertext)
			require.Len(t, ciphertext, len(plaintext)+snacl.NonceSize+
				snacl.Overhead)

			decrypted, err := test.key.Decrypt(ciphertext)
			require.NoError(t, err)
			require.Equal(t, plaintext, decrypted)
		})
	}
}

// TestWalletVaultEncryptLocked verifies that missing runtime state reports the
// vault locked sentinel with wallet and method context.
func TestWalletVaultEncryptLocked(t *testing.T) {
	t.Parallel()

	vault := NewWalletVault(nil, 1, false)
	ciphertext, err := vault.Encrypt(waddrmgr.CKTPrivate, []byte("plaintext"))
	require.Nil(t, ciphertext)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrVaultLocked)
	require.ErrorContains(t, err, "wallet 1 vault Encrypt")
}

// TestWalletVaultEncryptUnsupportedKeyTypes verifies that WalletVault only
// exposes the runtime crypto keys it holds in unlockedState.
func TestWalletVaultEncryptUnsupportedKeyTypes(t *testing.T) {
	t.Parallel()

	state := makeUnlockedState(t)
	vault := NewWalletVault(nil, 1, false)
	vault.unlockedState = state
	t.Cleanup(vault.Lock)

	tests := []struct {
		name    string
		keyType waddrmgr.CryptoKeyType
		message string
	}{
		{
			name:    "invalid key type",
			keyType: waddrmgr.CryptoKeyType(0xff),
			message: "255",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			ciphertext, err := vault.Encrypt(test.keyType, []byte("plaintext"))
			require.Nil(t, ciphertext)
			require.Error(t, err)
			require.ErrorIs(t, err, errUnsupportedCryptoKeyType)
			require.ErrorContains(t, err, "wallet 1 vault Encrypt")
			require.ErrorContains(t, err, test.message)
		})
	}
}

// TestWalletVaultDecryptSelectedRuntimeKeys verifies that Decrypt uses the
// selected runtime crypto key and preserves snacl plaintext semantics.
func TestWalletVaultDecryptSelectedRuntimeKeys(t *testing.T) {
	t.Parallel()

	privateKey, err := snacl.GenerateCryptoKey()
	require.NoError(t, err)
	scriptKey, err := snacl.GenerateCryptoKey()
	require.NoError(t, err)

	vault := NewWalletVault(nil, 1, false)
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

// TestWalletVaultDecryptLocked verifies that missing runtime state reports the
// vault locked sentinel with wallet and method context.
func TestWalletVaultDecryptLocked(t *testing.T) {
	t.Parallel()

	vault := NewWalletVault(nil, 1, false)
	plaintext, err := vault.Decrypt(waddrmgr.CKTPrivate, []byte("ciphertext"))
	require.Nil(t, plaintext)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrVaultLocked)
	require.ErrorContains(t, err, "wallet 1 vault Decrypt")
}

// TestWalletVaultDecryptUnsupportedKeyTypes verifies that WalletVault only
// exposes the runtime crypto keys it holds in unlockedState.
func TestWalletVaultDecryptUnsupportedKeyTypes(t *testing.T) {
	t.Parallel()

	state := makeUnlockedState(t)
	vault := NewWalletVault(nil, 1, false)
	vault.unlockedState = state
	t.Cleanup(vault.Lock)

	tests := []struct {
		name    string
		keyType waddrmgr.CryptoKeyType
		message string
	}{
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

// TestWalletVaultDecryptMalformedCiphertext verifies that snacl decrypt
// errors are returned with wallet and method context.
func TestWalletVaultDecryptMalformedCiphertext(t *testing.T) {
	t.Parallel()

	state := makeUnlockedState(t)
	vault := NewWalletVault(nil, 1, false)
	vault.unlockedState = state
	t.Cleanup(vault.Lock)

	plaintext, err := vault.Decrypt(waddrmgr.CKTPrivate, []byte("short"))
	require.Nil(t, plaintext)
	require.Error(t, err)
	require.ErrorIs(t, err, snacl.ErrMalformed)
	require.ErrorContains(t, err, "wallet 1 vault Decrypt: decrypt")
}

// TestWalletVaultPublicMapsToScriptKey verifies that a CKTPublic request is
// served by the script key. A SQL wallet has no separate public crypto key,
// but the retained taproot script import asks for that class, so the mapping
// is what keeps the import working and round-tripping.
func TestWalletVaultPublicMapsToScriptKey(t *testing.T) {
	t.Parallel()

	state := makeUnlockedState(t)
	vault := NewWalletVault(nil, 1, false)
	vault.unlockedState = state
	t.Cleanup(vault.Lock)

	plaintext := []byte("taproot script body")

	ciphertext, err := vault.Encrypt(waddrmgr.CKTPublic, plaintext)
	require.NoError(t, err)
	require.NotEqual(t, plaintext, ciphertext)

	// The same blob opens under either name, which is what makes the
	// mapping safe: the store records ScriptIsSecret for these rows.
	got, err := vault.Decrypt(waddrmgr.CKTPublic, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)

	got, err = vault.Decrypt(waddrmgr.CKTScript, ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
}
