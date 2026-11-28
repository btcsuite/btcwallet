package keyvault

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/waddrmgr"
	bwmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/mock"
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

// scriptWalletID is the wallet the script fixtures belong to.
const scriptWalletID = 7

// scriptFixture is a vault whose Store mock serves one encrypted script for
// one script pubkey.
type scriptFixture struct {
	vault        *WalletVault
	scriptPubKey []byte
	secret       *db.AddressSecret
}

// newScriptFixture returns an unlocked vault and a Store mock that returns
// script, encrypted under the vault's script key, once for scriptPubKey. The
// Store call asserts that the vault guard is free, because the guard must
// never wait for the Store.
func newScriptFixture(t *testing.T, script []byte) *scriptFixture {
	t.Helper()

	store := &bwmock.Store{}
	t.Cleanup(func() {
		store.AssertExpectations(t)
	})

	vault := NewWalletVault(store, scriptWalletID, false)
	vault.unlockedState = makeUnlockedState(t)
	t.Cleanup(vault.Lock)

	encrypted, err := vault.unlockedState.cryptoKeyScript.Encrypt(script)
	require.NoError(t, err)

	secret := &db.AddressSecret{
		EncryptedPrivKey: []byte("encrypted private key"),
		EncryptedScript:  encrypted,
		ScriptIsSecret:   true,
	}
	scriptPubKey := []byte("script pubkey selector")

	store.On("GetAddressSecret", mock.Anything, db.GetAddressSecretQuery{
		WalletID:     scriptWalletID,
		ScriptPubKey: scriptPubKey,
	}).Run(func(mock.Arguments) {
		require.True(t, vault.mtx.TryLock(), "store called under guard")
		vault.mtx.Unlock()
	}).Return(secret, nil).Once()

	return &scriptFixture{
		vault:        vault,
		scriptPubKey: scriptPubKey,
		secret:       secret,
	}
}

// requireSecretZeroed asserts that the vault cleared the encrypted address
// secret that it read from the Store.
func requireSecretZeroed(t *testing.T, secret *db.AddressSecret) {
	t.Helper()

	encrypted := [][]byte{secret.EncryptedPrivKey, secret.EncryptedScript}
	for _, buf := range encrypted {
		// A field the Store did not return stays nil.
		zeroed := bytes.Clone(buf)
		clear(zeroed)

		require.Equal(t, zeroed, buf)
	}
}

// TestWalletVaultDecryptScript verifies that DecryptScript returns the stored
// script bytes uninterpreted, as a copy the caller can change without
// changing a later result, and that it clears the encrypted Store copy.
func TestWalletVaultDecryptScript(t *testing.T) {
	t.Parallel()

	// Arrange: Store one encrypted script.
	stored := []byte("opaque stored script")
	f := newScriptFixture(t, stored)

	// Act: Decrypt the script.
	script, err := f.vault.DecryptScript(t.Context(), f.scriptPubKey)

	// Assert: The bytes match, and the encrypted copy was cleared.
	require.NoError(t, err)
	require.Equal(t, stored, script)
	requireSecretZeroed(t, f.secret)
}

// TestWalletVaultDecryptScriptNotFound verifies that an unlocked vault returns
// ErrScriptNotFound for an output without a stored script.
func TestWalletVaultDecryptScriptNotFound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		secret   *db.AddressSecret
		storeErr error
	}{{
		name:     "address not found",
		storeErr: db.ErrAddressNotFound,
	}, {
		name:     "secret not found",
		storeErr: db.ErrSecretNotFound,
	}, {
		name: "watch-only import without script",
		secret: &db.AddressSecret{
			EncryptedPrivKey: []byte("encrypted private key"),
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: An unlocked vault whose Store has no script.
			scriptPubKey := []byte("script pubkey selector")
			store := &bwmock.Store{}
			store.On("GetAddressSecret", mock.Anything,
				db.GetAddressSecretQuery{
					WalletID:     scriptWalletID,
					ScriptPubKey: scriptPubKey,
				}).Return(test.secret, test.storeErr).Once()

			vault := NewWalletVault(store, scriptWalletID, false)
			vault.unlockedState = makeUnlockedState(t)
			t.Cleanup(vault.Lock)

			// Act: Decrypt the missing script.
			script, err := vault.DecryptScript(t.Context(), scriptPubKey)

			// Assert: The missing script keeps its public error.
			require.Nil(t, script)
			require.ErrorIs(t, err, ErrScriptNotFound)
			require.NotErrorIs(t, err, ErrVaultLocked)
			store.AssertExpectations(t)

			if test.secret != nil {
				requireSecretZeroed(t, test.secret)
			}
		})
	}
}

// TestWalletVaultDecryptScriptLocked verifies that a locked vault fails before
// looking up the output, even when the Store has no script for it.
func TestWalletVaultDecryptScriptLocked(t *testing.T) {
	t.Parallel()

	// Arrange: A locked vault with no expected Store calls.
	store := &bwmock.Store{}
	vault := NewWalletVault(store, scriptWalletID, false)

	// Act: Decrypt the script.
	script, err := vault.DecryptScript(t.Context(), []byte("unknown output"))

	// Assert: The vault reports that it is locked.
	require.Nil(t, script)
	require.ErrorIs(t, err, ErrVaultLocked)
	require.ErrorContains(t, err, "wallet 7 vault DecryptScript")
	store.AssertNotCalled(t, "GetAddressSecret", mock.Anything, mock.Anything)
}

// TestWalletVaultDecryptScriptLockedDuringLookup verifies the second lock
// check and ciphertext cleanup when Lock runs after the initial check.
func TestWalletVaultDecryptScriptLockedDuringLookup(t *testing.T) {
	t.Parallel()

	// Arrange: Lock the vault during an otherwise successful Store lookup.
	store := &bwmock.Store{}
	vault := NewWalletVault(store, scriptWalletID, false)
	vault.unlockedState = makeUnlockedState(t)
	t.Cleanup(vault.Lock)

	encrypted, err := vault.unlockedState.cryptoKeyScript.Encrypt(
		[]byte("stored script"),
	)
	require.NoError(t, err)

	secret := &db.AddressSecret{EncryptedScript: encrypted}
	scriptPubKey := []byte("script pubkey selector")
	store.On("GetAddressSecret", mock.Anything, db.GetAddressSecretQuery{
		WalletID:     scriptWalletID,
		ScriptPubKey: scriptPubKey,
	}).Run(func(mock.Arguments) {
		require.True(t, vault.mtx.TryLock(), "Store called under guard")
		vault.mtx.Unlock()
		vault.Lock()
	}).Return(secret, nil).Once()

	// Act: Resolve a script whose key is cleared during the lookup.
	script, err := vault.DecryptScript(t.Context(), scriptPubKey)

	// Assert: The guarded check refuses decryption and clears ciphertext.
	require.Nil(t, script)
	require.ErrorIs(t, err, ErrVaultLocked)
	requireSecretZeroed(t, secret)
	store.AssertExpectations(t)
}

// TestWalletVaultDecryptScriptStoreError verifies that an unexpected Store
// failure is wrapped and not reported as a missing script.
func TestWalletVaultDecryptScriptStoreError(t *testing.T) {
	t.Parallel()

	// Arrange: A Store that fails the secret lookup.
	store := &bwmock.Store{}
	store.On("GetAddressSecret", mock.Anything, mock.Anything).Return(
		nil, errStoreUnavailable,
	).Once()

	vault := NewWalletVault(store, scriptWalletID, false)
	vault.unlockedState = makeUnlockedState(t)
	t.Cleanup(vault.Lock)

	// Act: Decrypt the script.
	script, err := vault.DecryptScript(t.Context(), []byte("selector"))

	// Assert: The Store error is kept and is not a missing script.
	require.Nil(t, script)
	require.ErrorIs(t, err, errStoreUnavailable)
	require.NotErrorIs(t, err, ErrScriptNotFound)
	store.AssertExpectations(t)
}

// TestWalletVaultDecryptScriptWrongKey verifies that ciphertext that the
// script key cannot open fails, and that the encrypted copy is cleared.
func TestWalletVaultDecryptScriptWrongKey(t *testing.T) {
	t.Parallel()

	// Arrange: Replace the stored ciphertext with one under another key.
	f := newScriptFixture(t, []byte("stored script"))
	otherKey, err := snacl.GenerateCryptoKey()
	require.NoError(t, err)

	f.secret.EncryptedScript, err = otherKey.Encrypt([]byte("other"))
	require.NoError(t, err)

	// Act: Decrypt the script.
	script, err := f.vault.DecryptScript(t.Context(), f.scriptPubKey)

	// Assert: Decryption fails without a script.
	require.Nil(t, script)
	require.ErrorIs(t, err, snacl.ErrDecryptFailed)
	require.ErrorContains(t, err, "decrypt script")
	requireSecretZeroed(t, f.secret)
}
