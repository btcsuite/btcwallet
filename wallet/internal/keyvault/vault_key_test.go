package keyvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	bwmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/signing"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const testWalletID = uint32(11)

var (
	// testScope is the key scope used by the derived-key fixtures.
	testScope = waddrmgr.KeyScopeBIP0084

	// testScriptPubKey selects the imported-key fixtures.
	testScriptPubKey = []byte{0x00, 0x14, 0x01, 0x02}

	// testImportedKey selects the imported key stored for testScriptPubKey.
	testImportedKey = signing.ImportedKey{ScriptPubKey: testScriptPubKey}
)

// TestLoadEncryptedKeyDerived verifies that a DerivedKey loads its account's
// stored ciphertext and a toKey that derives the selected child from the
// decrypted account key.
func TestLoadEncryptedKeyDerived(t *testing.T) {
	t.Parallel()

	// Arrange: A Store holding the encrypted key of account 3, and the
	// expected child of the account key.
	seed := bytes.Repeat([]byte{0x2a}, hdkeychain.RecommendedSeedLen)
	account, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	require.NoError(t, err)

	branch, err := account.Derive(1)
	require.NoError(t, err)

	leaf, err := branch.Derive(7)
	require.NoError(t, err)

	want, err := leaf.ECPrivKey()
	require.NoError(t, err)

	ciphertext := []byte{1, 2, 3}
	store := new(bwmock.Store)
	store.On("GetAccountSecret", mock.Anything, db.GetAccountSecretQuery{
		WalletID:      testWalletID,
		Scope:         db.KeyScope(testScope),
		AccountNumber: 3,
	}).Return(&db.AccountSecret{EncryptedPrivateKey: ciphertext}, nil).Once()

	sel := signing.DerivedKey{
		KeyScope: testScope,
		DerivationPath: waddrmgr.DerivationPath{
			InternalAccount: 3,
			Branch:          1,
			Index:           7,
		},
	}

	// Act: Load the key, then turn the account key into the child.
	got, toKey, err := LoadEncryptedKey(
		t.Context(), store, testWalletID, sel,
	)
	require.NoError(t, err)

	key, err := toKey([]byte(account.String()))

	// Assert: The stored ciphertext and the selected child.
	require.NoError(t, err)
	require.Equal(t, ciphertext, got)
	require.Equal(t, want.Serialize(), key.Serialize())
	store.AssertExpectations(t)
}

// TestLoadEncryptedKeyImported verifies that an ImportedKey loads the stored
// ciphertext of the imported key, clears the encrypted script copy, and
// returns a toKey that parses the decrypted raw key.
func TestLoadEncryptedKeyImported(t *testing.T) {
	t.Parallel()

	// Arrange: A Store holding the imported key and a script copy.
	keyBytes := sha256.Sum256([]byte("imported key"))
	want, _ := btcec.PrivKeyFromBytes(keyBytes[:])

	secret := &db.AddressSecret{
		EncryptedPrivKey: []byte{1, 2, 3},
		EncryptedScript:  []byte{4, 5},
	}
	store := new(bwmock.Store)
	store.On("GetAddressSecret", mock.Anything, db.GetAddressSecretQuery{
		WalletID:     testWalletID,
		ScriptPubKey: testScriptPubKey,
	}).Return(secret, nil).Once()

	// Act: Load the key, then parse the raw key.
	got, toKey, err := LoadEncryptedKey(
		t.Context(), store, testWalletID, testImportedKey,
	)
	require.NoError(t, err)

	key, err := toKey(want.Serialize())

	// Assert: The stored ciphertext, no script copy left behind, and the
	// imported key.
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2, 3}, got)
	require.Equal(t, []byte{0, 0}, secret.EncryptedScript)
	require.Equal(t, want.Serialize(), key.Serialize())
	store.AssertExpectations(t)
}

// TestLoadEncryptedKeyDerivedErrors verifies that a watch-only account reports
// ErrNoPrivateKey, and that a failed account read keeps the Store's error
// identity and clears whatever the Store returned.
func TestLoadEncryptedKeyDerivedErrors(t *testing.T) {
	t.Parallel()

	query := db.GetAccountSecretQuery{
		WalletID:      testWalletID,
		Scope:         db.KeyScope(testScope),
		AccountNumber: 3,
	}
	sel := signing.DerivedKey{
		KeyScope:       testScope,
		DerivationPath: waddrmgr.DerivationPath{InternalAccount: 3},
	}

	tests := []struct {
		name    string
		secret  *db.AccountSecret
		readErr error
		wantErr error
	}{
		{
			name:    "watch-only account",
			secret:  &db.AccountSecret{},
			wantErr: ErrNoPrivateKey,
		},
		{
			name: "failed read",
			secret: &db.AccountSecret{
				EncryptedPrivateKey: []byte{1, 2, 3},
			},
			readErr: context.Canceled,
			wantErr: context.Canceled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: A Store that answers the account query.
			store := new(bwmock.Store)
			store.On("GetAccountSecret", mock.Anything, query).Return(
				test.secret, test.readErr,
			).Once()

			// Act: Load the account key.
			got, toKey, err := LoadEncryptedKey(
				t.Context(), store, testWalletID, sel,
			)

			// Assert: The row's error, nothing returned, and no
			// secret left behind.
			require.ErrorIs(t, err, test.wantErr)
			require.Nil(t, got)
			require.Nil(t, toKey)

			stored := test.secret.EncryptedPrivateKey
			require.Empty(t, bytes.TrimLeft(stored, "\x00"))
			store.AssertExpectations(t)
		})
	}
}

// TestLoadEncryptedKeyImportedErrors verifies that an import the Store holds
// with only its script reports ErrNoPrivateKey, that other Store errors keep
// their identity, and that whatever the Store returned is cleared.
func TestLoadEncryptedKeyImportedErrors(t *testing.T) {
	t.Parallel()

	query := db.GetAddressSecretQuery{
		WalletID:     testWalletID,
		ScriptPubKey: testScriptPubKey,
	}

	tests := []struct {
		name    string
		secret  *db.AddressSecret
		readErr error
		wantErr error
	}{
		{
			name: "script without private key",
			secret: &db.AddressSecret{
				EncryptedScript: []byte{4, 5},
			},
			wantErr: ErrNoPrivateKey,
		},
		{
			name:    "unknown script",
			readErr: db.ErrAddressNotFound,
			wantErr: db.ErrAddressNotFound,
		},
		{
			name: "failed read",
			secret: &db.AddressSecret{
				EncryptedPrivKey: []byte{1, 2, 3},
				EncryptedScript:  []byte{4, 5},
			},
			readErr: context.Canceled,
			wantErr: context.Canceled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: A Store that answers the script query.
			store := new(bwmock.Store)
			store.On("GetAddressSecret", mock.Anything, query).Return(
				test.secret, test.readErr,
			).Once()

			// Act: Load the imported key.
			got, toKey, err := LoadEncryptedKey(
				t.Context(), store, testWalletID, testImportedKey,
			)

			// Assert: The row's error, nothing returned, and no
			// secret left behind.
			require.ErrorIs(t, err, test.wantErr)
			require.Nil(t, got)
			require.Nil(t, toKey)

			stored := addressSecretBytes(test.secret)
			require.Empty(t, bytes.TrimLeft(stored, "\x00"))
			store.AssertExpectations(t)
		})
	}
}

// addressSecretBytes returns a copy of the encrypted bytes of secret, nil for
// a nil secret, so a test can check that they were cleared.
func addressSecretBytes(secret *db.AddressSecret) []byte {
	if secret == nil {
		return nil
	}

	stored := append([]byte{}, secret.EncryptedPrivKey...)

	return append(stored, secret.EncryptedScript...)
}

// TestLoadEncryptedKeyInvalidSelector verifies that a selector
// signing.ValidateKeySelector refuses, whether a pointer or an import without
// a script, is refused without a Store read.
func TestLoadEncryptedKeyInvalidSelector(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sel  signing.KeySelector
	}{
		{
			name: "imported pointer",
			sel:  &signing.ImportedKey{ScriptPubKey: testScriptPubKey},
		},
		{
			name: "empty import script",
			sel:  signing.ImportedKey{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: A Store without expectations, so any read
			// fails the test.
			store := new(bwmock.Store)

			// Act: Load a key through the selector.
			got, toKey, err := LoadEncryptedKey(
				t.Context(), store, testWalletID, test.sel,
			)

			// Assert: The selector is refused, nothing is returned
			// and the Store was not read.
			require.ErrorIs(t, err, signing.ErrInvalidKeySelector)
			require.Nil(t, got)
			require.Nil(t, toKey)
			store.AssertExpectations(t)
		})
	}
}

// TestParseImportedKeyRejects verifies that a decrypted imported key is refused
// unless it is a 32-byte scalar in [1, N-1].
func TestParseImportedKeyRejects(t *testing.T) {
	t.Parallel()

	keyBytes := sha256.Sum256([]byte("imported key"))

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "short key",
			plaintext: keyBytes[1:],
		},
		{
			name:      "zero key",
			plaintext: make([]byte, btcec.PrivKeyBytesLen),
		},
		{
			name: "overflowing key",
			plaintext: bytes.Repeat(
				[]byte{0xff}, btcec.PrivKeyBytesLen,
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Act: Parse the plaintext.
			key, err := parseImportedKey(test.plaintext)

			// Assert: The key is refused.
			require.ErrorIs(t, err, errUnexpectedState)
			require.Nil(t, key)
		})
	}
}
