package keyvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"testing/synctest"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/snacl"
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

// keyFixture is an unlocked WalletVault over a mock Store, plus the account
// key the fixtures encrypt into that Store.
type keyFixture struct {
	vault   *WalletVault
	store   *bwmock.Store
	state   *unlockedState
	account *hdkeychain.ExtendedKey
}

// newKeyFixture returns an unlocked vault over a mock Store. The mock has
// no expectations, so any Store call a test does not program fails it.
func newKeyFixture(t *testing.T) *keyFixture {
	t.Helper()

	store := new(bwmock.Store)
	t.Cleanup(func() {
		store.AssertExpectations(t)
	})

	vault := NewWalletVault(store, testWalletID, false)
	state := makeUnlockedState(t)
	vault.unlockedState = state

	// Keep a copy of the private crypto key, because Lock clears the state
	// the vault holds.
	stateCopy := &unlockedState{cryptoKeyPrivate: state.cryptoKeyPrivate}

	account := state.hdRootKey
	for _, child := range []uint32{
		hdkeychain.HardenedKeyStart + testScope.Purpose,
		hdkeychain.HardenedKeyStart + testScope.Coin,
		hdkeychain.HardenedKeyStart,
	} {
		var err error

		account, err = account.Derive(child)
		require.NoError(t, err)
	}

	t.Cleanup(vault.Lock)

	return &keyFixture{
		vault:   vault,
		store:   store,
		state:   stateCopy,
		account: account,
	}
}

// encrypt encrypts plaintext under the vault's private crypto key.
func (f *keyFixture) encrypt(t *testing.T, plaintext []byte) []byte {
	t.Helper()

	ciphertext, err := f.state.cryptoKeyPrivate.Encrypt(plaintext)
	require.NoError(t, err)

	return ciphertext
}

// expectAccountSecret programs one account secret read and returns the
// ciphertext the Store hands out, so a test can check that it is cleared.
func (f *keyFixture) expectAccountSecret(t *testing.T,
	account uint32) []byte {

	t.Helper()

	ciphertext := f.encrypt(t, []byte(f.account.String()))
	f.store.On("GetAccountSecret", mock.Anything, db.GetAccountSecretQuery{
		WalletID:      testWalletID,
		Scope:         db.KeyScope(testScope),
		AccountNumber: account,
	}).Return(&db.AccountSecret{EncryptedPrivateKey: ciphertext}, nil).Once()

	return ciphertext
}

// expectImportedSecret programs one imported key read for testScriptPubKey
// and returns the ciphertext the Store hands out, so a test can check that it
// is cleared.
func (f *keyFixture) expectImportedSecret(t *testing.T,
	privKey []byte) []byte {

	t.Helper()

	ciphertext := f.encrypt(t, privKey)
	f.store.On("GetAddressSecret", mock.Anything, db.GetAddressSecretQuery{
		WalletID:     testWalletID,
		ScriptPubKey: testScriptPubKey,
	}).Return(&db.AddressSecret{EncryptedPrivKey: ciphertext}, nil).Once()

	return ciphertext
}

// leafKey returns the expected private key at branch/index of the fixture
// account.
func (f *keyFixture) leafKey(t *testing.T, branch,
	index uint32) *btcec.PrivateKey {

	t.Helper()

	branchKey, err := f.account.Derive(branch)
	require.NoError(t, err)

	leaf, err := branchKey.Derive(index)
	require.NoError(t, err)

	key, err := leaf.ECPrivKey()
	require.NoError(t, err)

	return key
}

// TestWalletVaultPubKey verifies that PubKey returns the public key of a
// hardened child, which an account XPub cannot derive, and of an imported key,
// and clears the Store ciphertext it read.
func TestWalletVaultPubKey(t *testing.T) {
	t.Parallel()

	// Arrange: Store the account key and pick a hardened branch and index.
	f := newKeyFixture(t)
	ciphertext := f.expectAccountSecret(t, 0)
	want := f.leafKey(
		t, hdkeychain.HardenedKeyStart+1, hdkeychain.HardenedKeyStart+7,
	)

	// Act: Derive the child's public key in the vault.
	pub, err := f.vault.PubKey(t.Context(), signing.DerivedKey{
		KeyScope: testScope,
		DerivationPath: waddrmgr.DerivationPath{
			Branch: hdkeychain.HardenedKeyStart + 1,
			Index:  hdkeychain.HardenedKeyStart + 7,
		},
	})

	// Assert: The vault returned the child's public key only.
	require.NoError(t, err)
	require.True(t, pub.IsEqual(want.PubKey()))
	require.Equal(t, make([]byte, len(ciphertext)), ciphertext)

	// Arrange: Store an imported key.
	imported := f.leafKey(t, 0, 3)
	ciphertext = f.expectImportedSecret(t, imported.Serialize())

	// Act: Ask for the import's public key.
	pub, err = f.vault.PubKey(t.Context(), testImportedKey)

	// Assert: The vault returned the import's public key only.
	require.NoError(t, err)
	require.True(t, pub.IsEqual(imported.PubKey()))
	require.Equal(t, make([]byte, len(ciphertext)), ciphertext)
}

// TestWalletVaultPubKeyLockedVault verifies that a locked vault refuses an
// invalid selector with ErrInvalidKeySelector and a valid one with
// ErrVaultLocked, both before any Store read.
func TestWalletVaultPubKeyLockedVault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     signing.KeySelector
		wantErr error
	}{
		{
			name:    "invalid selector while locked",
			key:     signing.ImportedKey{},
			wantErr: signing.ErrInvalidKeySelector,
		},
		{
			name:    "locked",
			key:     testImportedKey,
			wantErr: ErrVaultLocked,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: A locked vault. The mock Store has no
			// expectations, so any read fails the test.
			f := newKeyFixture(t)
			f.vault.Lock()

			// Act: Ask for the selected key's public key.
			pub, err := f.vault.PubKey(t.Context(), test.key)

			// Assert: The row's error and no key.
			require.ErrorIs(t, err, test.wantErr)
			require.Nil(t, pub)
		})
	}
}

// TestWalletVaultPubKeyLockedDuringLookup verifies that a Lock landing while
// PubKey reads the Store is still refused, by the lock check under the guard.
func TestWalletVaultPubKeyLockedDuringLookup(t *testing.T) {
	t.Parallel()

	// Arrange: An unlocked vault whose Store read locks the vault before it
	// returns the imported key.
	f := newKeyFixture(t)
	f.store.On("GetAddressSecret", mock.Anything, db.GetAddressSecretQuery{
		WalletID:     testWalletID,
		ScriptPubKey: testScriptPubKey,
	}).Run(func(mock.Arguments) {
		f.vault.Lock()
	}).Return(&db.AddressSecret{
		EncryptedPrivKey: f.encrypt(t, make([]byte, 32)),
	}, nil).Once()

	// Act: Ask for the import's public key.
	pub, err := f.vault.PubKey(t.Context(), testImportedKey)

	// Assert: The guarded phase found the vault locked.
	require.ErrorIs(t, err, ErrVaultLocked)
	require.Nil(t, pub)
}

// TestWalletVaultPubKeyMissingAccount verifies that an unlocked vault passes
// on the Store's error for an account it does not hold.
func TestWalletVaultPubKeyMissingAccount(t *testing.T) {
	t.Parallel()

	// Arrange: A Store without account 3.
	f := newKeyFixture(t)
	f.store.On("GetAccountSecret", mock.Anything, db.GetAccountSecretQuery{
		WalletID:      testWalletID,
		Scope:         db.KeyScope(testScope),
		AccountNumber: 3,
	}).Return(nil, db.ErrAccountNotFound).Once()

	// Act: Ask for a key of that account.
	pub, err := f.vault.PubKey(t.Context(), signing.DerivedKey{
		KeyScope:       testScope,
		DerivationPath: waddrmgr.DerivationPath{InternalAccount: 3},
	})

	// Assert: The Store's error and no key.
	require.ErrorIs(t, err, db.ErrAccountNotFound)
	require.Nil(t, pub)
}

// TestWalletVaultPubKeyWatchOnlyImport verifies that an import the Store holds
// without a private key, which it reports as db.ErrSecretNotFound, returns
// ErrNoPrivateKey.
func TestWalletVaultPubKeyWatchOnlyImport(t *testing.T) {
	t.Parallel()

	// Arrange: A Store that holds the script without a secret.
	f := newKeyFixture(t)
	f.store.On("GetAddressSecret", mock.Anything, db.GetAddressSecretQuery{
		WalletID:     testWalletID,
		ScriptPubKey: testScriptPubKey,
	}).Return(nil, db.ErrSecretNotFound).Once()

	// Act: Ask for the import's public key.
	pub, err := f.vault.PubKey(t.Context(), testImportedKey)

	// Assert: The import has no private key, and no key is returned.
	require.ErrorIs(t, err, ErrNoPrivateKey)
	require.ErrorIs(t, err, db.ErrSecretNotFound)
	require.Nil(t, pub)
}

// TestWalletVaultKeyUseClearsPlaintext verifies that the decrypted key
// material is cleared and the guard released whether the key use succeeds or
// fails. The guarded phase exposes its work buffers only to vault-owned code,
// so this test invokes that phase directly.
func TestWalletVaultKeyUseClearsPlaintext(t *testing.T) {
	t.Parallel()

	keyBytes := sha256.Sum256([]byte("cleanup key"))
	key, _ := btcec.PrivKeyFromBytes(keyBytes[:])
	errUse := errors.New("use failed")

	tests := []struct {
		name    string
		useErr  error
		wantErr error
	}{
		{
			name: "success",
		},
		{
			name:    "use error",
			useErr:  errUse,
			wantErr: errUse,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: An unlocked vault and a decryptor that hands
			// out a plaintext the test can inspect.
			f := newKeyFixture(t)
			plaintext := key.Serialize()

			// Act: Use the key.
			err := f.vault.useDecryptedKey(
				nil,
				func(*snacl.CryptoKey, []byte) ([]byte, error) {
					return plaintext, nil
				},
				parseImportedKey,
				func(*btcec.PrivateKey) error {
					return test.useErr
				},
			)

			// Assert: The use's error, plaintext is cleared and the
			// guard is free.
			require.ErrorIs(t, err, test.wantErr)
			require.Len(t, plaintext, btcec.PrivKeyBytesLen)
			require.Equal(t, make([]byte, len(plaintext)), plaintext)
			require.True(t, f.vault.mtx.TryLock())
			f.vault.mtx.Unlock()
		})
	}
}

// TestWalletVaultKeyUsePanicClearsPlaintext verifies that a key use that
// panics still clears the decrypted key material and releases the guard. The
// guarded phase exposes its work buffers only to vault-owned code, so this
// test invokes that phase directly.
func TestWalletVaultKeyUsePanicClearsPlaintext(t *testing.T) {
	t.Parallel()

	// Arrange: An unlocked vault, a decryptor that hands out a plaintext the
	// test can inspect, and a key use that panics.
	keyBytes := sha256.Sum256([]byte("cleanup key"))
	key, _ := btcec.PrivKeyFromBytes(keyBytes[:])
	f := newKeyFixture(t)
	plaintext := key.Serialize()

	use := func() {
		_ = f.vault.useDecryptedKey(
			nil,
			func(*snacl.CryptoKey, []byte) ([]byte, error) {
				return plaintext, nil
			},
			parseImportedKey,
			func(*btcec.PrivateKey) error {
				panic("use panic")
			},
		)
	}

	// Act and Assert: The panic reaches the caller.
	require.PanicsWithValue(t, "use panic", use)

	// Assert: Plaintext is cleared and the guard is free.
	require.Len(t, plaintext, btcec.PrivKeyBytesLen)
	require.Equal(t, make([]byte, len(plaintext)), plaintext)
	require.True(t, f.vault.mtx.TryLock())
	f.vault.mtx.Unlock()
}

// TestWalletVaultLockWaitsForKeyUse verifies that Lock waits for a key use
// that holds the guard, and that the next operation then reports
// ErrVaultLocked.
func TestWalletVaultLockWaitsForKeyUse(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		t.Helper()

		// Arrange: An unlocked vault and a key use that holds the
		// guard until the test releases it.
		f := newKeyFixture(t)
		key, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		defer key.Zero()

		plaintext := key.Serialize()
		entered := make(chan struct{})
		release := make(chan struct{})

		defer func() {
			select {
			case <-release:
			default:
				close(release)
			}
		}()

		// Act: Start a key use and wait until it holds the guard.
		used := make(chan error, 1)
		go func() {
			used <- f.vault.useDecryptedKey(
				nil,
				func(*snacl.CryptoKey, []byte) ([]byte, error) {
					return plaintext, nil
				},
				parseImportedKey,
				func(*btcec.PrivateKey) error {
					close(entered)
					<-release

					return nil
				},
			)
		}()

		<-entered

		// Assert: The key use holds the guard.
		free := f.vault.mtx.TryLock()
		if free {
			f.vault.mtx.Unlock()
		}

		require.False(t, free, "key use released the secret-use guard")

		// Act: Lock while the key use holds the guard, then release it.
		locked := make(chan bool, 1)
		go func() {
			f.vault.Lock()

			locked <- bytes.Equal(
				make([]byte, len(plaintext)), plaintext,
			)
		}()

		close(release)

		// Assert: Lock returned only after the key use cleared its
		// plaintext, and the next key use finds the vault locked.
		require.NoError(t, <-used)
		require.True(t, <-locked, "Lock returned before cleanup")

		_, err = f.vault.PubKey(t.Context(), testImportedKey)
		require.ErrorIs(t, err, ErrVaultLocked)
	})
}

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
// signing.ValidateKeySelector refuses, such as an import without a script, is
// refused without a Store read.
func TestLoadEncryptedKeyInvalidSelector(t *testing.T) {
	t.Parallel()

	// Arrange: A Store without expectations, so any read fails the test.
	store := new(bwmock.Store)

	// Act: Load a key through an import selector without a script.
	got, toKey, err := LoadEncryptedKey(
		t.Context(), store, testWalletID, signing.ImportedKey{},
	)

	// Assert: The selector is refused, nothing is returned and the Store
	// was not read.
	require.ErrorIs(t, err, signing.ErrInvalidKeySelector)
	require.Nil(t, got)
	require.Nil(t, toKey)
	store.AssertExpectations(t)
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
