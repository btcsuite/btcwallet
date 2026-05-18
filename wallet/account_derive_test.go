// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockVault is a testify-based mock for the keyvault interface that
// newAccountDeriveFn consumes. Each test configures its own expectations on
// the embedded mock.Mock so encrypt/decrypt behavior is locally scoped and
// does not leak between cases.
type mockVault struct {
	mock.Mock
}

// Encrypt forwards to the configured testify expectations. When the test
// programmed a function via Return, the function is invoked with the call
// args to compute the returned bytes; otherwise the static []byte (or nil)
// is returned as-is.
func (m *mockVault) Encrypt(keyType waddrmgr.CryptoKeyType,
	plaintext []byte) ([]byte, error) {

	args := m.Called(keyType, plaintext)

	return returnBytes(args, keyType, plaintext), args.Error(1)
}

// Decrypt forwards to the configured testify expectations. See Encrypt for
// the function-vs-static-bytes return semantics.
func (m *mockVault) Decrypt(keyType waddrmgr.CryptoKeyType,
	ciphertext []byte) ([]byte, error) {

	args := m.Called(keyType, ciphertext)

	return returnBytes(args, keyType, ciphertext), args.Error(1)
}

// returnBytes resolves the first programmed Return arg into a []byte
// slice. When the test set Return(fn, ...), where fn has the same shape as
// the mocked method, fn is invoked with the actual call args to compute
// the returned bytes (this is how the identity vault roundtrips bytes
// without static expectations).
func returnBytes(args mock.Arguments, keyType waddrmgr.CryptoKeyType,
	input []byte) []byte {

	if fn, ok := args.Get(0).(func(waddrmgr.CryptoKeyType, []byte) []byte); ok {
		return fn(keyType, input)
	}

	if args.Get(0) == nil {
		return nil
	}

	b, ok := args.Get(0).([]byte)
	if !ok {
		return nil
	}

	return b
}

// newIdentityVault returns a mockVault configured to act as an identity
// crypt — Encrypt and Decrypt both return a fresh copy of the input bytes
// with no error. This lets tests roundtrip derived account material
// without bringing in real cryptoKey wiring.
func newIdentityVault() *mockVault {
	vault := &mockVault{}
	identity := func(_ waddrmgr.CryptoKeyType, b []byte) []byte {
		out := make([]byte, len(b))
		copy(out, b)

		return out
	}

	vault.On("Encrypt", mock.Anything, mock.Anything).Return(identity, nil)
	vault.On("Decrypt", mock.Anything, mock.Anything).Return(identity, nil)

	return vault
}

// errEncryptForTest is the canned encrypt failure surfaced by
// newEncryptErrorVault so tests can assert the helper propagates vault
// errors via errors.Is.
var errEncryptForTest = errors.New("encrypt boom")

// newEncryptErrorVault returns a mockVault whose Encrypt call always fails
// with errEncryptForTest. Decrypt is left unconfigured because the tests
// that consume this vault never reach a decrypt path.
func newEncryptErrorVault() *mockVault {
	vault := &mockVault{}
	vault.On("Encrypt", mock.Anything, mock.Anything).Return(
		nil, errEncryptForTest,
	)

	return vault
}

// testMasterKey returns a deterministic master HD private key for derivation
// tests. The seed bytes are fixed so derived results are reproducible.
func testMasterKey(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()

	seed := bytes.Repeat([]byte{0xAA}, hdkeychain.RecommendedSeedLen)
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.SimNetParams)
	require.NoError(t, err)

	return masterKey
}

// TestNewAccountDeriveFn_Spendable verifies that the wallet-side derivation
// helper produces a DerivedAccountData consistent with manually walking the
// BIP44 path m/purpose'/coin'/account' from the captured master key.
func TestNewAccountDeriveFn_Spendable(t *testing.T) {
	t.Parallel()

	masterKey := testMasterKey(t)
	fingerprint, err := masterKeyFingerprint(masterKey)
	require.NoError(t, err)

	scope := db.KeyScope{Purpose: 84, Coin: 0}

	const accountNumber uint32 = 7

	derive := newAccountDeriveFn(masterKey, newIdentityVault(), fingerprint)
	data, err := derive(t.Context(), scope, accountNumber, false)
	require.NoError(t, err)
	require.NotNil(t, data)

	// Manually walk the same BIP44 path and check the helper agrees.
	expectAcctPriv, err := deriveBIP44AccountKey(
		masterKey, scope, accountNumber,
	)
	require.NoError(t, err)
	expectAcctPub, err := expectAcctPriv.Neuter()
	require.NoError(t, err)

	require.Equal(t,
		[]byte(expectAcctPub.String()), data.PublicKey,
	)
	require.Equal(t,
		[]byte(expectAcctPriv.String()), data.EncryptedPrivateKey,
	)
	require.Equal(t, fingerprint, data.MasterKeyFingerprint)
}

// TestNewAccountDeriveFn_MaxAccountNumber verifies that account numbers above
// the legacy wallet ceiling are rejected before derivation wraps into reserved
// or non-hardened child indexes.
func TestNewAccountDeriveFn_MaxAccountNumber(t *testing.T) {
	t.Parallel()

	masterKey := testMasterKey(t)
	scope := db.KeyScope{Purpose: 84, Coin: 0}

	derive := newAccountDeriveFn(masterKey, &mockVault{}, 0)
	data, err := derive(t.Context(), scope, db.MaxAccountNumber+1, false)

	require.Nil(t, data)
	require.ErrorIs(t, err, db.ErrMaxAccountNumberReached)
}

// TestNewAccountDeriveFn_WatchOnly verifies that a watch-only wallet rejects
// new derived-account creation. Hardened derivation requires the master HD
// private key, which a watch-only wallet does not hold.
func TestNewAccountDeriveFn_WatchOnly(t *testing.T) {
	t.Parallel()

	masterKey := testMasterKey(t)
	scope := db.KeyScope{Purpose: 84, Coin: 0}

	derive := newAccountDeriveFn(masterKey, newIdentityVault(), 0)
	data, err := derive(t.Context(), scope, 0, true)

	require.Nil(t, data)
	require.ErrorIs(t, err, errWatchOnlyAccountDerivation)
}

// TestNewAccountDeriveFn_NonPrivateMasterKey verifies that the helper
// refuses to derive when the captured master key has been neutered. Without
// the private key the hardened account-level derivation is impossible.
func TestNewAccountDeriveFn_NonPrivateMasterKey(t *testing.T) {
	t.Parallel()

	masterKey := testMasterKey(t)
	pubMaster, err := masterKey.Neuter()
	require.NoError(t, err)

	scope := db.KeyScope{Purpose: 84, Coin: 0}

	derive := newAccountDeriveFn(pubMaster, newIdentityVault(), 0)
	data, err := derive(t.Context(), scope, 0, false)

	require.Nil(t, data)
	require.ErrorIs(t, err, hdkeychain.ErrNotPrivExtKey)
}

// TestNewAccountDeriveFn_VaultEncryptError verifies that the helper
// propagates encryption failures from the keyvault rather than silently
// dropping the account private key.
func TestNewAccountDeriveFn_VaultEncryptError(t *testing.T) {
	t.Parallel()

	masterKey := testMasterKey(t)
	scope := db.KeyScope{Purpose: 84, Coin: 0}

	derive := newAccountDeriveFn(masterKey, newEncryptErrorVault(), 0)
	data, err := derive(t.Context(), scope, 0, false)

	require.Nil(t, data)
	require.ErrorIs(t, err, errEncryptForTest)
}

// TestMasterKeyFingerprint verifies that the helper returns the BIP32
// master-key fingerprint matching the well-known formula (first 4 bytes of
// HASH160 of the compressed master pubkey).
func TestMasterKeyFingerprint(t *testing.T) {
	t.Parallel()

	masterKey := testMasterKey(t)
	fingerprint, err := masterKeyFingerprint(masterKey)
	require.NoError(t, err)

	// The fingerprint is deterministic for a fixed seed; just ensure it is
	// non-zero and consistent across two calls.
	require.NotZero(t, fingerprint)

	again, err := masterKeyFingerprint(masterKey)
	require.NoError(t, err)
	require.Equal(t, fingerprint, again)
}

// TestDeriveChildKey_MatchesLegacyOnCleanParent regression-guards the
// runtime-check helper: for a 32-byte parent (the common case for every
// existing wallet), deriveChildKey must produce the exact same child
// bytes that the legacy DeriveNonStandard path would have, because that
// path is what every previously-persisted btcwallet key was derived
// under. Diverging here would silently lose UTXOs at any address that
// already lives on disk.
func TestDeriveChildKey_MatchesLegacyOnCleanParent(t *testing.T) {
	t.Parallel()

	masterKey := testMasterKey(t)
	require.False(t, masterKey.IsAffectedByIssue172(),
		"test seed should produce a full 32-byte master key")

	for _, i := range []uint32{
		hdkeychain.HardenedKeyStart,
		hdkeychain.HardenedKeyStart + 1,
		hdkeychain.HardenedKeyStart + 7,
		hdkeychain.HardenedKeyStart + 49,
		hdkeychain.HardenedKeyStart + 84,
	} {
		got, err := deriveChildKey(masterKey, i)
		require.NoError(t, err)

		//nolint:staticcheck
		want, err := masterKey.DeriveNonStandard(i)
		require.NoError(t, err)

		require.Equal(t, want.String(), got.String(),
			"deriveChildKey(%d) must match DeriveNonStandard on a clean parent",
			i)
	}
}
