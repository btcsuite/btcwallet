// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr

import (
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// TestAccountSecretDerived verifies that AccountSecret returns the persisted
// encrypted private key of a normal derived (default) account, as a
// caller-owned copy, and nothing else.
func TestAccountSecretDerived(t *testing.T) {
	t.Parallel()

	// Arrange: a created, unlocked manager and its BIP0044 scoped manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	scopedMgr := fetchBIP44Scoped(t, mgr)

	var (
		gotEnc       []byte
		expectedPriv *hdkeychain.ExtendedKey
	)

	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		// Unlock so we can decrypt the returned ciphertext for
		// verification, then read the account secret.
		err := mgr.Unlock(ns, privPassphrase)
		if err != nil {
			return err
		}

		gotEnc, err = assertCiphertextCopy(t, func() ([]byte, error) {
			return scopedMgr.AccountSecret(ns, DefaultAccountNum)
		})
		if err != nil {
			return err
		}

		// Derive the expected account private key straight from the
		// seed for cross-checking the returned ciphertext.
		expectedPriv = deriveTestAccountPrivKey(t)

		return nil
	})
	require.NoError(t, err)

	// Assert: a non-nil ciphertext that is a caller-owned copy.
	require.NotNil(t, gotEnc)
	require.NotEmpty(t, gotEnc)

	// Assert: decrypting the returned ciphertext with the crypto private
	// key yields the expected account private key. This proves the stored
	// ciphertext was returned verbatim (and never re-derived).
	mgr.mtx.RLock()
	serialized, err := mgr.cryptoKeyPriv.Decrypt(gotEnc)
	mgr.mtx.RUnlock()
	require.NoError(t, err)
	require.Equal(t, expectedPriv.String(), string(serialized))
}

// TestAccountSecretWatchOnly verifies that AccountSecret returns a nil
// encrypted private key for a watch-only imported account, which holds none.
func TestAccountSecretWatchOnly(t *testing.T) {
	t.Parallel()

	// Arrange: a created manager and its BIP0044 scoped manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	scopedMgr := fetchBIP44Scoped(t, mgr)

	// Import a watch-only account with a known fingerprint.
	acctKey := deriveTestAccountKey(t)
	require.NotNil(t, acctKey)

	acctKeyPub, err := acctKey.Neuter()
	require.NoError(t, err)

	const wantFingerprint = uint32(0xdeadbeef)

	var account uint32

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		account, err = scopedMgr.NewAccountWatchingOnly(
			ns, "watch-only", acctKeyPub, wantFingerprint, nil,
		)

		return err
	})
	require.NoError(t, err)

	// Act: read the account secret for the watch-only account.
	var gotEnc []byte

	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)

		gotEnc, err = scopedMgr.AccountSecret(ns, account)

		return err
	})
	require.NoError(t, err)

	// Assert: a watch-only account exposes no private key.
	require.Nil(t, gotEnc)
}

// TestAccountSecretNotFound verifies that AccountSecret returns
// ErrAccountNotFound for an account that does not exist.
func TestAccountSecretNotFound(t *testing.T) {
	t.Parallel()

	// Arrange: a created manager and its BIP0044 scoped manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	scopedMgr := fetchBIP44Scoped(t, mgr)

	// Act: read a non-existent account.
	err := walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)

		_, err := scopedMgr.AccountSecret(ns, 9999)

		return err
	})

	// Assert: the account-not-found error is returned.
	require.True(
		t, checkManagerError(t, "missing account", err,
			ErrAccountNotFound),
	)
}

// TestManagedAddressSecretPubKey verifies that ManagedAddressSecret returns the
// stored encrypted private key (and no script) for an imported pubkey address.
func TestManagedAddressSecretPubKey(t *testing.T) {
	t.Parallel()

	// Arrange: a created, unlocked manager and its BIP0044 scoped manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	scopedMgr := fetchBIP44Scoped(t, mgr)

	// A fixed private key we can import and later cross-check.
	privKeyBytes := hexToBytes(
		"c27d6581b92785834b381fa697c4b0ff" +
			"c4574b495743722e0acb7601b1b68b99",
	)
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	require.NoError(t, err)

	var (
		importedAddr address.Address
		gotPriv      []byte
		gotScript    []byte
		gotSecret    bool
	)

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		err := mgr.Unlock(ns, privPassphrase)
		if err != nil {
			return err
		}

		managed, err := scopedMgr.ImportPrivateKey(
			ns, wif, &BlockStamp{},
		)
		if err != nil {
			return err
		}

		importedAddr = managed.Address()

		// Act: read the address secret twice through the copy
		// assertion, so an aliased buffer would be caught here.
		gotPriv, err = assertCiphertextCopy(t, func() ([]byte, error) {
			priv, script, secret, err := scopedMgr.
				ManagedAddressSecret(ns, importedAddr)
			gotScript, gotSecret = script, secret

			return priv, err
		})

		return err
	})
	require.NoError(t, err)

	// Assert: a private-key ciphertext is returned and no script, so the
	// script-secrecy flag is false.
	require.NotEmpty(t, gotPriv)
	require.Nil(t, gotScript)
	require.False(t, gotSecret)

	// Assert: the ciphertext decrypts to the imported private key.
	mgr.mtx.RLock()
	serialized, err := mgr.cryptoKeyPriv.Decrypt(gotPriv)
	mgr.mtx.RUnlock()
	require.NoError(t, err)
	require.Equal(t, privKeyBytes, serialized)
}

// TestManagedAddressSecretScript verifies that ManagedAddressSecret returns the
// stored encrypted script (and no private key) for an imported script address.
func TestManagedAddressSecretScript(t *testing.T) {
	t.Parallel()

	// Arrange: a created, unlocked manager and its BIP0044 scoped manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	scopedMgr := fetchBIP44Scoped(t, mgr)

	script := hexToBytes(
		"51210373c717acd6b1d4c9d92e5c5c6c62c1c1c1c1c1c1c1c1c1c1c1c1c" +
			"1c1c1c1c1c151ae",
	)

	var (
		importedAddr address.Address
		gotPriv      []byte
		gotScript    []byte
		gotSecret    bool
	)

	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

		err := mgr.Unlock(ns, privPassphrase)
		if err != nil {
			return err
		}

		managed, err := scopedMgr.ImportScript(
			ns, script, &BlockStamp{},
		)
		if err != nil {
			return err
		}

		importedAddr = managed.Address()

		// Act: read the address secret twice through the copy
		// assertion, so an aliased buffer would be caught here.
		gotScript, err = assertCiphertextCopy(
			t, func() ([]byte, error) {
				priv, script, secret, err := scopedMgr.
					ManagedAddressSecret(ns, importedAddr)
				gotPriv, gotSecret = priv, secret

				return script, err
			},
		)

		return err
	})
	require.NoError(t, err)

	// Assert: a script ciphertext is returned and no private key.
	// ImportScript stores a P2SH redeem script, which is always secret, so
	// the flag is set.
	require.Nil(t, gotPriv)
	require.NotEmpty(t, gotScript)
	require.True(t, gotSecret)

	// Assert: the ciphertext decrypts to the imported script under the
	// script crypto key, matching the reported secrecy.
	mgr.mtx.RLock()
	serialized, err := mgr.cryptoKeyScript.Decrypt(gotScript)
	mgr.mtx.RUnlock()
	require.NoError(t, err)
	require.Equal(t, script, serialized)
}

// TestManagedAddressSecretNotFound verifies that ManagedAddressSecret returns
// the not-found error for an address that was never added to the manager,
// keeping it distinguishable from a found-but-secretless address.
func TestManagedAddressSecretNotFound(t *testing.T) {
	t.Parallel()

	// Arrange: a created manager and its BIP0044 scoped manager.
	teardown, db, mgr := setupManager(t)
	t.Cleanup(teardown)

	scopedMgr := fetchBIP44Scoped(t, mgr)

	// A valid P2PKH address that was never imported.
	unknown, err := address.NewAddressPubKeyHash(
		hexToBytes("0000000000000000000000000000000000000000"),
		&chaincfg.MainNetParams,
	)
	require.NoError(t, err)

	// Act: look up the unknown address.
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)

		_, _, _, err := scopedMgr.ManagedAddressSecret(ns, unknown)

		return err
	})

	// Assert: the address-not-found error is returned.
	require.True(
		t, checkManagerError(t, "missing address", err,
			ErrAddressNotFound),
	)
}

// assertCiphertextCopy reads a ciphertext twice through read, mutating the
// first result in place between reads. If read returns an independent copy the
// mutation cannot reach the second read, so the two results differ and the
// second is returned for any further assertions. A returned alias would make
// the two results the same mutated buffer.
func assertCiphertextCopy(t *testing.T, read func() ([]byte, error)) ([]byte,
	error) {

	t.Helper()

	first, err := read()
	if err != nil {
		return nil, err
	}

	require.NotEmpty(t, first)

	for i := range first {
		first[i] ^= 0xff
	}

	second, err := read()
	if err != nil {
		return nil, err
	}

	require.NotEqual(t, first, second)

	return second, nil
}

// fetchBIP44Scoped is a small helper that returns the concrete BIP0044 scoped
// key manager for the given root manager.
func fetchBIP44Scoped(t *testing.T, mgr *Manager) *ScopedKeyManager {
	t.Helper()

	acctStore, err := mgr.FetchScopedKeyManager(KeyScopeBIP0044)
	require.NoError(t, err)

	scopedMgr, ok := acctStore.(*ScopedKeyManager)
	require.True(t, ok)

	return scopedMgr
}

// deriveTestAccountPrivKey derives the default BIP0044 account extended private
// key straight from the test seed so tests can cross-check the ciphertext
// returned by AccountSecret.
func deriveTestAccountPrivKey(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()

	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	require.NoError(t, err)

	scopeKey, err := deriveCoinTypeKey(masterKey, KeyScopeBIP0044)
	require.NoError(t, err)

	accountKey, err := deriveAccountKey(scopeKey, 0)
	require.NoError(t, err)

	return accountKey
}
