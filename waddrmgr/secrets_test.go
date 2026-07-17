// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/stretchr/testify/require"
)

// secretsTestSeed is a fixed BIP-32 seed the secret-core tests build a master
// key from, so the prepared material is deterministic.
var secretsTestSeed = []byte{
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
	0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
}

var (
	secretsPubPass  = []byte("public-passphrase")
	secretsPrivPass = []byte("private-passphrase")
)

// secretsRootKey returns the deterministic master node the secret-core tests
// derive from.
func secretsRootKey(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()

	root, err := hdkeychain.NewMaster(secretsTestSeed, &chaincfg.MainNetParams)
	require.NoError(t, err)

	return root
}

// TestPrepareWalletSecrets proves the create-time preparation produces the
// manager root state and one default scope entry per requested scope, each with
// encrypted coin-type and account key material and no allocated account.
func TestPrepareWalletSecrets(t *testing.T) {
	t.Parallel()

	root := secretsRootKey(t)
	scopes := []KeyScope{KeyScopeBIP0084, KeyScopeBIP0086}

	secrets, err := PrepareWalletSecrets(
		root, secretsPubPass, secretsPrivPass, &FastScryptOptions, scopes,
	)
	require.NoError(t, err)

	// The manager root carries every master parameter and encrypted key.
	require.Equal(t, LatestMgrVersion, secrets.Manager.Version)
	require.False(t, secrets.Manager.WatchOnly)
	require.NotEmpty(t, secrets.Manager.MasterPubParams)
	require.NotEmpty(t, secrets.Manager.MasterPrivParams)
	require.NotEmpty(t, secrets.Manager.EncryptedCryptoPubKey)
	require.NotEmpty(t, secrets.Manager.EncryptedCryptoPrivKey)
	require.NotEmpty(t, secrets.Manager.EncryptedCryptoScriptKey)
	require.NotEmpty(t, secrets.Manager.EncryptedMasterHDPubKey)
	require.NotEmpty(t, secrets.Manager.EncryptedMasterHDPrivKey)

	// One default scope entry per requested scope, each idempotent-ready with
	// the absent-account sentinel and a default account zero.
	require.Len(t, secrets.Scopes, len(scopes))
	for i, scope := range scopes {
		entry := secrets.Scopes[i]
		require.Equal(t, scope, entry.State.Scope)
		require.Equal(t, ScopeAddrMap[scope], entry.State.AddrSchema)
		require.Equal(t, NoAccountAllocated, entry.State.LastAccount)
		require.NotEmpty(t, entry.State.EncryptedCoinPubKey)
		require.NotEmpty(t, entry.State.EncryptedCoinPrivKey)

		require.Equal(t, uint32(DefaultAccountNum), entry.Account.Account)
		require.Equal(t, AccountDefault, entry.Account.Type)
		require.Equal(t, defaultAccountName, entry.Account.Name)
		require.NotEmpty(t, entry.Account.EncryptedPubKey)
		require.NotEmpty(t, entry.Account.EncryptedPrivKey)
	}
}

// TestPrepareWalletSecretsRejectsWatchOnly proves a nil root key and an empty
// private passphrase are rejected, since this minimal path is not watch-only.
func TestPrepareWalletSecretsRejectsWatchOnly(t *testing.T) {
	t.Parallel()

	_, err := PrepareWalletSecrets(
		nil, secretsPubPass, secretsPrivPass, &FastScryptOptions,
		[]KeyScope{KeyScopeBIP0084},
	)
	require.True(t, IsError(err, ErrWatchingOnly))

	_, err = PrepareWalletSecrets(
		secretsRootKey(t), secretsPubPass, nil, &FastScryptOptions,
		[]KeyScope{KeyScopeBIP0084},
	)
	require.True(t, IsError(err, ErrEmptyPassphrase))
}

// TestManagerKeyringAccountKey proves the secret core reconstructed from
// durable state decrypts the account extended key: the public key while locked,
// the private key after unlock, and that both project to the same account
// identity a direct derivation from the root produces.
func TestManagerKeyringAccountKey(t *testing.T) {
	t.Parallel()

	root := secretsRootKey(t)
	scope := KeyScopeBIP0084

	secrets, err := PrepareWalletSecrets(
		root, secretsPubPass, secretsPrivPass, &FastScryptOptions,
		[]KeyScope{scope},
	)
	require.NoError(t, err)

	account := secrets.Scopes[0].Account

	// Independently derive the expected account key from the root.
	coinTypeKey, err := deriveCoinTypeKey(root, scope)
	require.NoError(t, err)
	wantAcctPriv, err := deriveAccountKey(coinTypeKey, 0)
	require.NoError(t, err)
	wantAcctPub, err := wantAcctPriv.Neuter()
	require.NoError(t, err)

	keyring, err := OpenManagerKeyring(
		secrets.Manager, secretsPubPass, &chaincfg.MainNetParams,
	)
	require.NoError(t, err)
	require.True(t, keyring.IsLocked())
	require.False(t, keyring.WatchOnly())

	// While locked, the account key is the public extended key.
	lockedKey, err := keyring.AccountKey(account)
	require.NoError(t, err)
	require.False(t, lockedKey.IsPrivate())
	require.Equal(t, wantAcctPub.String(), lockedKey.String())

	// After unlock, the account key is the private extended key, and its
	// neutered form matches the same public identity.
	require.NoError(t, keyring.Unlock(secretsPrivPass))
	require.False(t, keyring.IsLocked())

	unlockedKey, err := keyring.AccountKey(account)
	require.NoError(t, err)
	require.True(t, unlockedKey.IsPrivate())
	require.Equal(t, wantAcctPriv.String(), unlockedKey.String())

	neutered, err := unlockedKey.Neuter()
	require.NoError(t, err)
	require.Equal(t, wantAcctPub.String(), neutered.String())

	// Locking again falls back to the public key.
	keyring.Lock()
	require.True(t, keyring.IsLocked())

	relockedKey, err := keyring.AccountKey(account)
	require.NoError(t, err)
	require.False(t, relockedKey.IsPrivate())
	require.Equal(t, wantAcctPub.String(), relockedKey.String())
}

// TestManagerKeyringWrongPassphrase proves a wrong public passphrase fails the
// open and a wrong private passphrase fails the unlock with the typed error.
func TestManagerKeyringWrongPassphrase(t *testing.T) {
	t.Parallel()

	secrets, err := PrepareWalletSecrets(
		secretsRootKey(t), secretsPubPass, secretsPrivPass, &FastScryptOptions,
		[]KeyScope{KeyScopeBIP0084},
	)
	require.NoError(t, err)

	_, err = OpenManagerKeyring(
		secrets.Manager, []byte("wrong-public"), &chaincfg.MainNetParams,
	)
	require.True(t, IsError(err, ErrWrongPassphrase))

	keyring, err := OpenManagerKeyring(
		secrets.Manager, secretsPubPass, &chaincfg.MainNetParams,
	)
	require.NoError(t, err)

	err = keyring.Unlock([]byte("wrong-private"))
	require.True(t, IsError(err, ErrWrongPassphrase))
	require.True(t, keyring.IsLocked())
}

// TestManagerKeyringDerivesAddresses proves the reconstructed account key
// drives the shared chained-address derivation, so the secret core is a
// complete derivation source for the SQL wallet lifecycle.
func TestManagerKeyringDerivesAddresses(t *testing.T) {
	t.Parallel()

	scope := KeyScopeBIP0084

	secrets, err := PrepareWalletSecrets(
		secretsRootKey(t), secretsPubPass, secretsPrivPass,
		&FastScryptOptions, []KeyScope{scope},
	)
	require.NoError(t, err)

	keyring, err := OpenManagerKeyring(
		secrets.Manager, secretsPubPass, &chaincfg.MainNetParams,
	)
	require.NoError(t, err)

	acctKey, err := keyring.AccountKey(secrets.Scopes[0].Account)
	require.NoError(t, err)

	addrs, next, err := DeriveChainedAddresses(
		acctKey, ExternalBranch, WitnessPubKey, &chaincfg.MainNetParams, 0, 2,
	)
	require.NoError(t, err)
	require.Len(t, addrs, 2)
	require.Equal(t, uint32(2), next)
	require.NotEmpty(t, addrs[0].AddressID)
	require.NotEqual(t, addrs[0].AddressID, addrs[1].AddressID)
}
