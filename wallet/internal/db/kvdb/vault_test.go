package kvdb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btclog"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
	"github.com/btcsuite/btcwallet/wallet/internal/signing"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestLegacyWalletVaultChangePassphraseValidatesBeforeContext verifies that
// invalid parameters retain their identity and operation context even when the
// request context is already canceled.
func TestLegacyWalletVaultChangePassphraseValidatesBeforeContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	vault := &LegacyWalletVault{}
	err := vault.ChangePassphrase(ctx, keyvault.ChangePassphraseParams{
		PrivateOld: []byte("wrong-private-passphrase"),
		PrivateNew: []byte{},
	})
	require.ErrorIs(t, err, keyvault.ErrEmptyPassphrase)
	require.ErrorContains(t, err, "vault ChangePassphrase")
}

// TestLegacyWalletVaultDecryptScriptNotImplemented verifies that the legacy
// vault refuses the typed script operation, so the Wallet keeps its kvdb
// Store-and-Decrypt path.
func TestLegacyWalletVaultDecryptScriptNotImplemented(t *testing.T) {
	t.Parallel()

	vault := &LegacyWalletVault{}
	script, err := vault.DecryptScript(t.Context(), []byte("script pubkey"))
	require.Nil(t, script)
	require.ErrorIs(t, err, keyvault.ErrNotImplemented)
}

// TestLegacyWalletVaultECDH verifies that the legacy vault computes the same
// secret the peer derives from the wallet's public key, so kvdb ECDH no longer
// needs a Wallet-side private key.
func TestLegacyWalletVaultECDH(t *testing.T) {
	t.Parallel()

	// Arrange: An unlocked legacy vault, the public key at m/84'/1'/0'/0/1
	// read from the account xpub, and a peer key.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	mgr := newSpendableAddrMgr(t, dbConn)
	vault := NewLegacyWalletVault(dbConn, mgr)
	require.NoError(t, vault.Unlock(t.Context(), testPrivPass))
	t.Cleanup(vault.Lock)

	path := waddrmgr.DerivationPath{Branch: 0, Index: 1}
	walletPub := legacyAccountChildPubKey(
		t, dbConn, mgr, waddrmgr.KeyScopeBIP0084, path,
	)

	peer, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	// Act: Compute the shared secret with the wallet key.
	got, err := vault.ECDH(
		t.Context(), waddrmgr.KeyScopeBIP0084, path, peer.PubKey(),
	)

	// Assert: The peer computes the same secret from the public key.
	require.NoError(t, err)
	require.Equal(t, keyvault.ECDHSecret(peer, walletPub), got)
}

// TestLegacyWalletVaultECDHErrors verifies the error identities the Wallet
// maps to its public ECDH errors, in the order the SQL vault reports them.
func TestLegacyWalletVaultECDHErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		account   uint32
		unlock    bool
		nilRemote bool
		wantErr   error
	}{
		{
			name:      "invalid remote",
			unlock:    true,
			nilRemote: true,
			wantErr:   keyvault.ErrInvalidRemoteKey,
		},
		{
			name:    "missing account while locked",
			account: 99,
			wantErr: db.ErrAccountNotFound,
		},
		{
			name:    "locked",
			wantErr: keyvault.ErrVaultLocked,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: A legacy vault in the row's lock state.
			dbConn, cleanup := newTestDB(t)
			t.Cleanup(cleanup)

			mgr := newSpendableAddrMgr(t, dbConn)
			vault := NewLegacyWalletVault(dbConn, mgr)

			if test.unlock {
				require.NoError(
					t, vault.Unlock(t.Context(), testPrivPass),
				)
				t.Cleanup(vault.Lock)
			}

			peer, err := btcec.NewPrivateKey()
			require.NoError(t, err)

			remote := peer.PubKey()
			if test.nilRemote {
				remote = nil
			}

			// Act: Request the secret for the row's account.
			got, err := vault.ECDH(
				t.Context(), waddrmgr.KeyScopeBIP0084,
				waddrmgr.DerivationPath{
					InternalAccount: test.account,
				}, remote,
			)

			// Assert: The row's error identity and no secret.
			require.ErrorIs(t, err, test.wantErr)
			require.Equal(t, [32]byte{}, got)
		})
	}
}

// legacyAccountChildPubKey derives the public key at path from the stored
// account xpub, independently of the vault's private derivation.
func legacyAccountChildPubKey(t *testing.T, dbConn walletdb.DB,
	mgr *waddrmgr.Manager, scope waddrmgr.KeyScope,
	path waddrmgr.DerivationPath) *btcec.PublicKey {

	t.Helper()

	scoped, err := mgr.FetchScopedKeyManager(scope)
	require.NoError(t, err)

	var props *waddrmgr.AccountProperties

	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)

		var viewErr error

		props, viewErr = scoped.AccountProperties(
			ns, path.InternalAccount,
		)

		return viewErr
	})
	require.NoError(t, err)

	branch, err := keyvault.DeriveChild(props.AccountPubKey, path.Branch)
	require.NoError(t, err)

	leaf, err := keyvault.DeriveChild(branch, path.Index)
	require.NoError(t, err)

	pubKey, err := leaf.ECPubKey()
	require.NoError(t, err)

	return pubKey
}

// TestLegacyWalletVaultTranslatesManagerSentinels verifies that the adapter
// surfaces keyvault sentinels rather than leaking the underlying waddrmgr
// sentinels, so callers can handle keyvault.Vault errors backend-independently
// (matching what WalletVault returns for the same cases).
func TestLegacyWalletVaultTranslatesManagerSentinels(t *testing.T) {
	t.Parallel()

	t.Run("unlock wrong passphrase", func(t *testing.T) {
		t.Parallel()

		dbConn, cleanup := newTestDB(t)
		t.Cleanup(cleanup)

		mgr := newSpendableAddrMgr(t, dbConn)
		vault := NewLegacyWalletVault(dbConn, mgr)

		// waddrmgr.Manager.Unlock reports a wrong passphrase as
		// waddrmgr.ErrWrongPassphrase; the adapter must translate it to
		// keyvault.ErrInvalidPassphrase, matching WalletVault.
		err := vault.Unlock(t.Context(), []byte("wrong-passphrase"))
		require.ErrorIs(t, err, keyvault.ErrInvalidPassphrase)
		require.False(t, waddrmgr.IsError(err, waddrmgr.ErrWrongPassphrase))
	})

	t.Run("encrypt while locked", func(t *testing.T) {
		t.Parallel()

		dbConn, cleanup := newTestDB(t)
		t.Cleanup(cleanup)

		// A freshly opened manager is locked, so encrypting under the
		// script crypto key hits waddrmgr.ErrLocked; the adapter must
		// translate it to keyvault.ErrVaultLocked, matching WalletVault.
		mgr := newSpendableAddrMgr(t, dbConn)
		vault := NewLegacyWalletVault(dbConn, mgr)
		require.True(t, vault.IsLocked())

		_, err := vault.Encrypt(waddrmgr.CKTScript, []byte("plaintext"))
		require.ErrorIs(t, err, keyvault.ErrVaultLocked)
		require.False(t, waddrmgr.IsError(err, waddrmgr.ErrLocked))
	})

	t.Run("decrypt while locked", func(t *testing.T) {
		t.Parallel()

		dbConn, cleanup := newTestDB(t)
		t.Cleanup(cleanup)

		mgr := newSpendableAddrMgr(t, dbConn)
		vault := NewLegacyWalletVault(dbConn, mgr)
		require.True(t, vault.IsLocked())

		_, err := vault.Decrypt(waddrmgr.CKTScript, []byte("ciphertext"))
		require.ErrorIs(t, err, keyvault.ErrVaultLocked)
		require.False(t, waddrmgr.IsError(err, waddrmgr.ErrLocked))
	})
}

// TestLegacyWalletVaultUnlockReadFailure checks the lock postcondition when
// the read transaction fails after the address manager accepts the passphrase.
func TestLegacyWalletVaultUnlockReadFailure(t *testing.T) {
	t.Parallel()

	// Arrange: Use a real wallet so authentication changes its key state.
	// Return a finalization error only after the real read succeeds.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)
	mgr := newSpendableAddrMgr(t, dbConn)
	t.Cleanup(mgr.Close)

	view := func(read func(walletdb.ReadTx) error, reset func()) error {
		err := dbConn.View(read, reset)
		if err != nil {
			return err
		}

		return errInjectedCommit
	}
	reader := &watchViewDB{DB: dbConn}
	reader.On("View", mock.Anything, mock.Anything).Return(view).Once()
	vault := NewLegacyWalletVault(reader, mgr)

	// Act: Authenticate with the original private passphrase through View.
	err := vault.Unlock(t.Context(), testPrivPass)

	// Assert: The caller sees the driver's error and the vault has erased
	// the private key material made available during the callback.
	require.ErrorIs(t, err, errInjectedCommit)
	require.True(t, vault.IsLocked())
	reader.AssertExpectations(t)
}

// TestLegacyWalletVaultUnlockAlreadyUnlocked verifies that unlocking an
// already-unlocked vault returns keyvault.ErrVaultUnlocked without validating
// the passphrase and without locking the manager. A wrong passphrase must not
// disturb the unlocked state.
func TestLegacyWalletVaultUnlockAlreadyUnlocked(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	mgr := newSpendableAddrMgr(t, dbConn)
	vault := NewLegacyWalletVault(dbConn, mgr)

	// Unlock once with the correct passphrase.
	require.NoError(t, vault.Unlock(t.Context(), testPrivPass))
	require.False(t, vault.IsLocked())

	// A second unlock with a wrong passphrase must short-circuit to
	// ErrVaultUnlocked (contract: no passphrase validation while unlocked)
	// and leave the manager unlocked rather than locking it.
	err := vault.Unlock(t.Context(), []byte("wrong-passphrase"))
	require.ErrorIs(t, err, keyvault.ErrVaultUnlocked)
	require.False(t, vault.IsLocked(),
		"a rejected re-unlock must not lock the manager")
}

// TestLegacyWalletVaultLockWatchOnly verifies that locking a watch-only vault
// is a silent no-op: waddrmgr.Manager.Lock returns ErrWatchingOnly for a
// watch-only manager, and the Vault contract makes Lock void, so nothing must
// be logged as an error.
//
// Not parallel: it swaps the package logger, which is process-global state.
//
//nolint:paralleltest // mutates the package logger; must not run in parallel.
func TestLegacyWalletVaultLockWatchOnly(t *testing.T) {
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	mgr := newSpendableAddrMgr(t, dbConn)
	convertAddrStoreToWatchOnly(t, dbConn, mgr)

	vault := NewLegacyWalletVault(dbConn, mgr)

	// Capture package log output so we can assert Lock swallows the
	// watch-only case instead of logging it as an error.
	var buf bytes.Buffer

	restore := log
	backend := btclog.NewBackend(&buf)
	logger := backend.Logger("KVDBTEST")
	logger.SetLevel(btclog.LevelTrace)
	log = logger
	t.Cleanup(func() {
		log = restore
	})

	// Lock is void; it must not panic and must not log an error for the
	// watch-only no-op.
	require.NotPanics(t, vault.Lock)

	require.NotContains(t, buf.String(), "lock manager",
		"watch-only Lock must not log an error")
}

// TestLegacyWalletVaultChangePassphrase covers the adapter's rotation
// behaviour across the halves kvdb owns. kvdb is the only backend with a public
// passphrase, so this is where the field pair has to work: a private-only
// rotation retires the old private passphrase, a public-only rotation leaves
// the private half alone, a combined request rotates both, and a wrong old
// public passphrase is rejected without mutating anything.
func TestLegacyWalletVaultChangePassphrase(t *testing.T) {
	t.Parallel()

	newPubPass := []byte("brand-new-pub-pass")
	newPrivPass := []byte("brand-new-priv-pass")

	tests := []struct {
		name   string
		params keyvault.ChangePassphraseParams

		// wantErr is the error the rotation must return; nil means it
		// must succeed.
		wantErr error

		// wantUnlock is the passphrase that must unlock the manager
		// after the request settles.
		wantUnlock []byte
	}{{
		name: "private only",
		params: keyvault.ChangePassphraseParams{
			PrivateOld: testPrivPass,
			PrivateNew: newPrivPass,
		},
		wantUnlock: newPrivPass,
	}, {
		name: "public only leaves the private half",
		params: keyvault.ChangePassphraseParams{
			PublicOld: testPubPass,
			PublicNew: newPubPass,
		},
		wantUnlock: testPrivPass,
	}, {
		name: "combined rotates both",
		params: keyvault.ChangePassphraseParams{
			PublicOld:  testPubPass,
			PublicNew:  newPubPass,
			PrivateOld: testPrivPass,
			PrivateNew: newPrivPass,
		},
		wantUnlock: newPrivPass,
	}, {
		name: "wrong old public mutates nothing",
		params: keyvault.ChangePassphraseParams{
			PublicOld: []byte("not-the-public-passphrase"),
			PublicNew: newPubPass,
		},
		wantErr:    keyvault.ErrInvalidPassphrase,
		wantUnlock: testPrivPass,
	}, {
		name: "empty new private mutates nothing",
		params: keyvault.ChangePassphraseParams{
			PrivateOld: testPrivPass,
			PrivateNew: []byte{},
		},
		wantErr:    keyvault.ErrEmptyPassphrase,
		wantUnlock: testPrivPass,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			dbConn, cleanup := newTestDB(t)
			t.Cleanup(cleanup)

			mgr := newSpendableAddrMgr(t, dbConn)
			vault := NewLegacyWalletVault(dbConn, mgr)

			err := vault.ChangePassphrase(t.Context(), test.params)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
			} else {
				require.NoError(t, err)
			}

			// A rotated private half must retire the old
			// passphrase before the new one is accepted.
			if test.params.PrivateOld != nil && test.wantErr == nil {
				require.Error(
					t, vault.Unlock(
						t.Context(), testPrivPass,
					),
				)
			}

			// A failed unlock already leaves the manager locked,
			// but be explicit before retrying.
			vault.Lock()
			require.NoError(
				t, vault.Unlock(t.Context(), test.wantUnlock),
			)
		})
	}
}

// TestLegacyWalletVaultForwardsExplicitKeyClass verifies that the adapter
// forwards the caller's explicit CryptoKeyType to the legacy manager rather
// than selecting a key itself: the Vault takes the key class as an argument, so
// wallet mode is not its policy to make.
func TestLegacyWalletVaultForwardsExplicitKeyClass(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		keyType waddrmgr.CryptoKeyType
	}{
		{name: "public", keyType: waddrmgr.CKTPublic},
		{name: "script", keyType: waddrmgr.CKTScript},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			dbConn, cleanup := newTestDB(t)
			t.Cleanup(cleanup)

			mgr := newSpendableAddrMgr(t, dbConn)
			vault := NewLegacyWalletVault(dbConn, mgr)

			// The script key is only available while unlocked.
			require.NoError(
				t, vault.Unlock(t.Context(), testPrivPass),
			)

			plaintext := []byte("explicit key class")

			ciphertext, err := vault.Encrypt(
				test.keyType, plaintext,
			)
			require.NoError(t, err)
			require.NotEqual(t, plaintext, ciphertext)

			got, err := vault.Decrypt(test.keyType, ciphertext)
			require.NoError(t, err)
			require.Equal(t, plaintext, got)
		})
	}
}

// TestLegacyWalletVaultPubKey verifies that the legacy vault returns the
// public key of the account child it derives through the private key,
// including a hardened child, which an account XPub cannot derive, and of an
// imported key.
func TestLegacyWalletVaultPubKey(t *testing.T) {
	t.Parallel()

	// Arrange: An unlocked legacy vault with an imported key, the public key
	// at m/84'/1'/0'/0/1 read from the account xpub, and a hardened child
	// derived by the unlocked manager.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	mgr := newSpendableAddrMgr(t, dbConn)
	vault := NewLegacyWalletVault(dbConn, mgr)
	require.NoError(t, vault.Unlock(t.Context(), testPrivPass))
	t.Cleanup(vault.Lock)

	path := waddrmgr.DerivationPath{Branch: 0, Index: 1}
	walletPub := legacyAccountChildPubKey(
		t, dbConn, mgr, waddrmgr.KeyScopeBIP0084, path,
	)

	hardenedPath := waddrmgr.DerivationPath{
		Index: hdkeychain.HardenedKeyStart,
	}
	hardenedPub := legacyManagerPubKey(
		t, dbConn, mgr, waddrmgr.KeyScopeBIP0084, hardenedPath,
	)

	importedKey, importedScript := importLegacyPrivKey(t, dbConn, mgr)

	// Act: Derive the key at the path, the hardened child and the import.
	pub, err := vault.PubKey(t.Context(), signing.DerivedKey{
		KeyScope:       waddrmgr.KeyScopeBIP0084,
		DerivationPath: path,
	})
	hardened, hardenedErr := vault.PubKey(t.Context(), signing.DerivedKey{
		KeyScope:       waddrmgr.KeyScopeBIP0084,
		DerivationPath: hardenedPath,
	})
	imported, importedErr := vault.PubKey(t.Context(), signing.ImportedKey{
		ScriptPubKey: importedScript,
	})

	// Assert: The vault derived each key through its private key.
	require.NoError(t, err)
	require.True(t, pub.IsEqual(walletPub))
	require.NoError(t, hardenedErr)
	require.True(t, hardened.IsEqual(hardenedPub))
	require.NoError(t, importedErr)
	require.True(t, imported.IsEqual(importedKey.PubKey()))
}

// legacyManagerPubKey derives the public key at path with the unlocked
// manager's own private derivation, independently of the vault.
func legacyManagerPubKey(t *testing.T, dbConn walletdb.DB,
	mgr *waddrmgr.Manager, scope waddrmgr.KeyScope,
	path waddrmgr.DerivationPath) *btcec.PublicKey {

	t.Helper()

	scoped, err := mgr.FetchScopedKeyManager(scope)
	require.NoError(t, err)

	var addr waddrmgr.ManagedAddress

	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)

		var viewErr error

		addr, viewErr = scoped.DeriveFromKeyPath(ns, path)

		return viewErr
	})
	require.NoError(t, err)

	pubAddr, ok := addr.(waddrmgr.ManagedPubKeyAddress)
	require.True(t, ok)

	return pubAddr.PubKey()
}

// importLegacyPrivKey imports a new private key into the unlocked manager's
// BIP84 scope and returns the key and its output script.
func importLegacyPrivKey(t *testing.T, dbConn walletdb.DB,
	mgr *waddrmgr.Manager) (*btcec.PrivateKey, []byte) {

	t.Helper()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	wif, err := btcutil.NewWIF(privKey, mgr.ChainParams(), true)
	require.NoError(t, err)

	scoped, err := mgr.FetchScopedKeyManager(waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)

	var script []byte

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)

		addr, importErr := scoped.ImportPrivateKey(ns, wif, nil)
		if importErr != nil {
			return importErr
		}

		script, importErr = txscript.PayToAddrScript(addr.Address())

		return importErr
	})
	require.NoError(t, err)

	return privKey, script
}

// importLegacyPubKey imports pub into the manager's BIP84 scope as a
// watch-only address and returns its output script.
func importLegacyPubKey(t *testing.T, dbConn walletdb.DB,
	mgr *waddrmgr.Manager, pub *btcec.PublicKey) []byte {

	t.Helper()

	scoped, err := mgr.FetchScopedKeyManager(waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)

	var script []byte

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)

		addr, importErr := scoped.ImportPublicKey(ns, pub, nil)
		if importErr != nil {
			return importErr
		}

		script, importErr = txscript.PayToAddrScript(addr.Address())

		return importErr
	})
	require.NoError(t, err)

	return script
}

// legacyP2WKHScript returns the simnet P2WPKH output script of the public key
// of the private key with the given seed.
func legacyP2WKHScript(t *testing.T, seed string) (*btcec.PublicKey, []byte) {
	t.Helper()

	keyBytes := sha256.Sum256([]byte(seed))
	_, pub := btcec.PrivKeyFromBytes(keyBytes[:])

	addr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pub.SerializeCompressed()), &chaincfg.SimNetParams,
	)
	require.NoError(t, err)

	script, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	return pub, script
}

// TestLegacyWalletVaultPubKeyLocked verifies that a locked manager refuses an
// invalid selector with the SQL vault's sentinel and any other key with
// keyvault.ErrVaultLocked, both before the Store lookup.
func TestLegacyWalletVaultPubKeyLocked(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     signing.KeySelector
		wantErr error
	}{
		{
			name: "missing account while locked",
			key: signing.DerivedKey{
				KeyScope: waddrmgr.KeyScopeBIP0084,
				DerivationPath: waddrmgr.DerivationPath{
					InternalAccount: 99,
				},
			},
			wantErr: keyvault.ErrVaultLocked,
		},
		{
			name:    "empty import script while locked",
			key:     signing.ImportedKey{},
			wantErr: signing.ErrInvalidKeySelector,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: A locked legacy vault.
			dbConn, cleanup := newTestDB(t)
			t.Cleanup(cleanup)

			mgr := newSpendableAddrMgr(t, dbConn)
			vault := NewLegacyWalletVault(dbConn, mgr)

			// Act: Ask for the row's key.
			pub, err := vault.PubKey(t.Context(), test.key)

			// Assert: The row's error identity and no key.
			require.ErrorIs(t, err, test.wantErr)
			require.Nil(t, pub)
		})
	}
}

// TestLegacyWalletVaultPubKeyErrors verifies the error identities the Wallet
// maps to its public signer errors on an unlocked manager: a missing account
// keeps the Store's identity, and a watch-only import reports
// keyvault.ErrNoPrivateKey. kvdb reports a script it does not know like a
// watch-only import, so an unknown script reports keyvault.ErrNoPrivateKey
// too.
func TestLegacyWalletVaultPubKeyErrors(t *testing.T) {
	t.Parallel()

	watchOnlyPub, watchOnlyScript := legacyP2WKHScript(t, "watch-only")
	_, unknownScript := legacyP2WKHScript(t, "unknown")

	tests := []struct {
		name    string
		key     signing.KeySelector
		wantErr error
	}{
		{
			name: "missing account",
			key: signing.DerivedKey{
				KeyScope: waddrmgr.KeyScopeBIP0084,
				DerivationPath: waddrmgr.DerivationPath{
					InternalAccount: 99,
				},
			},
			wantErr: db.ErrAccountNotFound,
		},
		{
			name:    "watch-only import",
			key:     signing.ImportedKey{ScriptPubKey: watchOnlyScript},
			wantErr: keyvault.ErrNoPrivateKey,
		},
		{
			name:    "unknown script",
			key:     signing.ImportedKey{ScriptPubKey: unknownScript},
			wantErr: keyvault.ErrNoPrivateKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: An unlocked legacy vault holding a watch-only
			// import.
			dbConn, cleanup := newTestDB(t)
			t.Cleanup(cleanup)

			mgr := newSpendableAddrMgr(t, dbConn)
			vault := NewLegacyWalletVault(dbConn, mgr)
			require.NoError(t, vault.Unlock(t.Context(), testPrivPass))
			t.Cleanup(vault.Lock)

			script := importLegacyPubKey(t, dbConn, mgr, watchOnlyPub)
			require.Equal(t, watchOnlyScript, script)

			// Act: Ask for the row's key.
			pub, err := vault.PubKey(t.Context(), test.key)

			// Assert: The row's error identity and no key.
			require.ErrorIs(t, err, test.wantErr)
			require.Nil(t, pub)
		})
	}
}

// TestLegacyWalletVaultPubKeyWatchOnlyManager verifies that a watch-only
// manager, which can never be unlocked, skips the lock check and reports
// keyvault.ErrNoPrivateKey for an account key.
func TestLegacyWalletVaultPubKeyWatchOnlyManager(t *testing.T) {
	t.Parallel()

	// Arrange: A legacy vault over a watch-only manager.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	mgr := newSpendableAddrMgr(t, dbConn)
	vault := NewLegacyWalletVault(dbConn, mgr)
	convertAddrStoreToWatchOnly(t, dbConn, mgr)

	// Act: Ask for a key of the default account.
	pub, err := vault.PubKey(t.Context(), signing.DerivedKey{
		KeyScope: waddrmgr.KeyScopeBIP0084,
	})

	// Assert: The account has no private key, and no key is returned.
	require.ErrorIs(t, err, keyvault.ErrNoPrivateKey)
	require.Nil(t, pub)
}

// TestLegacyWalletVaultSignDigest verifies that the legacy vault signs with
// the account child key, so kvdb signing needs no Wallet-side private key.
func TestLegacyWalletVaultSignDigest(t *testing.T) {
	t.Parallel()

	// Arrange: An unlocked legacy vault and the public key at
	// m/84'/1'/0'/0/1 read from the account xpub.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	mgr := newSpendableAddrMgr(t, dbConn)
	vault := NewLegacyWalletVault(dbConn, mgr)
	require.NoError(t, vault.Unlock(t.Context(), testPrivPass))
	t.Cleanup(vault.Lock)

	path := waddrmgr.DerivationPath{Branch: 0, Index: 1}
	walletPub := legacyAccountChildPubKey(
		t, dbConn, mgr, waddrmgr.KeyScopeBIP0084, path,
	)
	digest := sha256.Sum256([]byte("kvdb vault digest"))

	// Act: Sign a digest with the key at the path.
	sig, err := vault.SignDigest(t.Context(), signing.DigestRequest{
		Key: signing.DerivedKey{
			KeyScope:       waddrmgr.KeyScopeBIP0084,
			DerivationPath: path,
		},
		Digest: digest,
		Mode:   signing.ModeSchnorr,
	})

	// Assert: The signature verifies under the wallet key.
	require.NoError(t, err)

	schnorrSig, ok := sig.(signing.SchnorrSignature)
	require.True(t, ok)
	require.True(t, schnorrSig.Verify(digest[:], walletPub))
}
