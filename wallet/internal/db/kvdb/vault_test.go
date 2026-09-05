package kvdb

import (
	"bytes"
	"context"
	"testing"

	"github.com/btcsuite/btclog"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
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
