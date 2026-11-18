package keyvault

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/waddrmgr"
	bwmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestWalletVaultECDHLockDuringLookup proves lookup does not hold the guard
// and a Lock during lookup prevents subsequent decryption.
func TestWalletVaultECDHLockDuringLookup(t *testing.T) {
	t.Parallel()

	// Arrange: Lock synchronously from the Store, before secret use starts.
	store := &bwmock.Store{}
	vault := NewWalletVault(store, 7, false)
	vault.unlockedState = makeUnlockedState(t)
	t.Cleanup(vault.Lock)

	scope := waddrmgr.KeyScopeBIP0084
	path := waddrmgr.DerivationPath{InternalAccount: 9, Branch: 1, Index: 3}
	encrypted, err := vault.Encrypt(
		waddrmgr.CKTPrivate, []byte(vault.unlockedState.hdRootKey.String()),
	)
	require.NoError(t, err)
	store.On("GetAccountSecret", mock.Anything, db.GetAccountSecretQuery{
		WalletID: 7, Scope: db.KeyScope(scope), AccountNumber: 9,
	}).Run(func(mock.Arguments) {
		require.True(t, vault.mtx.TryLock(), "Store called under guard")
		vault.mtx.Unlock()
		vault.Lock()
	}).Return(&db.AccountSecret{EncryptedPrivateKey: encrypted}, nil).Once()

	peer := vault.unlockedState.hdRootKey
	peerPublic, err := peer.ECPubKey()
	require.NoError(t, err)

	// Act: Finish lookup after runtime keys have been cleared.
	got, err := vault.ECDH(t.Context(), scope, path, peerPublic)

	// Assert: The guarded lock check rejects use and clears the Store copy.
	require.ErrorIs(t, err, ErrVaultLocked)
	require.Equal(t, [32]byte{}, got)
	require.Equal(t, make([]byte, len(encrypted)), encrypted)
	store.AssertExpectations(t)
}

// TestWalletVaultECDHStoreErrorCleanup covers a Store that returns a partial
// secret alongside an error. The public call owns and clears that copy too.
func TestWalletVaultECDHStoreErrorCleanup(t *testing.T) {
	t.Parallel()

	// Arrange: A locked vault and an unsuccessful Store read with data.
	store := &bwmock.Store{}
	vault := NewWalletVault(store, 7, false)
	encrypted := []byte("partially loaded ciphertext")
	store.On("GetAccountSecret", mock.Anything, mock.Anything).Return(
		&db.AccountSecret{EncryptedPrivateKey: encrypted}, errStoreUnavailable,
	).Once()

	peer, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	defer peer.Zero()

	// Act: Lookup fails before the lock check.
	got, err := vault.ECDH(
		t.Context(), waddrmgr.KeyScope{}, waddrmgr.DerivationPath{},
		peer.PubKey(),
	)

	// Assert: Preserve the Store error and clear its owned copy.
	require.ErrorIs(t, err, errStoreUnavailable)
	require.Equal(t, [32]byte{}, got)
	require.Equal(t, make([]byte, len(encrypted)), encrypted)
	store.AssertExpectations(t)
}

// TestWalletVaultECDHGuardJoinsCleanup uses the private guarded phase because
// public ECDH exposes neither plaintext nor a deterministic in-guard pause.
// The decrypt dependency retains only the test's plaintext, never the key.
func TestWalletVaultECDHGuardJoinsCleanup(t *testing.T) {
	t.Parallel()

	// Arrange: Pause the real secret phase under the guard.
	vault := NewWalletVault(nil, 7, false)
	vault.unlockedState = makeUnlockedState(t)
	t.Cleanup(vault.Lock)
	plaintext := []byte(vault.unlockedState.hdRootKey.String())
	public, err := vault.unlockedState.hdRootKey.ECPubKey()
	require.NoError(t, err)

	entered := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})

	result := make(chan error, 1)
	go func() {
		_, err := vault.ecdh(
			waddrmgr.DerivationPath{Branch: 1, Index: 2}, public, nil,
			func(*snacl.CryptoKey, []byte) ([]byte, error) {
				close(entered)
				<-release

				return plaintext, nil
			},
		)
		result <- err
	}()

	<-entered

	// Act: Try to Lock while the guarded phase is held. TryLock gives a
	// deterministic guard probe without a timing-based negative wait.
	free := vault.mtx.TryLock()
	if free {
		vault.mtx.Unlock()
	}

	locked := make(chan bool, 1)
	go func() {
		vault.Lock()

		locked <- bytes.Equal(make([]byte, len(plaintext)), plaintext)
	}()

	// Assert: Lock cannot return until use and cleanup finish.
	require.False(t, free, "ECDH released the secret-use guard")
	require.Empty(t, locked)
	require.False(t, bytes.Equal(make([]byte, len(plaintext)), plaintext))
	close(release)
	require.NoError(t, <-result)
	require.True(t, <-locked, "Lock returned before plaintext cleanup")
	require.True(t, bytes.Equal(make([]byte, len(plaintext)), plaintext))
	require.True(t, vault.IsLocked())
}

// TestWalletVaultECDHPlaintextErrorCleanup observes buffers the public API
// cannot expose, covering decryption, parsing and key-extraction errors.
func TestWalletVaultECDHPlaintextErrorCleanup(t *testing.T) {
	t.Parallel()

	state := makeUnlockedState(t)
	t.Cleanup(state.zero)

	xpub, err := state.hdRootKey.Neuter()
	require.NoError(t, err)

	t.Cleanup(xpub.Zero)

	public, err := xpub.ECPubKey()
	require.NoError(t, err)

	tests := []struct {
		name       string
		plaintext  []byte
		decryptErr error
		wantErr    error
	}{
		{
			name:       "partial decryption",
			plaintext:  []byte("partial plaintext"),
			decryptErr: snacl.ErrDecryptFailed,
			wantErr:    snacl.ErrDecryptFailed,
		},
		{
			name:      "malformed account",
			plaintext: []byte("not an extended key"),
			wantErr:   hdkeychain.ErrInvalidKeyLen,
		},
		{
			name:      "public account ciphertext",
			plaintext: []byte(xpub.String()),
			wantErr:   hdkeychain.ErrNotPrivExtKey,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: The decrypt result is visible only to this test.
			vault := NewWalletVault(nil, 7, false)
			vault.unlockedState = makeUnlockedState(t)
			t.Cleanup(vault.Lock)

			plaintext := bytes.Clone(test.plaintext)

			// Act: Fail at a stage after the guard was acquired.
			got, err := vault.ecdh(
				waddrmgr.DerivationPath{}, public, nil,
				func(*snacl.CryptoKey, []byte) ([]byte, error) {
					return plaintext, test.decryptErr
				},
			)

			// Assert: Every error clears plaintext and releases the guard.
			require.ErrorIs(t, err, test.wantErr)
			require.Equal(t, [32]byte{}, got)
			require.True(
				t, bytes.Equal(make([]byte, len(plaintext)), plaintext),
			)
			require.True(t, vault.mtx.TryLock())
			vault.mtx.Unlock()
		})
	}
}

// TestWalletVaultECDHPanicReleasesGuard forces a dependency panic to check
// unwinding releases the guard. No plaintext was returned to the vault yet.
func TestWalletVaultECDHPanicReleasesGuard(t *testing.T) {
	t.Parallel()

	// Arrange: A valid peer and a vault whose decrypt dependency panics.
	vault := NewWalletVault(nil, 7, false)
	vault.unlockedState = makeUnlockedState(t)
	t.Cleanup(vault.Lock)
	public, err := vault.unlockedState.hdRootKey.ECPubKey()
	require.NoError(t, err)

	// Act: Panic from vault-owned code while the guard is held.
	require.PanicsWithValue(t, "decrypt panic", func() {
		_, _ = vault.ecdh(
			waddrmgr.DerivationPath{}, public, nil,
			func(*snacl.CryptoKey, []byte) ([]byte, error) {
				panic("decrypt panic")
			},
		)
	})

	// Assert: Lock remains usable after unwinding.
	require.True(t, vault.mtx.TryLock())
	vault.mtx.Unlock()
}
