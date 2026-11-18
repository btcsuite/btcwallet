package wallet

import (
	"bytes"
	"context"
	"testing"
	"testing/synctest"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// sqlECDHFixture uses the production SQL vault and request loop, with no Wallet
// cache or UnsafeVault reference. A regression to Wallet-side key use fails
// rather than silently receiving private material from a permissive mock.
type sqlECDHFixture struct {
	wallet    *Wallet
	store     *walletmock.Store
	vault     *keyvault.WalletVault
	path      BIP32Path
	query     db.GetAccountSecretQuery
	encrypted []byte
	public    *btcec.PublicKey
}

// newSQLECDHFixture creates an encrypted account and independently derives its
// public child. Private fixture setup ends before any ECDH request is made.
func newSQLECDHFixture(t *testing.T) *sqlECDHFixture {
	t.Helper()

	w, deps := createSQLWalletWithMocks(t)
	root, err := hdkeychain.NewMaster(bytes.Repeat([]byte{3}, 32), &chainParams)
	require.NoError(t, err)

	defer root.Zero()

	passphrase := []byte("ecdh fixture")
	secrets, err := keyvault.CreateWalletSecrets(passphrase, root, false)
	require.NoError(t, err)

	deps.store.On(
		"GetWalletSecrets", mock.Anything, w.id,
	).Return(secrets, nil).Once()
	vault := keyvault.NewWalletVault(deps.store, w.id, false)
	require.NoError(t, vault.Unlock(t.Context(), passphrase))
	t.Cleanup(vault.Lock)

	encrypted, err := vault.Encrypt(waddrmgr.CKTPrivate, []byte(root.String()))
	require.NoError(t, err)

	accountPub, err := root.Neuter()
	require.NoError(t, err)

	defer accountPub.Zero()

	path := BIP32Path{
		KeyScope: waddrmgr.KeyScopeBIP0084,
		DerivationPath: waddrmgr.DerivationPath{
			InternalAccount: 7,
			Account:         hdkeychain.HardenedKeyStart + 7,
			Branch:          1,
			Index:           9,
		},
	}
	public, err := deriveStoredAccountChildPubKey(
		[]byte(accountPub.String()), path.DerivationPath,
	)
	require.NoError(t, err)

	w.addrStore = nil
	w.cache = nil
	w.unsafeVault = nil
	w.keyVault = vault
	startLoadedWalletForTest(t, w)
	w.state.toUnlocked()

	return &sqlECDHFixture{
		wallet: w,
		store:  deps.store,
		vault:  vault,
		path:   path,
		query: db.GetAccountSecretQuery{
			WalletID:      w.id,
			Scope:         db.KeyScope(path.KeyScope),
			AccountNumber: 7,
		},
		encrypted: encrypted,
		public:    public,
	}
}

// TestECDHSQLContained exercises public SQL ECDH with only a safe vault
// reference. The peer-side oracle checks the exact digest, not just symmetry.
func TestECDHSQLContained(t *testing.T) {
	t.Parallel()

	// Arrange: A non-default numbered account and nonzero child path.
	f := newSQLECDHFixture(t)
	f.store.On("GetAccountSecret", mock.Anything, f.query).Return(
		&db.AccountSecret{EncryptedPrivateKey: f.encrypted}, nil,
	).Once()

	peer, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{5}, 32))
	defer peer.Zero()

	want, _ := expectedECDHSecret(t, peer, f.public)

	// Act: Use only the public safe signer contract.
	var signer Signer = f.wallet

	got, err := signer.ECDH(t.Context(), f.path, peer.PubKey())

	// Assert: No Wallet-owned key path is available, and the digest is exact.
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Equal(t, make([]byte, len(f.encrypted)), f.encrypted)
}

// TestECDHSQLAccountErrors pins lookup-error precedence over a vault that has
// locked since Wallet admission. Wallet's state check still comes first.
func TestECDHSQLAccountErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		secret   *db.AccountSecret
		storeErr error
		wantErr  error
	}{
		{
			name:     "missing account",
			storeErr: db.ErrAccountNotFound,
			wantErr:  ErrAccountNotInStore,
		},
		{
			name:     "unavailable account",
			storeErr: db.ErrAccountSecretUnavailable,
			wantErr:  ErrAccountNotInStore,
		},
		{
			name:    "watch-only account",
			secret:  &db.AccountSecret{},
			wantErr: ErrWatchOnlyAccount,
		},
		{
			name: "locked account",
			secret: &db.AccountSecret{
				EncryptedPrivateKey: []byte("ciphertext"),
			},
			wantErr: keyvault.ErrVaultLocked,
		},
		{
			name:     "store failure",
			storeErr: errPrivKeyMock,
			wantErr:  errPrivKeyMock,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Keep Wallet admitted state, but lock the vault.
			f := newSQLECDHFixture(t)
			f.vault.Lock()
			f.store.On(
				"GetAccountSecret", mock.Anything, f.query,
			).Return(test.secret, test.storeErr).Once()

			peer, _ := deterministicPrivKey(t)

			// Act: Resolve the numbered account through SQL ECDH.
			got, err := f.wallet.ECDH(t.Context(), f.path, peer.PubKey())

			// Assert: Missing/watch-only/Store errors precede vault lock.
			require.ErrorIs(t, err, test.wantErr)
			require.Equal(t, [32]byte{}, got)
		})
	}
}

// TestECDHSQLStateBeforePeer pins Wallet state errors before peer validation.
// The merged nil/off-curve tests already cover validation before Store access.
func TestECDHSQLStateBeforePeer(t *testing.T) {
	t.Parallel()

	// Arrange: An SQL wallet with no expected account lookup.
	f := newSQLECDHFixture(t)
	f.wallet.state.toLocked()

	// Act/Assert: State errors precede invalid peer errors.
	got, err := f.wallet.ECDH(t.Context(), f.path, nil)
	require.ErrorIs(t, err, ErrStateForbidden)
	require.Equal(t, [32]byte{}, got)
}

// TestECDHSQLDecryptError preserves the real cipher error through the safe
// public path, rather than testing only an injected decrypt result.
func TestECDHSQLDecryptError(t *testing.T) {
	t.Parallel()

	// Arrange: An unlocked SQL vault and invalid account ciphertext.
	f := newSQLECDHFixture(t)
	encrypted := bytes.Repeat([]byte{1}, len(f.encrypted))
	f.store.On("GetAccountSecret", mock.Anything, f.query).Return(
		&db.AccountSecret{EncryptedPrivateKey: encrypted}, nil,
	).Once()

	// Act: Attempt ECDH using the real cipher implementation.
	got, err := f.wallet.ECDH(t.Context(), f.path, f.public)

	// Assert: Preserve the cipher identity and expose no result.
	require.ErrorIs(t, err, snacl.ErrDecryptFailed)
	require.Equal(t, [32]byte{}, got)
	require.Equal(t, make([]byte, len(encrypted)), encrypted)
}

// TestECDHSQLCanceledBeforeAdmission rejects cancellation without a request
// receiver, so the test cannot accidentally admit work in a select race.
func TestECDHSQLCanceledBeforeAdmission(t *testing.T) {
	t.Parallel()

	// Arrange: A started SQL wallet with no request-loop receiver.
	w, _ := createTestWalletWithMocks(t)
	require.NoError(t, w.state.toStarting())
	require.NoError(t, w.state.toStarted())
	w.state.toUnlocked()
	w.addrStore = nil
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	peer, _ := deterministicPrivKey(t)

	// Act: Submit an already canceled request.
	got, err := w.ECDH(ctx, BIP32Path{}, peer.PubKey())

	// Assert: No dependency is used.
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, [32]byte{}, got)
}

// TestECDHSQLCancellationJoinsStop proves accepted SQL ECDH retains its exact
// result after cancellation and Stop waits for a Store ignoring cancellation.
func TestECDHSQLCancellationJoinsStop(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		t.Helper()

		// Arrange: Hold the admitted lookup before any secret use.
		f := newSQLECDHFixture(t)
		entered := make(chan struct{})
		release := make(chan struct{})
		f.store.On(
			"GetAccountSecret", mock.Anything, f.query,
		).Run(func(mock.Arguments) {
			close(entered)
			<-release
		}).Return(
			&db.AccountSecret{EncryptedPrivateKey: f.encrypted}, nil,
		).Once()

		peer, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{5}, 32))
		defer peer.Zero()

		want, _ := expectedECDHSecret(t, peer, f.public)

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		result := make(chan ecdhResp, 1)
		go func() {
			digest, err := f.wallet.ECDH(ctx, f.path, peer.PubKey())
			result <- ecdhResp{secret: digest, err: err}
		}()

		<-entered

		// Act: Cancel the caller and stop while the dependency is held.
		cancel()

		stopped := make(chan error, 1)
		go func() {
			stopped <- f.wallet.stop()
		}()

		synctest.Wait()

		// Assert: Neither return is allowed until the accepted use ends.
		require.Empty(t, result)
		require.Empty(t, stopped)
		close(release)
		synctest.Wait()

		got := <-result
		require.NoError(t, got.err)
		require.Equal(t, want, got.secret)
		require.NoError(t, <-stopped)
		require.True(t, f.vault.IsLocked())

		_, err := f.wallet.ECDH(t.Context(), f.path, nil)
		require.ErrorIs(t, err, ErrWalletStopped)
	})
}
