package wallet

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
	"github.com/btcsuite/btcwallet/wallet/internal/signing"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// parityIndices returns indices of account keys in scope with an even and an
// odd Y coordinate, found by public derivation.
func parityIndices(t *testing.T, w *Wallet, scope waddrmgr.KeyScope,
	account uint32) (uint32, uint32) {

	t.Helper()

	var found [2]*uint32
	for index := uint32(0); found[0] == nil || found[1] == nil; index++ {
		require.Less(t, index, uint32(64))

		pub, err := w.DerivePubKey(t.Context(), DerivePubKeyParams{
			Account: NewAccountSelectorByNumber(
				scope, AccountNumber(account),
			),
			Index: index,
		})
		require.NoError(t, err)

		parity := pub.SerializeCompressed()[0] - 0x02
		if found[parity] == nil {
			found[parity] = &index
		}
	}

	return *found[0], *found[1]
}

// sqlSignerPrivKeys reads the private keys at paths through the unsafe vault,
// then drops it, so the signing that follows uses only vault primitives. The
// keys compute the expected signatures and are zeroed when the test ends.
func sqlSignerPrivKeys(t *testing.T, w *Wallet,
	paths ...BIP32Path) []*btcec.PrivateKey {

	t.Helper()

	keys := make([]*btcec.PrivateKey, len(paths))
	for i, path := range paths {
		key, err := w.DerivePrivKey(t.Context(), path)
		require.NoError(t, err)
		t.Cleanup(key.Zero)

		keys[i] = key
	}

	w.unsafeVault = nil

	return keys
}

// sqlSignerPubKeys reads the public keys at paths through the unsafe vault,
// then drops it, so the signing that follows uses only vault primitives.
func sqlSignerPubKeys(t *testing.T, w *Wallet,
	paths ...BIP32Path) []*btcec.PublicKey {

	t.Helper()

	keys := sqlSignerPrivKeys(t, w, paths...)

	pubs := make([]*btcec.PublicKey, len(keys))
	for i, key := range keys {
		pubs[i] = key.PubKey()
	}

	return pubs
}

// TestSQLSignerUsesVaultPrimitives verifies that SQL digest signing works
// without a raw decryption dependency: ECDSA, compact ECDSA and untweaked
// Schnorr signatures verify under the key at the path.
func TestSQLSignerUsesVaultPrimitives(t *testing.T) {
	t.Parallel()

	// Arrange: Create a SQLite wallet, read the key at one path and drop
	// the unsafe vault.
	w := createSQLiteWallet(t, createTestChain(t))
	path := BIP32Path{
		KeyScope:       waddrmgr.KeyScopeBIP0084,
		DerivationPath: waddrmgr.DerivationPath{Index: 3},
	}
	pub := sqlSignerPubKeys(t, w, path)[0]
	digest := sha256.Sum256([]byte("sql signer digest"))

	// Act: Sign each untweaked intent without the unsafe vault.
	derSig, derErr := w.SignDigest(t.Context(), path, &SignDigestIntent{
		Digest: digest[:], SigType: SigTypeECDSA,
	})
	compactSig, compactErr := w.SignDigest(t.Context(), path,
		&SignDigestIntent{
			Digest: digest[:], SigType: SigTypeECDSA, CompactSig: true,
		},
	)
	schnorrSig, schnorrErr := w.SignDigest(t.Context(), path,
		&SignDigestIntent{Digest: digest[:], SigType: SigTypeSchnorr},
	)

	// Assert: Verify the signatures using public data alone.
	require.NoError(t, derErr)
	require.NoError(t, compactErr)
	require.NoError(t, schnorrErr)

	der, ok := derSig.(ECDSASignature)
	require.True(t, ok)
	require.True(t, der.Verify(digest[:], pub))

	compact, ok := compactSig.(CompactSignature)
	require.True(t, ok)

	recovered, compressed, err := ecdsa.RecoverCompact(compact, digest[:])
	require.NoError(t, err)
	require.True(t, compressed)
	require.True(t, recovered.IsEqual(pub))

	schnorrPlain, ok := schnorrSig.(SchnorrSignature)
	require.True(t, ok)
	require.True(t, schnorrPlain.Verify(digest[:], pub))
}

// TestSQLSignerTaprootTweak verifies that Taproot-tweaked digest signatures
// verify under the expected BIP-86 and script-root output keys for internal
// keys of both parities and for a hardened child, which an account XPub
// cannot derive.
func TestSQLSignerTaprootTweak(t *testing.T) {
	t.Parallel()

	// Arrange: Create a SQLite wallet, pick even and odd keys and a
	// hardened child, and read their public keys before dropping the
	// unsafe vault.
	w := createSQLiteWallet(t, createTestChain(t))
	even, odd := parityIndices(t, w, waddrmgr.KeyScopeBIP0084, 0)

	const hardened = hdkeychain.HardenedKeyStart

	evenPath := BIP32Path{
		KeyScope:       waddrmgr.KeyScopeBIP0084,
		DerivationPath: waddrmgr.DerivationPath{Index: even},
	}
	oddPath := BIP32Path{
		KeyScope:       waddrmgr.KeyScopeBIP0084,
		DerivationPath: waddrmgr.DerivationPath{Index: odd},
	}
	hardenedPath := BIP32Path{
		KeyScope: waddrmgr.KeyScopeBIP0084,
		DerivationPath: waddrmgr.DerivationPath{
			Branch: hardened, Index: hardened,
		},
	}
	pubs := sqlSignerPubKeys(t, w, evenPath, oddPath, hardenedPath)

	digest := sha256.Sum256([]byte("sql signer taproot digest"))
	root := sha256.Sum256([]byte("script root"))

	tests := []struct {
		name string
		path BIP32Path
		pub  *btcec.PublicKey
	}{
		{name: "even key", path: evenPath, pub: pubs[0]},
		{name: "odd key", path: oddPath, pub: pubs[1]},
		{name: "hardened child", path: hardenedPath, pub: pubs[2]},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Act: Sign a BIP-86 and a script-root digest.
			keyPathSig, keyPathErr := w.SignDigest(
				t.Context(), test.path, &SignDigestIntent{
					Digest:       digest[:],
					SigType:      SigTypeSchnorr,
					TaprootTweak: []byte{},
				},
			)
			scriptSig, scriptErr := w.SignDigest(
				t.Context(), test.path, &SignDigestIntent{
					Digest:       digest[:],
					SigType:      SigTypeSchnorr,
					TaprootTweak: root[:],
				},
			)

			// Assert: Each verifies under its output key.
			require.NoError(t, keyPathErr)
			require.NoError(t, scriptErr)

			keyPath, ok := keyPathSig.(SchnorrSignature)
			require.True(t, ok)
			require.True(t, keyPath.Verify(
				digest[:], txscript.ComputeTaprootKeyNoScript(test.pub),
			))

			script, ok := scriptSig.(SchnorrSignature)
			require.True(t, ok)
			require.True(t, script.Verify(
				digest[:],
				txscript.ComputeTaprootOutputKey(test.pub, root[:]),
			))
		})
	}
}

// TestSignDigestTaprootChecksVaultSignature verifies that a Taproot digest
// signature is returned only when it is a Schnorr signature that verifies
// under the output key Wallet derived from the vault's public key. A vault
// that signs with another key returns ErrSigningKeyMismatch, and one that
// returns any other signature type returns ErrUnknownSignMethod.
func TestSignDigestTaprootChecksVaultSignature(t *testing.T) {
	t.Parallel()

	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}
	digest := sha256.Sum256([]byte("taproot vault check"))
	_, walletPub := deterministicPrivKey(t)

	otherKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	otherSchnorr, err := schnorr.Sign(otherKey, digest[:])
	require.NoError(t, err)

	tests := []struct {
		name    string
		sig     Signature
		wantErr error
	}{
		{
			name:    "other key",
			sig:     SchnorrSignature{Signature: otherSchnorr},
			wantErr: ErrSigningKeyMismatch,
		},
		{
			name: "ecdsa signature",
			sig: ECDSASignature{
				Signature: ecdsa.Sign(otherKey, digest[:]),
			},
			wantErr: ErrUnknownSignMethod,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: A vault that reports the wallet key but returns
			// the test case's signature.
			w, mocks := createUnlockedWalletWithMocks(t)
			mocks.vault.On(
				"PubKey", mock.Anything, signing.DerivedKey(path),
			).Return(walletPub, nil).Once()
			mocks.vault.On(
				"SignDigest", mock.Anything, mock.Anything,
			).Return(test.sig, nil).Once()

			// Act: Sign a BIP-86 key-path digest.
			sig, err := w.SignDigest(t.Context(), path,
				&SignDigestIntent{
					Digest:       digest[:],
					SigType:      SigTypeSchnorr,
					TaprootTweak: []byte{},
				},
			)

			// Assert: Wallet refuses the vault's signature.
			require.ErrorIs(t, err, test.wantErr)
			require.Nil(t, sig)
		})
	}
}

// TestSignDigestMapsVaultTweakError verifies that a Taproot tweak the vault
// refuses reaches the caller as ErrInvalidSignParam and keeps
// ErrInvalidKeyTweak in the chain.
func TestSignDigestMapsVaultTweakError(t *testing.T) {
	t.Parallel()

	// Arrange: A vault that reports the wallet key but refuses the tweak.
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}
	digest := sha256.Sum256([]byte("taproot vault tweak"))
	_, walletPub := deterministicPrivKey(t)

	w, mocks := createUnlockedWalletWithMocks(t)
	mocks.vault.On(
		"PubKey", mock.Anything, signing.DerivedKey(path),
	).Return(walletPub, nil).Once()
	mocks.vault.On("SignDigest", mock.Anything, mock.Anything).Return(
		nil, fmt.Errorf("vault: %w", signing.ErrInvalidKeyTweak),
	).Once()

	// Act: Sign a BIP-86 key-path digest.
	sig, err := w.SignDigest(t.Context(), path, &SignDigestIntent{
		Digest:       digest[:],
		SigType:      SigTypeSchnorr,
		TaprootTweak: []byte{},
	})

	// Assert: The error carries both sentinels.
	require.Nil(t, sig)
	require.ErrorIs(t, err, ErrInvalidSignParam)
	require.ErrorIs(t, err, ErrInvalidKeyTweak)
}

// TestSQLSignerConcurrentLock verifies that signatures racing a Lock either
// complete with a valid signature or fail as locked. Run with -race, it also
// checks that Lock and vault signing share state safely.
func TestSQLSignerConcurrentLock(t *testing.T) {
	t.Parallel()

	// Arrange: Create a wallet and its expected public key.
	w := createSQLiteWallet(t, createTestChain(t))
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}
	digest := sha256.Sum256([]byte("concurrent lock"))

	pub, err := w.DerivePubKey(t.Context(), DerivePubKeyParams{
		Account: NewAccountSelectorByNumber(waddrmgr.KeyScopeBIP0084, 0),
	})
	require.NoError(t, err)

	// Act: Sign from several goroutines while the wallet locks.
	const signers = 16

	var (
		wg   sync.WaitGroup
		sigs = make([]Signature, signers)
		errs = make([]error, signers)
	)

	for i := range signers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			sigs[i], errs[i] = w.SignDigest(
				t.Context(), path, &SignDigestIntent{
					Digest:  digest[:],
					SigType: SigTypeECDSA,
				},
			)
		}()
	}

	require.NoError(t, w.Lock(t.Context()))
	wg.Wait()

	// Assert: Every result is a valid signature or a locked error.
	for i := range signers {
		if errs[i] != nil {
			locked := errors.Is(errs[i], ErrStateForbidden) ||
				errors.Is(errs[i], keyvault.ErrVaultLocked)
			require.True(t, locked, "signer %d: %v", i, errs[i])

			continue
		}

		sig, ok := sigs[i].(ECDSASignature)
		require.True(t, ok)
		require.True(t, sig.Verify(digest[:], pub))
	}

	require.True(t, w.keyVault.IsLocked())
}
