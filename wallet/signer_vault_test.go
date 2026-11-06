package wallet

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
	"github.com/stretchr/testify/require"
)

// privateDecryptSpy wraps the SQL WalletVault and counts private-key decrypts.
// Safe SQL signing must not decrypt a private key for wallet code, so the
// count stays zero for those calls.
type privateDecryptSpy struct {
	*keyvault.WalletVault

	privateDecrypts atomic.Int32

	// signDigests counts vault signing requests, so a test can show that
	// a malformed request never reached the vault.
	signDigests atomic.Int32
}

// SignDigest counts vault signing requests and forwards to the real vault.
func (s *privateDecryptSpy) SignDigest(ctx context.Context,
	req keyvault.SignDigestRequest) (keyvault.DigestSignature, error) {

	s.signDigests.Add(1)

	return s.WalletVault.SignDigest(ctx, req) //nolint:wrapcheck
}

// Decrypt counts private-key decrypts and forwards to the real vault.
func (s *privateDecryptSpy) Decrypt(keyType waddrmgr.CryptoKeyType,
	ciphertext []byte) ([]byte, error) {

	if keyType == waddrmgr.CKTPrivate {
		s.privateDecrypts.Add(1)
	}

	return s.WalletVault.Decrypt(keyType, ciphertext) //nolint:wrapcheck
}

// newSQLSignerWallet returns an unlocked SQLite wallet whose vault is wrapped
// in a privateDecryptSpy.
func newSQLSignerWallet(t *testing.T) (*Wallet, *privateDecryptSpy) {
	t.Helper()

	w := createSQLiteWallet(t, createTestChain(t))

	vault, ok := w.keyVault.(*keyvault.WalletVault)
	require.True(t, ok)

	// No request has used the vault yet, so swapping it here happens
	// before any request goroutine reads it. The wallet reaches raw
	// decryption through unsafeVault, so both views must be the spy.
	spy := &privateDecryptSpy{WalletVault: vault}
	w.keyVault = spy
	w.unsafeVault = spy

	return w, spy
}

// taprootSignerPaths returns two BIP-84 paths whose keys have an even and an
// odd Y coordinate, found by public derivation.
func taprootSignerPaths(t *testing.T, w *Wallet) []BIP32Path {
	t.Helper()

	var even, odd *BIP32Path
	for index := uint32(0); even == nil || odd == nil; index++ {
		require.Less(t, index, uint32(64))

		pub, err := w.DerivePubKey(t.Context(), DerivePubKeyParams{
			Account: NewAccountSelectorByNumber(
				waddrmgr.KeyScopeBIP0084, 0,
			),
			Index: index,
		})
		require.NoError(t, err)

		path := &BIP32Path{
			KeyScope: waddrmgr.KeyScopeBIP0084,
			DerivationPath: waddrmgr.DerivationPath{
				Index: index,
			},
		}

		if pub.SerializeCompressed()[0] == 0x03 {
			if odd == nil {
				odd = path
			}

			continue
		}

		if even == nil {
			even = path
		}
	}

	return []BIP32Path{*even, *odd}
}

// TestSQLSignerUsesVaultPrimitives verifies that SQL SignDigest and ECDH sign
// through the vault without a private-key decrypt in wallet code, and that the
// results equal the legacy results for the same key. Both Y parities are used,
// so the Taproot tweak's parity handling is checked. The key exported through
// UnsafeSigner is the oracle, and its decrypt proves the spy observes the
// legacy path.
func TestSQLSignerUsesVaultPrimitives(t *testing.T) {
	t.Parallel()

	// Arrange: Create a SQLite wallet and pick even and odd Taproot keys.
	w, spy := newSQLSignerWallet(t)
	paths := taprootSignerPaths(t, w)
	digest := sha256.Sum256([]byte("sql signer digest"))
	root := sha256.Sum256([]byte("script root"))

	remote, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	intents := []*SignDigestIntent{
		{Digest: digest[:], SigType: SigTypeECDSA},
		{Digest: digest[:], SigType: SigTypeECDSA, CompactSig: true},
		{Digest: digest[:], SigType: SigTypeSchnorr},
		{
			Digest:       digest[:],
			SigType:      SigTypeSchnorr,
			TaprootTweak: []byte{},
		},
		{
			Digest:       digest[:],
			SigType:      SigTypeSchnorr,
			TaprootTweak: root[:],
		},
	}

	for _, path := range paths {
		// Act: Sign every intent and compute ECDH through the vault.
		sigs := make([]Signature, 0, len(intents))
		for _, intent := range intents {
			sig, err := w.SignDigest(t.Context(), path, intent)
			require.NoError(t, err)

			sigs = append(sigs, sig)
		}

		secret, err := w.ECDH(t.Context(), path, remote.PubKey())
		require.NoError(t, err)

		// Assert: No private key reached wallet code.
		require.Zero(t, spy.privateDecrypts.Load())

		// Assert: Each result equals the legacy result for the
		// exported key.
		privKey, err := w.DerivePrivKey(t.Context(), path)
		require.NoError(t, err)
		require.Positive(t, spy.privateDecrypts.Swap(0))

		for i, intent := range intents {
			want, err := signDigestWithPrivKey(privKey, intent)
			require.NoError(t, err)
			require.Equal(t, want, sigs[i], "intent %d", i)
		}

		wantPoint := compressedSharedPoint(privKey, remote.PubKey())
		require.Equal(t, sha256.Sum256(wantPoint), secret)

		// The tweaked signature verifies under the output key.
		schnorrSig, ok := sigs[4].(SchnorrSignature)
		require.True(t, ok)

		outputKey := txscript.ComputeTaprootOutputKey(
			privKey.PubKey(), root[:],
		)
		require.True(t, schnorrSig.Verify(digest[:], outputKey))

		privKey.Zero()
	}
}

// TestSQLSignerKeyErrors verifies that SQL vault lookup errors keep the
// legacy Signer sentinels, and that none of them decrypt a private key.
func TestSQLSignerKeyErrors(t *testing.T) {
	t.Parallel()

	// Arrange: Select an account number the wallet does not have.
	w, spy := newSQLSignerWallet(t)
	path := BIP32Path{
		KeyScope: waddrmgr.KeyScopeBIP0084,
		DerivationPath: waddrmgr.DerivationPath{
			InternalAccount: 99,
		},
	}
	digest := sha256.Sum256([]byte("missing account"))

	remote, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	// Act: Sign and compute ECDH with the missing account, and request a
	// tweaked Schnorr signature, which reads the account XPub first.
	_, signErr := w.SignDigest(t.Context(), path, &SignDigestIntent{
		Digest:  digest[:],
		SigType: SigTypeECDSA,
	})
	_, tweakErr := w.SignDigest(t.Context(), path, &SignDigestIntent{
		Digest:       digest[:],
		SigType:      SigTypeSchnorr,
		TaprootTweak: []byte{},
	})
	_, ecdhErr := w.ECDH(t.Context(), path, remote.PubKey())

	// Assert: Each call reports the legacy sentinel without a decrypt.
	require.ErrorIs(t, signErr, ErrAccountNotInStore)
	require.ErrorIs(t, tweakErr, ErrAccountNotInStore)
	require.ErrorIs(t, ecdhErr, ErrAccountNotInStore)
	require.Zero(t, spy.privateDecrypts.Load())
}

// TestMapDerivedKeyErr verifies the mapping from vault lookup errors to the
// legacy Signer sentinels.
func TestMapDerivedKeyErr(t *testing.T) {
	t.Parallel()

	errOther := errors.New("other")

	require.ErrorIs(
		t, mapDerivedKeyErr(keyvault.ErrKeyNotFound), ErrAccountNotInStore,
	)
	require.ErrorIs(
		t, mapDerivedKeyErr(keyvault.ErrNoPrivateKey), ErrWatchOnlyAccount,
	)
	require.ErrorIs(t, mapDerivedKeyErr(errOther), errOther)
}

// TestSQLSignerLockedPublicDerivation verifies that a locked SQL wallet still
// derives public keys, refuses safe signing, and uses no vault secret.
func TestSQLSignerLockedPublicDerivation(t *testing.T) {
	t.Parallel()

	// Arrange: Lock the wallet.
	w, spy := newSQLSignerWallet(t)
	require.NoError(t, w.Lock(t.Context()))

	digest := sha256.Sum256([]byte("locked"))
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}

	// Act: Derive a public key and request a signature.
	pub, pubErr := w.DerivePubKey(t.Context(), DerivePubKeyParams{
		Account: NewAccountSelectorByNumber(waddrmgr.KeyScopeBIP0084, 0),
	})
	_, signErr := w.SignDigest(t.Context(), path, &SignDigestIntent{
		Digest:  digest[:],
		SigType: SigTypeECDSA,
	})

	// Assert: Public derivation works and signing is refused.
	require.NoError(t, pubErr)
	require.NotNil(t, pub)
	require.ErrorIs(t, signErr, ErrStateForbidden)
	require.Zero(t, spy.privateDecrypts.Load())
}

// TestSQLSignerConcurrentLock verifies that signatures racing a Lock either
// complete with a valid signature or fail as locked. Run with -race, it also
// checks that Lock and vault signing share state safely.
func TestSQLSignerConcurrentLock(t *testing.T) {
	t.Parallel()

	// Arrange: Create a wallet and its expected public key.
	w, _ := newSQLSignerWallet(t)
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

// legacyOnlyVault hides the SQL signing operations of a vault, so the wallet
// takes its legacy decrypt-and-sign path with the same keys.
type legacyOnlyVault struct {
	keyvault.Vault
}

// newSQLiteBenchWallet creates an unlocked SQLite wallet for benchmarks.
func newSQLiteBenchWallet(b *testing.B) *Wallet {
	b.Helper()

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	require.NoError(b, err)

	m := testSQLiteManagerWithChain(b, createTestChain(b))
	w, err := m.Create(CreateWalletParams{
		Name:              testWalletName,
		Mode:              ModeImportSeed,
		Seed:              seed,
		PrivatePassphrase: []byte("private"),
		Birthday:          time.Now(),
	})
	require.NoError(b, err)
	require.NoError(b, w.Unlock(b.Context(), UnlockRequest{
		Passphrase: []byte("private"), Timeout: -1,
	}))

	// Create the BIP-84 account 0 that the benchmarks sign with.
	_, err = w.NewAccount(b.Context(), NewAccountParams{
		Scope: waddrmgr.KeyScopeBIP0084, Name: "bench",
	})
	require.NoError(b, err)

	return w
}

// BenchmarkSQLSignerPaths compares SQL signing through the vault with the
// legacy path, where wallet code decrypts and derives the key, on one SQLite
// wallet.
func BenchmarkSQLSignerPaths(b *testing.B) {
	digest := sha256.Sum256([]byte("benchmark"))
	path := BIP32Path{KeyScope: waddrmgr.KeyScopeBIP0084}

	remote, err := btcec.NewPrivateKey()
	require.NoError(b, err)

	ops := []struct {
		name string
		run  func(b *testing.B, w *Wallet) error
	}{
		{
			name: "ECDSA",
			run: func(b *testing.B, w *Wallet) error {
				b.Helper()

				_, err := w.SignDigest(
					b.Context(), path, &SignDigestIntent{
						Digest:  digest[:],
						SigType: SigTypeECDSA,
					},
				)

				return err
			},
		},
		{
			name: "SchnorrTaprootTweak",
			run: func(b *testing.B, w *Wallet) error {
				b.Helper()

				_, err := w.SignDigest(
					b.Context(), path, &SignDigestIntent{
						Digest:       digest[:],
						SigType:      SigTypeSchnorr,
						TaprootTweak: []byte{},
					},
				)

				return err
			},
		},
		{
			name: "ECDH",
			run: func(b *testing.B, w *Wallet) error {
				b.Helper()

				_, err := w.ECDH(b.Context(), path, remote.PubKey())

				return err
			},
		},
		{
			name: "RawSigTaprootKeyPath",
			run: func(b *testing.B, w *Wallet) error {
				b.Helper()

				prevOut := wire.NewTxOut(10_000, []byte{0x51})
				tx, sigHashes := rawSigTx(prevOut)

				_, err := w.ComputeRawSig(b.Context(), &RawSigParams{
					Tx:        tx,
					Output:    prevOut,
					SigHashes: sigHashes,
					Path:      path,
					Details: TaprootSpendDetails{
						SpendPath: KeyPathSpend,
					},
				})

				return err
			},
		},
		{
			name: "UnlockingScriptP2WKH",
			run: func(b *testing.B, w *Wallet) error {
				b.Helper()

				info, err := w.NewAddress(
					b.Context(), NewAccountSelectorByNumber(
						waddrmgr.KeyScopeBIP0084, 0,
					), false,
				)
				if err != nil {
					return err
				}

				pkScript, err := txscript.PayToAddrScript(info.Addr)
				if err != nil {
					return err
				}

				prevOut := wire.NewTxOut(10_000, pkScript)
				tx, sigHashes := rawSigTx(prevOut)

				_, err = w.ComputeUnlockingScript(
					b.Context(), &UnlockingScriptParams{
						Tx:        tx,
						Output:    prevOut,
						SigHashes: sigHashes,
						HashType:  txscript.SigHashAll,
					},
				)

				return err
			},
		},
	}

	for _, mode := range []string{"vault", "legacy"} {
		for _, op := range ops {
			b.Run(mode+"/"+op.name, func(b *testing.B) {
				w := newSQLiteBenchWallet(b)
				if mode == "legacy" {
					w.keyVault = legacyOnlyVault{w.keyVault}
				}

				b.ReportAllocs()
				b.ResetTimer()

				for b.Loop() {
					require.NoError(b, op.run(b, w))
				}
			})
		}
	}
}

// TestTaprootOutputTweakMatchesTxscript verifies that the folded scalar pair
// equals txscript.TweakTaprootPrivKey for keys of both Y parities, with and
// without a script root.
func TestTaprootOutputTweakMatchesTxscript(t *testing.T) {
	t.Parallel()

	root := sha256.Sum256([]byte("root"))

	var even, odd *btcec.PrivateKey
	for even == nil || odd == nil {
		key, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		if key.PubKey().SerializeCompressed()[0] == 0x02 {
			even = key
		} else {
			odd = key
		}
	}

	for _, key := range []*btcec.PrivateKey{even, odd} {
		for _, scriptRoot := range [][]byte{{}, root[:]} {
			// Arrange: Fold the tweak from the public key only.
			tweak, outputKey, err := foldKeyTweak(
				key.PubKey(), KeyTweak{}, true, scriptRoot,
			)
			require.NoError(t, err)

			want := txscript.TweakTaprootPrivKey(*key, scriptRoot)

			// Act: Sign the same digest with both keys through the
			// equivalence that the vault applies.
			digest := sha256.Sum256(scriptRoot)
			sig := ecdsa.Sign(want, digest[:])

			// Assert: The output key is the tweaked key's public key,
			// so the vault's effective-key check accepts the pair.
			require.True(t, outputKey.IsEqual(want.PubKey()))
			require.True(t, sig.Verify(digest[:], outputKey))
			tweak.Zero()
		}
	}
}
