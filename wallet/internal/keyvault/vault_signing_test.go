package keyvault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/waddrmgr"
	bwmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const signingWalletID = uint32(11)

var (
	// testScope is the key scope used by the derived-key fixtures.
	testScope = waddrmgr.KeyScopeBIP0084

	// testScriptPubKey selects the imported-key fixtures.
	testScriptPubKey = []byte{0x00, 0x14, 0x01, 0x02}

	// testDigest is the digest the signing tests sign.
	testDigest = sha256.Sum256([]byte("vault signing digest"))
)

// signingVault is an unlocked WalletVault over a mock Store, plus the account
// key the fixtures encrypt into that Store.
type signingVault struct {
	vault   *WalletVault
	store   *bwmock.Store
	state   *unlockedState
	account *hdkeychain.ExtendedKey
}

// newSigningVault returns an unlocked vault over a mock Store. The mock has
// no expectations, so any Store call a test does not program fails it.
func newSigningVault(t *testing.T) *signingVault {
	t.Helper()

	store := new(bwmock.Store)
	t.Cleanup(func() {
		store.AssertExpectations(t)
	})

	vault := NewWalletVault(store, signingWalletID, false)
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

	return &signingVault{
		vault:   vault,
		store:   store,
		state:   stateCopy,
		account: account,
	}
}

// encrypt encrypts plaintext under the vault's private crypto key.
func (f *signingVault) encrypt(t *testing.T, plaintext []byte) []byte {
	t.Helper()

	ciphertext, err := f.state.cryptoKeyPrivate.Encrypt(plaintext)
	require.NoError(t, err)

	return ciphertext
}

// expectAccountSecret programs one account secret read and returns the
// ciphertext the Store hands out, so a test can check that it is cleared.
func (f *signingVault) expectAccountSecret(t *testing.T,
	account uint32) []byte {

	t.Helper()

	ciphertext := f.encrypt(t, []byte(f.account.String()))
	f.store.On("GetAccountSecret", mock.Anything, db.GetAccountSecretQuery{
		WalletID:      signingWalletID,
		Scope:         db.KeyScope(testScope),
		AccountNumber: account,
	}).Return(&db.AccountSecret{EncryptedPrivateKey: ciphertext}, nil).Once()

	return ciphertext
}

// expectImportedSecret programs one imported key read for testScriptPubKey.
func (f *signingVault) expectImportedSecret(t *testing.T,
	privKey []byte) []byte {

	t.Helper()

	ciphertext := f.encrypt(t, privKey)
	f.store.On("GetAddressSecret", mock.Anything, db.GetAddressSecretQuery{
		WalletID:     signingWalletID,
		ScriptPubKey: testScriptPubKey,
	}).Return(&db.AddressSecret{EncryptedPrivKey: ciphertext}, nil).Once()

	return ciphertext
}

// leafKey returns the expected private key at branch/index of the fixture
// account.
func (f *signingVault) leafKey(t *testing.T, branch,
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

// scalarHex parses a 32-byte big-endian hex scalar.
func scalarHex(t *testing.T, value string) *btcec.ModNScalar {
	t.Helper()

	raw, err := hex.DecodeString(value)
	require.NoError(t, err)

	var scalar btcec.ModNScalar
	require.False(t, scalar.SetByteSlice(raw))

	return &scalar
}

// pubKeyHex parses a hex public key.
func pubKeyHex(t *testing.T, value string) *btcec.PublicKey {
	t.Helper()

	raw, err := hex.DecodeString(value)
	require.NoError(t, err)

	key, err := btcec.ParsePubKey(raw)
	require.NoError(t, err)

	return key
}

// sha256Scalar returns SHA-256 of the concatenated inputs as a scalar.
func sha256Scalar(parts ...[]byte) *btcec.ModNScalar {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write(part)
	}

	var scalar btcec.ModNScalar
	scalar.SetByteSlice(hash.Sum(nil))

	return &scalar
}

// TestWalletVaultSignDigestModes verifies that each signing mode signs with
// the derived child key selected by scope, BIP44 number, branch and index, and
// that the Store ciphertext is cleared after use.
func TestWalletVaultSignDigestModes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mode   SignMode
		verify func(t *testing.T, key *btcec.PublicKey, sig DigestSignature)
	}{
		{
			name: "ecdsa",
			mode: SignModeECDSA,
			verify: func(t *testing.T, key *btcec.PublicKey,
				sig DigestSignature) {

				t.Helper()

				require.True(t, sig.ECDSA.Verify(testDigest[:], key))
				require.Nil(t, sig.Compact)
				require.Nil(t, sig.Schnorr)
			},
		},
		{
			name: "compact ecdsa",
			mode: SignModeCompactECDSA,
			verify: func(t *testing.T, key *btcec.PublicKey,
				sig DigestSignature) {

				t.Helper()

				recovered, compressed, err := ecdsa.RecoverCompact(
					sig.Compact, testDigest[:],
				)
				require.NoError(t, err)
				require.True(t, compressed)
				require.True(t, recovered.IsEqual(key))
			},
		},
		{
			name: "schnorr",
			mode: SignModeSchnorr,
			verify: func(t *testing.T, key *btcec.PublicKey,
				sig DigestSignature) {

				t.Helper()

				require.True(t, sig.Schnorr.Verify(testDigest[:], key))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Store the account key and select one child.
			f := newSigningVault(t)
			ciphertext := f.expectAccountSecret(t, 0)
			want := f.leafKey(t, 1, 7)

			// Act: Sign the digest in the requested mode.
			sig, err := f.vault.SignDigest(
				t.Context(), SignDigestRequest{
					Key:    DerivedKey(testScope, 0, 1, 7),
					Digest: testDigest,
					Mode:   test.mode,
				},
			)

			// Assert: The child key signed, and the vault cleared the
			// ciphertext it read.
			require.NoError(t, err)
			test.verify(t, want.PubKey(), sig)
			require.Equal(t, make([]byte, len(ciphertext)), ciphertext)
		})
	}
}

// TestWalletVaultSignDigestImportedKey verifies that a raw imported key is
// selected by its script pubkey and signs without leaving the vault.
func TestWalletVaultSignDigestImportedKey(t *testing.T) {
	t.Parallel()

	// Arrange: Store one raw imported key.
	f := newSigningVault(t)
	want, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	f.expectImportedSecret(t, want.Serialize())

	// Act: Sign through the script pubkey selector.
	sig, err := f.vault.SignDigest(t.Context(), SignDigestRequest{
		Key:    ImportedKey(testScriptPubKey),
		Digest: testDigest,
		Mode:   SignModeSchnorr,
	})

	// Assert: The imported key produced the signature.
	require.NoError(t, err)
	require.True(t, sig.Schnorr.Verify(testDigest[:], want.PubKey()))
}

// TestWalletVaultKeyTweakBOLT3 verifies the affine key tweak against the BOLT
// 3 Appendix E key derivation vectors. The Lightning hashes are computed here,
// as lnd computes them; the vault only applies mul*d + add. Each case signs
// with ECDSA and Schnorr and checks the effective key before signing.
func TestWalletVaultKeyTweakBOLT3(t *testing.T) {
	t.Parallel()

	const (
		baseSecret = "000102030405060708090a0b0c0d0e0f101112131415161718" +
			"191a1b1c1d1e1f"
		perCommitmentSecret = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b" +
			"0a09080706050403020100"
		basePoint = "036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a" +
			"95b216691468e2"
		perCommitmentPoint = "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd" +
			"25eaf467a4a1c2a45ce1486"
		localPubKey = "0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc" +
			"43f5494984db29e5"
		revocationPubKey = "02916e326636d19c33f13e8c0c3a03dd157f332f3e99c3" +
			"17c141dd865eb01f8ff0"
	)

	baseRaw, err := hex.DecodeString(baseSecret)
	require.NoError(t, err)

	base := pubKeyHex(t, basePoint)
	commitPoint := pubKeyHex(t, perCommitmentPoint)
	commitSecret := scalarHex(t, perCommitmentSecret)

	// Single tweak: d + SHA256(per_commitment_point || basepoint).
	single := sha256Scalar(
		commitPoint.SerializeCompressed(), base.SerializeCompressed(),
	)

	// Revocation: d*SHA256(R || P) + s*SHA256(P || R).
	revMul := sha256Scalar(
		base.SerializeCompressed(), commitPoint.SerializeCompressed(),
	)
	revAdd := sha256Scalar(
		commitPoint.SerializeCompressed(), base.SerializeCompressed(),
	)
	revAdd.Mul(commitSecret)

	// Revocation followed by the single tweak folds into one pair.
	var revSingleAdd btcec.ModNScalar
	revSingleAdd.Set(revAdd).Add(single)

	var one, zero btcec.ModNScalar
	one.SetInt(1)

	// combinedKey is (r*d + c*s + t)*G, built from public keys only.
	combinedKey := func() *btcec.PublicKey {
		var basePart, addPart, sum btcec.JacobianPoint
		base.AsJacobian(&basePart)
		btcec.ScalarMultNonConst(revMul, &basePart, &basePart)
		btcec.ScalarBaseMultNonConst(&revSingleAdd, &addPart)
		btcec.AddNonConst(&basePart, &addPart, &sum)
		sum.ToAffine()

		return btcec.NewPublicKey(&sum.X, &sum.Y)
	}

	tests := []struct {
		name      string
		mul       *btcec.ModNScalar
		add       *btcec.ModNScalar
		effective *btcec.PublicKey
	}{
		{
			name:      "identity",
			mul:       &one,
			add:       &zero,
			effective: base,
		},
		{
			name:      "single",
			mul:       &one,
			add:       single,
			effective: pubKeyHex(t, localPubKey),
		},
		{
			name:      "revocation",
			mul:       revMul,
			add:       revAdd,
			effective: pubKeyHex(t, revocationPubKey),
		},
		{
			name:      "revocation and single",
			mul:       revMul,
			add:       &revSingleAdd,
			effective: combinedKey(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			for _, mode := range []SignMode{
				SignModeECDSA, SignModeSchnorr,
			} {
				// Arrange: Store the BOLT 3 base secret as an
				// imported key and build the tweak.
				f := newSigningVault(t)
				f.expectImportedSecret(t, baseRaw)

				tweak, err := NewKeyTweak(test.mul, test.add)
				require.NoError(t, err)

				// Act: Sign under the tweak with the expected
				// effective key.
				sig, err := f.vault.SignDigest(
					t.Context(), SignDigestRequest{
						Key:          ImportedKey(testScriptPubKey),
						Digest:       testDigest,
						Mode:         mode,
						Tweak:        tweak,
						EffectiveKey: test.effective,
					},
				)

				// Assert: The signature verifies under the vector's
				// effective key.
				require.NoError(t, err)

				if mode == SignModeECDSA {
					require.True(t, sig.ECDSA.Verify(
						testDigest[:], test.effective,
					))

					continue
				}

				require.True(t, sig.Schnorr.Verify(
					testDigest[:], test.effective,
				))
			}
		})
	}
}

// TestNewKeyTweakRejectsZeroMultiplier verifies that a zero multiplier, which
// would discard the wallet key, is refused when the tweak is built.
func TestNewKeyTweakRejectsZeroMultiplier(t *testing.T) {
	t.Parallel()

	var zero, add btcec.ModNScalar
	add.SetInt(5)

	_, err := NewKeyTweak(&zero, &add)
	require.ErrorIs(t, err, ErrInvalidKeyTweak)

	_, err = NewKeyTweak(nil, &add)
	require.ErrorIs(t, err, ErrInvalidKeyTweak)
}

// TestWalletVaultSignDigestTweakFailures verifies tweak and effective-key
// failures: a cleared tweak fails before any Store read, while a cancelling
// tweak and a wrong effective key fail after derivation without signing.
func TestWalletVaultSignDigestTweakFailures(t *testing.T) {
	t.Parallel()

	keyBytes := sha256.Sum256([]byte("tweak failure key"))
	key, _ := btcec.PrivKeyFromBytes(keyBytes[:])

	var one btcec.ModNScalar
	one.SetInt(1)

	// The add term -d cancels the key into zero.
	var cancel btcec.ModNScalar
	cancel.Set(&key.Key).Negate()

	other, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	tests := []struct {
		name      string
		storeRead bool
		tweak     func(t *testing.T) *KeyTweak
		effective *btcec.PublicKey
		wantErr   error
	}{
		{
			name: "cleared tweak",
			tweak: func(t *testing.T) *KeyTweak {
				t.Helper()

				tweak, err := NewKeyTweak(&one, &one)
				require.NoError(t, err)
				tweak.Zero()

				return tweak
			},
			wantErr: ErrInvalidKeyTweak,
		},
		{
			name:      "cancelling tweak",
			storeRead: true,
			tweak: func(t *testing.T) *KeyTweak {
				t.Helper()

				tweak, err := NewKeyTweak(&one, &cancel)
				require.NoError(t, err)

				return tweak
			},
			wantErr: ErrInvalidKeyTweak,
		},
		{
			name:      "effective key mismatch",
			storeRead: true,
			tweak: func(t *testing.T) *KeyTweak {
				t.Helper()

				return nil
			},
			effective: other.PubKey(),
			wantErr:   ErrEffectiveKeyMismatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Program a Store read only for cases that pass
			// request validation.
			f := newSigningVault(t)
			if test.storeRead {
				f.expectImportedSecret(t, key.Serialize())
			}

			// Act: Request a signature.
			sig, err := f.vault.SignDigest(
				t.Context(), SignDigestRequest{
					Key:          ImportedKey(testScriptPubKey),
					Digest:       testDigest,
					Mode:         SignModeSchnorr,
					Tweak:        test.tweak(t),
					EffectiveKey: test.effective,
				},
			)

			// Assert: No signature is returned.
			require.ErrorIs(t, err, test.wantErr)
			require.Equal(t, DigestSignature{}, sig)
		})
	}
}

// TestWalletVaultSigningInvalidRequests verifies that malformed requests fail
// before any Store read. The fixture Store has no expectations, so a read
// fails the test.
func TestWalletVaultSigningInvalidRequests(t *testing.T) {
	t.Parallel()

	f := newSigningVault(t)

	_, err := f.vault.SignDigest(t.Context(), SignDigestRequest{
		Digest: testDigest,
		Mode:   SignModeECDSA,
	})
	require.ErrorIs(t, err, ErrInvalidKeySelector)

	_, err = f.vault.SignDigest(t.Context(), SignDigestRequest{
		Key:    ImportedKey(nil),
		Digest: testDigest,
		Mode:   SignModeECDSA,
	})
	require.ErrorIs(t, err, ErrInvalidKeySelector)

	_, err = f.vault.SignDigest(t.Context(), SignDigestRequest{
		Key:    DerivedKey(testScope, 0, 0, 0),
		Digest: testDigest,
	})
	require.ErrorIs(t, err, ErrInvalidSignMode)

	_, err = f.vault.ECDH(t.Context(), DerivedKey(testScope, 0, 0, 0), nil)
	require.ErrorIs(t, err, ErrInvalidRemoteKey)

	var x, y btcec.FieldVal
	x.SetInt(1)
	y.SetInt(1)
	_, err = f.vault.ECDH(
		t.Context(), DerivedKey(testScope, 0, 0, 0),
		btcec.NewPublicKey(&x, &y),
	)
	require.ErrorIs(t, err, ErrInvalidRemoteKey)
}

// TestWalletVaultSigningKeyLookupErrors verifies that missing and watch-only
// keys are reported from the Store lookup, before the lock check, and that a
// locked vault refuses a key the Store holds.
func TestWalletVaultSigningKeyLookupErrors(t *testing.T) {
	t.Parallel()

	accountQuery := db.GetAccountSecretQuery{
		WalletID:      signingWalletID,
		Scope:         db.KeyScope(testScope),
		AccountNumber: 3,
	}
	addressQuery := db.GetAddressSecretQuery{
		WalletID:     signingWalletID,
		ScriptPubKey: testScriptPubKey,
	}

	tests := []struct {
		name    string
		key     KeySelector
		arrange func(f *signingVault)
		wantErr error
	}{
		{
			name: "missing account",
			key:  DerivedKey(testScope, 3, 0, 0),
			arrange: func(f *signingVault) {
				f.store.On("GetAccountSecret", mock.Anything,
					accountQuery).Return(
					nil, db.ErrAccountNotFound,
				).Once()
			},
			wantErr: ErrKeyNotFound,
		},
		{
			name: "watch-only account",
			key:  DerivedKey(testScope, 3, 0, 0),
			arrange: func(f *signingVault) {
				f.store.On("GetAccountSecret", mock.Anything,
					accountQuery).Return(
					&db.AccountSecret{}, nil,
				).Once()
			},
			wantErr: ErrNoPrivateKey,
		},
		{
			name: "missing import",
			key:  ImportedKey(testScriptPubKey),
			arrange: func(f *signingVault) {
				f.store.On("GetAddressSecret", mock.Anything,
					addressQuery).Return(
					nil, db.ErrSecretNotFound,
				).Once()
			},
			wantErr: ErrKeyNotFound,
		},
		{
			name: "watch-only import",
			key:  ImportedKey(testScriptPubKey),
			arrange: func(f *signingVault) {
				f.store.On("GetAddressSecret", mock.Anything,
					addressQuery).Return(
					&db.AddressSecret{
						EncryptedScript: []byte{1},
					}, nil,
				).Once()
			},
			wantErr: ErrNoPrivateKey,
		},
		{
			name: "store failure",
			key:  DerivedKey(testScope, 3, 0, 0),
			arrange: func(f *signingVault) {
				f.store.On("GetAccountSecret", mock.Anything,
					accountQuery).Return(
					nil, context.Canceled,
				).Once()
			},
			wantErr: context.Canceled,
		},
		{
			name: "locked",
			key:  ImportedKey(testScriptPubKey),
			arrange: func(f *signingVault) {
				f.expectImportedSecret(t, make([]byte, 32))
			},
			wantErr: ErrVaultLocked,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Lock the vault, so only the Store lookup can
			// classify the key.
			f := newSigningVault(t)
			f.vault.Lock()
			test.arrange(f)

			// Act: Request ECDH, which uses the same key path.
			remote, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			_, err = f.vault.ECDH(t.Context(), test.key, remote.PubKey())

			// Assert: The lookup error is returned.
			require.ErrorIs(t, err, test.wantErr)
		})
	}
}

// TestWalletVaultECDHBOLT8Vectors verifies that the vault returns the BOLT 8
// Appendix A ss values: SHA-256 of the compressed shared point, for both Y
// parities, matching lnd's keychain.ECDHRing.
func TestWalletVaultECDHBOLT8Vectors(t *testing.T) {
	t.Parallel()

	vectors := []struct {
		name       string
		privKey    string
		remotePub  string
		wantSecret string
	}{
		{
			name: "act one es even",
			privKey: "1212121212121212121212121212121212121212121212" +
				"121212121212121212",
			remotePub: "028d7500dd4c12685d1f568b4c2b5048e8534b873319f3" +
				"a8daa612b469132ec7f7",
			wantSecret: "1e2fb3c8fe8fb9f262f649f64d26ecf0f2c0a805a767cf" +
				"02dc2d77a6ef1fdcc3",
		},
		{
			name: "act two ee odd",
			privKey: "1212121212121212121212121212121212121212121212" +
				"121212121212121212",
			remotePub: "02466d7fcae563e5cb09a0d1870bb580344804617879a1" +
				"4949cf22285f1bae3f27",
			wantSecret: "c06363d6cc549bcb7913dbb9ac1c33fc1158680c89e972" +
				"000ecd06b36c472e47",
		},
		{
			name: "act three se even",
			privKey: "1111111111111111111111111111111111111111111111" +
				"111111111111111111",
			remotePub: "02466d7fcae563e5cb09a0d1870bb580344804617879a1" +
				"4949cf22285f1bae3f27",
			wantSecret: "b36b6d195982c5be874d6d542dc268234379e1ae4ff170" +
				"9402135b7de5cf0766",
		},
	}

	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Store the vector key as an imported key.
			f := newSigningVault(t)
			privKey, err := hex.DecodeString(vector.privKey)
			require.NoError(t, err)
			f.expectImportedSecret(t, privKey)

			// Act: Compute ECDH with the remote vector key.
			secret, err := f.vault.ECDH(
				t.Context(), ImportedKey(testScriptPubKey),
				pubKeyHex(t, vector.remotePub),
			)

			// Assert: The digest is the vector's ss.
			require.NoError(t, err)
			require.Equal(t, vector.wantSecret, hex.EncodeToString(
				secret[:],
			))
		})
	}
}

// TestWalletVaultECDHDerivedKey verifies that ECDH with a derived key equals
// SHA-256 of the compressed point computed with btcec on the expected key.
func TestWalletVaultECDHDerivedKey(t *testing.T) {
	t.Parallel()

	// Arrange: Store the account key and pick a remote key.
	f := newSigningVault(t)
	f.expectAccountSecret(t, 0)
	want := f.leafKey(t, 0, 2)
	remote, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	var remotePoint, shared btcec.JacobianPoint
	remote.PubKey().AsJacobian(&remotePoint)
	btcec.ScalarMultNonConst(&want.Key, &remotePoint, &shared)
	shared.ToAffine()
	expected := sha256.Sum256(
		btcec.NewPublicKey(&shared.X, &shared.Y).SerializeCompressed(),
	)

	// Act: Compute ECDH in the vault.
	secret, err := f.vault.ECDH(
		t.Context(), DerivedKey(testScope, 0, 0, 2), remote.PubKey(),
	)

	// Assert: The vault digest matches the independent result.
	require.NoError(t, err)
	require.Equal(t, expected, secret)
}

// TestWalletVaultSigningClearsPlaintext verifies that the decrypted key
// material is cleared on success, on a tweak error and on a panic, and that a
// panic releases the guard. It replaces package hooks, so it does not run in
// parallel.
//
//nolint:paralleltest
func TestWalletVaultSigningClearsPlaintext(t *testing.T) {
	var plaintext []byte

	decryptPrivateSecret = func(key *snacl.CryptoKey,
		ciphertext []byte) ([]byte, error) {

		var err error

		plaintext, err = key.Decrypt(ciphertext)

		return plaintext, err
	}
	t.Cleanup(func() {
		decryptPrivateSecret = func(key *snacl.CryptoKey,
			ciphertext []byte) ([]byte, error) {

			return key.Decrypt(ciphertext)
		}
		privateKeyReadyHook = nil
	})

	keyBytes := sha256.Sum256([]byte("cleanup key"))
	key, _ := btcec.PrivKeyFromBytes(keyBytes[:])

	var one, cancel btcec.ModNScalar
	one.SetInt(1)
	cancel.Set(&key.Key).Negate()

	cancelTweak, err := NewKeyTweak(&one, &cancel)
	require.NoError(t, err)

	tests := []struct {
		name    string
		tweak   *KeyTweak
		hook    func()
		wantErr error
		panics  bool
	}{
		{
			name: "success",
		},
		{
			name:    "tweak error",
			tweak:   cancelTweak,
			wantErr: ErrInvalidKeyTweak,
		},
		{
			name:   "panic",
			hook:   func() { panic("signer panic") },
			panics: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Arrange: Store the key and install the hook.
			plaintext = nil
			privateKeyReadyHook = test.hook
			f := newSigningVault(t)
			ciphertext := f.expectImportedSecret(t, key.Serialize())

			req := SignDigestRequest{
				Key:    ImportedKey(testScriptPubKey),
				Digest: testDigest,
				Mode:   SignModeECDSA,
				Tweak:  test.tweak,
			}

			// Act: Sign, recovering a panic for inspection.
			sign := func() {
				_, err = f.vault.SignDigest(t.Context(), req)
			}

			if test.panics {
				require.PanicsWithValue(t, "signer panic", sign)
			} else {
				sign()
				require.ErrorIs(t, err, test.wantErr)
			}

			// Assert: Both buffers are cleared, and the guard is free.
			require.Len(t, plaintext, btcec.PrivKeyBytesLen)
			require.Equal(t, make([]byte, len(plaintext)), plaintext)
			require.Equal(t, make([]byte, len(ciphertext)), ciphertext)

			locked := make(chan struct{})
			go func() {
				f.vault.Lock()
				close(locked)
			}()

			select {
			case <-locked:
			case <-time.After(5 * time.Second):
				t.Fatal("Lock blocked after the operation returned")
			}
		})
	}
}

// TestWalletVaultLockWaitsForSigning verifies that Lock waits for a signing
// operation that holds the guard, and that the next operation then reports
// ErrVaultLocked. It replaces a package hook, so it does not run in parallel.
//
//nolint:paralleltest
func TestWalletVaultLockWaitsForSigning(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	privateKeyReadyHook = func() {
		close(entered)
		<-release
	}
	t.Cleanup(func() {
		privateKeyReadyHook = nil
	})

	// Arrange: Store one key and start a signature that blocks under the
	// guard.
	f := newSigningVault(t)
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	f.expectImportedSecret(t, key.Serialize())

	signed := make(chan error, 1)
	go func() {
		_, err := f.vault.SignDigest(t.Context(), SignDigestRequest{
			Key:    ImportedKey(testScriptPubKey),
			Digest: testDigest,
			Mode:   SignModeECDSA,
		})
		signed <- err
	}()

	<-entered

	// Act: Lock while the signature holds the guard.
	locked := make(chan struct{})
	go func() {
		f.vault.Lock()
		close(locked)
	}()

	// Assert: Lock waits for the signature, which then succeeds.
	select {
	case <-locked:
		t.Fatal("Lock returned while a signature held the key")
	case <-time.After(50 * time.Millisecond):
	}

	privateKeyReadyHook = nil

	close(release)
	require.NoError(t, <-signed)

	<-locked
	require.True(t, f.vault.IsLocked())

	f.expectImportedSecret(t, key.Serialize())
	_, err = f.vault.SignDigest(t.Context(), SignDigestRequest{
		Key:    ImportedKey(testScriptPubKey),
		Digest: testDigest,
		Mode:   SignModeECDSA,
	})
	require.ErrorIs(t, err, ErrVaultLocked)
}

// TestWalletVaultSigningWatchOnlyWallet verifies that a watch-only wallet
// vault, which holds no private crypto key, refuses to sign.
func TestWalletVaultSigningWatchOnlyWallet(t *testing.T) {
	t.Parallel()

	// Arrange: Turn the fixture into a watch-only vault.
	f := newSigningVault(t)
	f.vault.watchOnly = true
	f.expectImportedSecret(t, make([]byte, 32))

	// Act: Request a signature.
	_, err := f.vault.SignDigest(t.Context(), SignDigestRequest{
		Key:    ImportedKey(testScriptPubKey),
		Digest: testDigest,
		Mode:   SignModeECDSA,
	})

	// Assert: The private crypto key is unavailable.
	require.ErrorIs(t, err, errUnsupportedCryptoKeyType)
}
