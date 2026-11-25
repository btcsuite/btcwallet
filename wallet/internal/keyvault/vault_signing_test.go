package keyvault

import (
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/signing"
	"github.com/stretchr/testify/require"
)

// testDigest is the digest the signing tests sign.
var testDigest = sha256.Sum256([]byte("vault signing digest"))

// testDerivedKey selects the account child the digest signing tests sign
// with: branch 1, index 7 of the fixture account.
var testDerivedKey = signing.DerivedKey{
	KeyScope: testScope,
	DerivationPath: waddrmgr.DerivationPath{
		Branch: 1,
		Index:  7,
	},
}

// TestWalletVaultSignDigestECDSA verifies that an ECDSA request signs with the
// derived child key selected by scope, BIP44 number, branch and index, and
// that the Store ciphertext is cleared after use.
func TestWalletVaultSignDigestECDSA(t *testing.T) {
	t.Parallel()

	// Arrange: A vault over the fixture account.
	f := newKeyFixture(t)
	want := f.leafKey(t, 1, 7).PubKey()
	ciphertext := f.expectAccountSecret(
		t, testDerivedKey.DerivationPath.InternalAccount,
	)

	// Act: Sign the digest with ECDSA.
	sig, err := f.vault.SignDigest(t.Context(), signing.DigestRequest{
		Key:    testDerivedKey,
		Digest: testDigest,
		Mode:   signing.ModeECDSA,
	})
	require.NoError(t, err)

	// Assert: The child key signed, and the vault cleared the ciphertext.
	ecdsaSig, ok := sig.(signing.ECDSASignature)
	require.True(t, ok)
	require.True(t, ecdsaSig.Verify(testDigest[:], want))
	require.Equal(t, make([]byte, len(ciphertext)), ciphertext)
}

// TestWalletVaultSignDigestCompact verifies that a compact ECDSA request
// returns a recoverable signature for the compressed child public key, and
// that the Store ciphertext is cleared after use.
func TestWalletVaultSignDigestCompact(t *testing.T) {
	t.Parallel()

	// Arrange: A vault over the fixture account.
	f := newKeyFixture(t)
	want := f.leafKey(t, 1, 7).PubKey()
	ciphertext := f.expectAccountSecret(
		t, testDerivedKey.DerivationPath.InternalAccount,
	)

	// Act: Sign the digest with compact ECDSA.
	sig, err := f.vault.SignDigest(t.Context(), signing.DigestRequest{
		Key:    testDerivedKey,
		Digest: testDigest,
		Mode:   signing.ModeCompactECDSA,
	})
	require.NoError(t, err)

	// Assert: The signature recovers the compressed child key, and the
	// vault cleared the ciphertext.
	compact, ok := sig.(signing.CompactSignature)
	require.True(t, ok)

	recovered, compressed, err := ecdsa.RecoverCompact(
		compact, testDigest[:],
	)
	require.NoError(t, err)
	require.True(t, compressed)
	require.True(t, recovered.IsEqual(want))
	require.Equal(t, make([]byte, len(ciphertext)), ciphertext)
}

// TestWalletVaultSignDigestSchnorr verifies that a Schnorr request returns a
// BIP-340 signature by the child key, and that the Store ciphertext is
// cleared after use.
func TestWalletVaultSignDigestSchnorr(t *testing.T) {
	t.Parallel()

	// Arrange: A vault over the fixture account.
	f := newKeyFixture(t)
	want := f.leafKey(t, 1, 7).PubKey()
	ciphertext := f.expectAccountSecret(
		t, testDerivedKey.DerivationPath.InternalAccount,
	)

	// Act: Sign the digest with Schnorr.
	sig, err := f.vault.SignDigest(t.Context(), signing.DigestRequest{
		Key:    testDerivedKey,
		Digest: testDigest,
		Mode:   signing.ModeSchnorr,
	})
	require.NoError(t, err)

	// Assert: The child key signed, and the vault cleared the ciphertext.
	schnorrSig, ok := sig.(signing.SchnorrSignature)
	require.True(t, ok)
	require.True(t, schnorrSig.Verify(testDigest[:], want))
	require.Equal(t, make([]byte, len(ciphertext)), ciphertext)
}

// TestWalletVaultSignDigestTweak verifies that the vault signs with
// mul*d + add for a request tweak, here 3*d + 5 computed without KeyTweak,
// and that the Store ciphertext is cleared after use.
func TestWalletVaultSignDigestTweak(t *testing.T) {
	t.Parallel()

	// Arrange: A vault over the fixture account, the tweak 3*d + 5 and the
	// public key of the tweaked child key.
	f := newKeyFixture(t)
	child := f.leafKey(t, 1, 7)
	ciphertext := f.expectAccountSecret(
		t, testDerivedKey.DerivationPath.InternalAccount,
	)

	three := new(btcec.ModNScalar).SetInt(3)
	five := new(btcec.ModNScalar).SetInt(5)

	tweak, err := signing.NewKeyTweak(three.Bytes(), five.Bytes())
	require.NoError(t, err)

	tweakedKey := child.Key
	tweakedKey.Mul(three).Add(five)
	want := btcec.PrivKeyFromScalar(&tweakedKey).PubKey()

	// Act: Sign the digest with ECDSA under the tweak.
	sig, err := f.vault.SignDigest(t.Context(), signing.DigestRequest{
		Key:    testDerivedKey,
		Digest: testDigest,
		Mode:   signing.ModeECDSA,
		Tweak:  tweak,
	})
	require.NoError(t, err)

	// Assert: The tweaked key signed, and the vault cleared the ciphertext.
	ecdsaSig, ok := sig.(signing.ECDSASignature)
	require.True(t, ok)
	require.True(t, ecdsaSig.Verify(testDigest[:], want))
	require.Equal(t, make([]byte, len(ciphertext)), ciphertext)
}

// TestWalletVaultSignDigestImportedKey verifies that a raw imported key is
// selected by its script pubkey and signs without leaving the vault.
func TestWalletVaultSignDigestImportedKey(t *testing.T) {
	t.Parallel()

	// Arrange: Store one raw imported key.
	f := newKeyFixture(t)
	want, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	ciphertext := f.expectImportedSecret(t, want.Serialize())

	// Act: Sign through the script pubkey selector.
	sig, err := f.vault.SignDigest(t.Context(), signing.DigestRequest{
		Key:    testImportedKey,
		Digest: testDigest,
		Mode:   signing.ModeSchnorr,
	})

	// Assert: The imported key produced the signature.
	require.NoError(t, err)

	schnorrSig, ok := sig.(signing.SchnorrSignature)
	require.True(t, ok)
	require.True(t, schnorrSig.Verify(testDigest[:], want.PubKey()))
	require.Equal(t, make([]byte, len(ciphertext)), ciphertext)
}

// TestWalletVaultSignDigestInvalidRequest verifies that a malformed request
// fails before any Store read. The fixture Store has no expectations, so a
// read fails the test. DigestRequest.Validate has its own field coverage.
func TestWalletVaultSignDigestInvalidRequest(t *testing.T) {
	t.Parallel()

	f := newKeyFixture(t)

	_, err := f.vault.SignDigest(t.Context(), signing.DigestRequest{
		Key:    signing.DerivedKey{KeyScope: testScope},
		Digest: testDigest,
	})
	require.ErrorIs(t, err, signing.ErrInvalidMode)
}
