package signing

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"slices"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// TestKeyTweakBOLT3 verifies the affine key tweak against the BOLT 3 Appendix
// E key derivation vectors. The Lightning hashes are computed here, as lnd
// computes them; the tweak only applies mul*d + add. Apply on the base secret
// and PubKey on the base point must both give the vector's key.
func TestKeyTweakBOLT3(t *testing.T) {
	t.Parallel()

	const (
		baseSecret = "000102030405060708090a0b0c0d0e0f101112131415161718" +
			"191a1b1c1d1e1f"
		perCommitmentSecret = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b" +
			"0a09080706050403020100"
		perCommitmentPoint = "025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd" +
			"25eaf467a4a1c2a45ce1486"
		localPubKey = "0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc" +
			"43f5494984db29e5"
		revocationPubKey = "02916e326636d19c33f13e8c0c3a03dd157f332f3e99c3" +
			"17c141dd865eb01f8ff0"
	)

	baseKey, base := btcec.PrivKeyFromBytes(decodeHex(t, baseSecret))
	commitPoint, err := btcec.ParsePubKey(decodeHex(t, perCommitmentPoint))
	require.NoError(t, err)

	basePoint := base.SerializeCompressed()
	commit := commitPoint.SerializeCompressed()
	hash := func(a, b []byte) [32]byte {
		return sha256.Sum256(append(slices.Clone(a), b...))
	}

	// Single tweak: d + SHA256(per_commitment_point || basepoint).
	single := hash(commit, basePoint)

	// Revocation: d*SHA256(R || P) + s*SHA256(P || R).
	revMul := hash(basePoint, commit)

	var revAdd, secret btcec.ModNScalar
	revAdd.SetBytes(&single)
	secret.SetByteSlice(decodeHex(t, perCommitmentSecret))
	revAdd.Mul(&secret)

	tests := []struct {
		name string
		mul  [32]byte
		add  [32]byte
		want string
	}{
		{name: "single", mul: [32]byte{31: 1}, add: single, want: localPubKey},
		{
			name: "revocation", mul: revMul, add: revAdd.Bytes(),
			want: revocationPubKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Build the tweak and a copy of the base secret.
			tweak, err := NewKeyTweak(test.mul, test.add)
			require.NoError(t, err)

			key, _ := btcec.PrivKeyFromBytes(baseKey.Serialize())
			want := decodeHex(t, test.want)

			// Act: Tweak the secret and the public key.
			applyErr := tweak.Apply(key)
			pub, pubErr := tweak.PubKey(base)

			// Assert: Both give the vector's key.
			require.NoError(t, applyErr)
			require.NoError(t, pubErr)
			require.Equal(t, want, key.PubKey().SerializeCompressed())
			require.Equal(t, want, pub.SerializeCompressed())
		})
	}
}

// TestNewKeyTweak tests that the identity tweak is the zero value, which
// keeps a derivation record's own key bytes.
func TestNewKeyTweak(t *testing.T) {
	t.Parallel()

	tweak, err := NewKeyTweak([32]byte{31: 1}, [32]byte{})
	require.NoError(t, err)
	require.Equal(t, KeyTweak{}, tweak)
}

// TestNewKeyTweakInvalid tests that the tweak constructor refuses scalars at
// or above the curve order and a zero multiplier.
func TestNewKeyTweakInvalid(t *testing.T) {
	t.Parallel()

	// overOrder is the curve order plus one. Reduced, it would be a valid
	// non-zero multiplier.
	var overOrder [32]byte
	new(big.Int).Add(btcec.S256().N, big.NewInt(1)).FillBytes(overOrder[:])

	one := [32]byte{31: 1}

	tests := []struct {
		name string
		mul  [32]byte
		add  [32]byte
	}{{
		name: "multiplier above the curve order",
		mul:  overOrder,
		add:  one,
	}, {
		name: "addend above the curve order",
		mul:  one,
		add:  overOrder,
	}, {
		name: "zero multiplier",
		add:  one,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewKeyTweak(tc.mul, tc.add)
			require.ErrorIs(t, err, ErrInvalidKeyTweak)
		})
	}
}

// TestKeyTweakApply tests that the zero value leaves the key unchanged, that a
// tweak cancelling the key is refused, and that PubKey predicts the public key
// Apply produces. TestKeyTweakBOLT3 checks mul*d + add against the vectors.
func TestKeyTweakApply(t *testing.T) {
	t.Parallel()

	base, _ := btcec.PrivKeyFromBytes(decodeHex(t, "22a47fa09a223f2aa079"+
		"edf85a7c2d4f8720ee63e502ee2869afab7de234b80c"))

	one := [32]byte{31: 1}

	negKey := base.Key
	cancelling, err := NewKeyTweak(one, negKey.Negate().Bytes())
	require.NoError(t, err)

	tests := []struct {
		name    string
		tweak   KeyTweak
		want    btcec.ModNScalar
		wantErr error
	}{{
		name: "zero value",
		want: base.Key,
	}, {
		name:    "cancelling tweak",
		tweak:   cancelling,
		wantErr: ErrInvalidKeyTweak,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key := &btcec.PrivateKey{Key: base.Key}

			err := tc.tweak.Apply(key)
			pubKey, pubErr := tc.tweak.PubKey(base.PubKey())

			require.ErrorIs(t, err, tc.wantErr)
			require.ErrorIs(t, pubErr, tc.wantErr)

			if tc.wantErr == nil {
				require.True(t, key.Key.Equals(&tc.want))
				require.True(t, pubKey.IsEqual(key.PubKey()))
			}
		})
	}
}

// decodeHex decodes a hex test vector.
func decodeHex(t *testing.T, value string) []byte {
	t.Helper()

	raw, err := hex.DecodeString(value)
	require.NoError(t, err)

	return raw
}

// TestKeyTweakThen verifies that Then composes two tweaks in order: applying
// the result once equals applying the first tweak and then the second.
func TestKeyTweakThen(t *testing.T) {
	t.Parallel()

	// Arrange: Two tweaks with both scalars set and a base key.
	firstMul := sha256.Sum256([]byte("first mul"))
	firstAdd := sha256.Sum256([]byte("first add"))
	first, err := NewKeyTweak(firstMul, firstAdd)
	require.NoError(t, err)

	nextMul := sha256.Sum256([]byte("next mul"))
	nextAdd := sha256.Sum256([]byte("next add"))
	next, err := NewKeyTweak(nextMul, nextAdd)
	require.NoError(t, err)

	baseBytes := sha256.Sum256([]byte("then base"))
	want, _ := btcec.PrivKeyFromBytes(baseBytes[:])
	require.NoError(t, first.Apply(want))
	require.NoError(t, next.Apply(want))

	// Act: Compose the tweaks and apply the result once.
	composed := first.Then(next)

	got, _ := btcec.PrivKeyFromBytes(baseBytes[:])
	require.NoError(t, composed.Apply(got))

	// Assert: Both give the same key.
	require.True(t, got.Key.Equals(&want.Key))
}

// TestKeyTweakThenIdentity verifies that composing with the identity, the zero
// value, returns the other tweak unchanged, so composing two identities stays
// the zero value.
func TestKeyTweakThenIdentity(t *testing.T) {
	t.Parallel()

	// Arrange: A tweak with both scalars set and the identity.
	mul := sha256.Sum256([]byte("identity mul"))
	add := sha256.Sum256([]byte("identity add"))
	tweak, err := NewKeyTweak(mul, add)
	require.NoError(t, err)

	var identity KeyTweak

	// Act: Compose the tweak with the identity on each side, and the
	// identity with itself.
	after := tweak.Then(identity)
	before := identity.Then(tweak)
	both := identity.Then(identity)

	// Assert: The identity keeps the other tweak, and two identities stay
	// the zero value.
	require.Equal(t, tweak, after)
	require.Equal(t, tweak, before)
	require.Equal(t, KeyTweak{}, both)
}
