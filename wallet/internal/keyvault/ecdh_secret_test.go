package keyvault

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

// TestECDHSecretBOLT8Vectors pins ECDHSecret, shared by vault and kvdb ECDH, to
// the BOLT 8 Appendix A transport vectors. Their ss values are
// sha256(compressed(k*P)), libsecp256k1's default ECDH output and the function
// lnd implements as keychain.ECDHRing, so matching them proves ECDH's format
// independently of btcec's own helpers. The vectors include both Y parities,
// and for each the hash of the X coordinate alone is checked to differ, so the
// parity byte is shown to be part of the hashed input.
func TestECDHSecretBOLT8Vectors(t *testing.T) {
	t.Parallel()

	vectors := []struct {
		name       string
		privKey    string
		remotePub  string
		wantPrefix byte
		wantSecret string
	}{
		{
			name: "act one es",
			privKey: "1212121212121212121212121212121212121212121212" +
				"121212121212121212",
			remotePub: "028d7500dd4c12685d1f568b4c2b5048e8534b873319f3" +
				"a8daa612b469132ec7f7",
			wantPrefix: secp256k1.PubKeyFormatCompressedEven,
			wantSecret: "1e2fb3c8fe8fb9f262f649f64d26ecf0f2c0a805a767cf" +
				"02dc2d77a6ef1fdcc3",
		},
		{
			name: "act two ee",
			privKey: "1212121212121212121212121212121212121212121212" +
				"121212121212121212",
			remotePub: "02466d7fcae563e5cb09a0d1870bb580344804617879a1" +
				"4949cf22285f1bae3f27",
			wantPrefix: secp256k1.PubKeyFormatCompressedOdd,
			wantSecret: "c06363d6cc549bcb7913dbb9ac1c33fc1158680c89e972" +
				"000ecd06b36c472e47",
		},
		{
			name: "act three se",
			privKey: "1111111111111111111111111111111111111111111111" +
				"111111111111111111",
			remotePub: "02466d7fcae563e5cb09a0d1870bb580344804617879a1" +
				"4949cf22285f1bae3f27",
			wantPrefix: secp256k1.PubKeyFormatCompressedEven,
			wantSecret: "b36b6d195982c5be874d6d542dc268234379e1ae4ff170" +
				"9402135b7de5cf0766",
		},
	}

	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Decode the vector's local key and remote point.
			privBytes, err := hex.DecodeString(vector.privKey)
			require.NoError(t, err)

			privKey, _ := btcec.PrivKeyFromBytes(privBytes)

			pubBytes, err := hex.DecodeString(vector.remotePub)
			require.NoError(t, err)

			remotePub, err := btcec.ParsePubKey(pubBytes)
			require.NoError(t, err)

			wantSecret, err := hex.DecodeString(vector.wantSecret)
			require.NoError(t, err)

			// Act: Compute the shared secret.
			secret := ECDHSecret(privKey, remotePub)

			// Assert: The secret is the vector's ss, which hashes X with
			// the labeled parity byte rather than X alone.
			require.Equal(t, wantSecret, secret[:])

			rawX := btcec.GenerateSharedSecret(privKey, remotePub)
			withParity := sha256.Sum256(
				append([]byte{vector.wantPrefix}, rawX...),
			)
			require.Equal(t, wantSecret, withParity[:])

			xOnly := sha256.Sum256(rawX)
			require.NotEqual(t, wantSecret, xOnly[:])
		})
	}
}
