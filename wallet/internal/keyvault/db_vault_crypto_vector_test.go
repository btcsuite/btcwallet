package keyvault

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/waddrmgr"
	bwmock "github.com/btcsuite/btcwallet/wallet/internal/bwtest/mock"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// knownSecrets describes one fixed wallet crypto test vector.
type knownSecrets struct {
	name       string
	passphrase string

	masterPrivParamsHex  string
	expectedMasterKeyHex string

	encryptedCryptoPrivKeyHex string
	expectedCryptoPrivKeyHex  string
	privatePlaintext          string
	privateCiphertextHex      string

	encryptedCryptoScriptKeyHex string
	expectedCryptoScriptKeyHex  string
	scriptPlaintext             string
	scriptCiphertextHex         string
}

// knownSecretsVector lists the fixed wallet crypto vectors exercised by the
// tests.
var knownSecretsVector = []knownSecrets{
	{
		name: "bacon",

		//nolint:dupword // intentional passphrase
		passphrase: "bacon bacon bacon",

		masterPrivParamsHex: "000102030405060708090a0b0c0d0e0f10111213141516" +
			"1718191a1b1c1d1e1f158f62f8b7e2ff57f773b26b4d1aca3936a2d947c44b9" +
			"dfb47eb89046612cb4700100000000000001000000000000000010000000000" +
			"0000",
		expectedMasterKeyHex: "43af670d6b1249f9e96cf8f8f92ab13fa6627404117e1" +
			"b8f8fa14079120812f1",

		encryptedCryptoPrivKeyHex: "202122232425262728292a2b2c2d2e2f30313233" +
			"34353637cac1fbbfcc257c7012b52e1c43e077477c399af4661b27fe466eb62" +
			"c84025115a9a693bb7ae54e1bd0a8439ea5381e0b",
		expectedCryptoPrivKeyHex: "102132435465768798a9bacbdcedfe0f1e2d3c4b5" +
			"a69788796a5b4c3d2e1f00f",
		privatePlaintext: "super private bacon",
		privateCiphertextHex: "606162636465666768696a6b6c6d6e6f7071727374757" +
			"677a2aa9c51787b17707d10e4d159cb79a8a06cd5ecfc2966b13db37f787f45" +
			"5dac5cd3a1",

		encryptedCryptoScriptKeyHex: "404142434445464748494a4b4c4d4e4f505152" +
			"5354555657c959384d2e141c477f05d2ed2bf79bcbdad8598ba657b619d1adf" +
			"7ddc96d71a220f05456c3cb95aaec64790ae1368376",
		expectedCryptoScriptKeyHex: "f0dfcebdac9b8a7968574635241302f1e2d3c4b" +
			"5a69788796a5b4c3d2e1f0efd",
		scriptPlaintext: "super script bacon",
		scriptCiphertextHex: "808182838485868788898a8b8c8d8e8f90919293949596" +
			"97625f4959ccbe194fa059bab34e292c093d90ec9311a0a78a3105fde16a28b" +
			"a378c0c",
	},
	{
		name: "cactus",

		//nolint:dupword // intentional passphrase
		passphrase: "cactus cactus cactus",

		masterPrivParamsHex: "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6" +
			"b7b8b9babbbcbdbebf0e04d873e158a36569a4c16b2b7738d151785b2461c64" +
			"728a2f68c1cf3dd82ab00100000000000001000000000000000010000000000" +
			"0000",
		expectedMasterKeyHex: "7f47493d99a2d8ec31e9d1415154894fa6343ead7a124" +
			"f4748a7754fb71a51a4",

		encryptedCryptoPrivKeyHex: "202122232425262728292a2b2c2d2e2f30313233" +
			"34353637e0b733784af58281f00f98488060ffb6791168adbb00e22ac450ee6" +
			"89d8656373a76c228053d97ef1251fce6cc66abaf",
		expectedCryptoPrivKeyHex: "001f2e3d4c5b6a798897a6b5c4d3e2f10ffeeddcc" +
			"bbaa9988776655443322110",
		privatePlaintext: "super private cactus",
		privateCiphertextHex: "606162636465666768696a6b6c6d6e6f7071727374757" +
			"6777d0a7662896ad5f17802c0df700d4585778592b544a0685e2d6ad08f439a" +
			"1e83d5bb3390",

		encryptedCryptoScriptKeyHex: "404142434445464748494a4b4c4d4e4f505152" +
			"53545556574d486bca825066bb8dea31c8743e85d0fc31927e48367276a7794" +
			"be08e83aea0e4107819ad4856e0ef11440d241a38b1",
		expectedCryptoScriptKeyHex: "ffeeddccbbaa998877665544332211000f1e2d3" +
			"c4b5a69788796a5b4c3d2e1f0",
		scriptPlaintext: "super script cactus",
		scriptCiphertextHex: "808182838485868788898a8b8c8d8e8f90919293949596" +
			"9715d23fd581b57ca0117f583b2ee0198bf3b37d4770b55c05911d196893871" +
			"95cb00c2b",
	},
}

// TestDBVaultKnownVectorMasterKey verifies that each fixed passphrase and
// serialized parameters derive the expected master private crypto key.
func TestDBVaultKnownVectorMasterKey(t *testing.T) {
	t.Parallel()

	for _, know := range knownSecretsVector {
		t.Run(know.name, func(t *testing.T) {
			t.Parallel()

			passphrase := []byte(know.passphrase)

			var masterKey snacl.SecretKey
			require.NoError(
				t, masterKey.Unmarshal(
					decodeHex(t, know.masterPrivParamsHex),
				),
			)
			t.Cleanup(masterKey.Zero)

			require.NoError(t, masterKey.DeriveKey(&passphrase))
			require.Equal(
				t, decodeHex(t, know.expectedMasterKeyHex), masterKey.Key[:],
			)
		})
	}
}

// TestDBVaultKnownVectorUnlockAndDecrypt verifies the full persisted-secret
// chain: fixed wallet secrets unlock known runtime keys, and those keys decrypt
// fixed ciphertext/plaintext vectors. These regression-guards catch crypto
// library changes that would break backward compatibility with older persisted
// wallet state.
func TestDBVaultKnownVectorUnlockAndDecrypt(t *testing.T) {
	t.Parallel()

	for _, known := range knownSecretsVector {
		t.Run(known.name, func(t *testing.T) {
			t.Parallel()

			secrets := &db.WalletSecrets{
				MasterPrivParams: decodeHex(
					t, known.masterPrivParamsHex,
				),
				EncryptedCryptoPrivKey: decodeHex(
					t, known.encryptedCryptoPrivKeyHex,
				),
				EncryptedCryptoScriptKey: decodeHex(
					t, known.encryptedCryptoScriptKeyHex,
				),
			}

			const walletID = uint32(1)

			store := new(bwmock.Store)
			store.On("GetWalletSecrets", mock.Anything, walletID).
				Return(secrets, nil).Once()
			t.Cleanup(func() {
				store.AssertExpectations(t)
			})

			vault := NewDBVault(store, walletID)
			require.NoError(
				t, vault.Unlock(t.Context(), []byte(known.passphrase), -1),
			)
			t.Cleanup(vault.Lock)

			require.NotNil(t, vault.unlockedState)
			require.Equal(
				t, decodeHex(t, known.expectedCryptoPrivKeyHex),
				vault.unlockedState.cryptoKeyPrivate[:],
			)
			require.Equal(
				t, decodeHex(t, known.expectedCryptoScriptKeyHex),
				vault.unlockedState.cryptoKeyScript[:],
			)

			decryptedPrivate, err := vault.Decrypt(
				waddrmgr.CKTPrivate,
				decodeHex(t, known.privateCiphertextHex),
			)
			require.NoError(t, err)
			require.Equal(
				t, []byte(known.privatePlaintext), decryptedPrivate,
			)

			decryptedScript, err := vault.Decrypt(
				waddrmgr.CKTScript,
				decodeHex(t, known.scriptCiphertextHex),
			)
			require.NoError(t, err)
			require.Equal(t, []byte(known.scriptPlaintext), decryptedScript)
		})
	}
}

// decodeHex decodes bytes from a hex string.
func decodeHex(t *testing.T, value string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	require.NoError(t, err)

	return decoded
}
