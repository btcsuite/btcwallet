package keyvault

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// testGenesisRootKey builds a deterministic spendable HD root key for genesis
// tests.
func testGenesisRootKey(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()

	seed := []byte("0123456789abcdef0123456789abcdef")
	hdRootKey, err := hdkeychain.NewMaster(
		seed, &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	return hdRootKey
}

// TestCreateWalletSecretsRoundtrip verifies what CreateWalletSecrets persists
// for each wallet mode and that it decrypts back under the correct passphrase —
// the parity guarantee that a SQL wallet derives the same keys as the legacy
// backend for a given seed — while the wrong passphrase is rejected.
func TestCreateWalletSecretsRoundtrip(t *testing.T) {
	t.Parallel()

	const passphrase = "correct horse battery staple"

	tests := []struct {
		name      string
		watchOnly bool

		// decryptPass is the passphrase used to decrypt; when it
		// differs from the creating one the decrypt must be rejected.
		decryptPass string
		wantErr     error
	}{{
		name:        "spendable",
		decryptPass: passphrase,
	}, {
		name:        "watch-only",
		watchOnly:   true,
		decryptPass: passphrase,
	}, {
		name:        "wrong passphrase",
		decryptPass: "wrong passphrase",
		wantErr:     ErrInvalidPassphrase,
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var hdRootKey *hdkeychain.ExtendedKey
			if !test.watchOnly {
				hdRootKey = testGenesisRootKey(t)
			}

			secrets, err := createWalletSecretsFast(
				[]byte(passphrase), hdRootKey, test.watchOnly,
			)
			require.NoError(t, err)

			// The master private params are always persisted; the
			// private halves only for a spendable wallet.
			require.NotEmpty(t, secrets.MasterPrivParams)
			require.NotEmpty(t, secrets.EncryptedCryptoScriptKey)

			if test.watchOnly {
				require.Empty(t, secrets.EncryptedCryptoPrivKey)
				require.Empty(
					t, secrets.EncryptedMasterHdPrivKey,
				)
			} else {
				require.NotEmpty(
					t, secrets.EncryptedCryptoPrivKey,
				)
				require.NotEmpty(
					t, secrets.EncryptedMasterHdPrivKey,
				)
			}

			state, err := decryptWalletSecrets(
				secrets, []byte(test.decryptPass),
				test.watchOnly,
			)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)

				return
			}

			require.NoError(t, err)

			defer state.zero()

			require.NotEqual(
				t, snacl.CryptoKey{}, state.cryptoKeyScript,
			)

			if test.watchOnly {
				// Watch-only wallets hold no private material.
				require.Nil(t, state.hdRootKey)
				require.Equal(
					t, snacl.CryptoKey{},
					state.cryptoKeyPrivate,
				)

				return
			}

			// The decrypted HD root key must round-trip exactly.
			require.NotNil(t, state.hdRootKey)
			require.Equal(
				t, hdRootKey.String(), state.hdRootKey.String(),
			)
			require.NotEqual(
				t, snacl.CryptoKey{}, state.cryptoKeyPrivate,
			)
		})
	}
}

// TestCreateWalletSecretsInputGuards verifies that CreateWalletSecrets rejects
// invalid genesis inputs before deriving secret material.
func TestCreateWalletSecretsInputGuards(t *testing.T) {
	t.Parallel()

	passphrase := []byte("correct horse battery staple")

	tests := []struct {
		name       string
		passphrase []byte
		rootKey    func(t *testing.T) *hdkeychain.ExtendedKey
		watchOnly  bool
		wantErr    error
	}{
		{
			name:       "spendable private key and passphrase",
			passphrase: passphrase,
			rootKey:    testGenesisRootKey,
			watchOnly:  false,
			wantErr:    nil,
		},
		{
			name:       "spendable nil root key",
			passphrase: passphrase,
			rootKey: func(*testing.T) *hdkeychain.ExtendedKey {
				return nil
			},
			watchOnly: false,
			wantErr:   errUnexpectedState,
		},
		{
			name:       "spendable neutered root key",
			passphrase: passphrase,
			rootKey: func(t *testing.T) *hdkeychain.ExtendedKey {
				t.Helper()

				neutered, err := testGenesisRootKey(t).Neuter()
				require.NoError(t, err)

				return neutered
			},
			watchOnly: false,
			wantErr:   errRootKeyNotPrivate,
		},
		{
			name:       "spendable empty passphrase",
			passphrase: nil,
			rootKey:    testGenesisRootKey,
			watchOnly:  false,
			wantErr:    ErrEmptyPassphrase,
		},
		{
			name:       "watch-only neutered key",
			passphrase: passphrase,
			rootKey: func(t *testing.T) *hdkeychain.ExtendedKey {
				t.Helper()

				neutered, err := testGenesisRootKey(t).Neuter()
				require.NoError(t, err)

				return neutered
			},
			watchOnly: true,
			wantErr:   nil,
		},
		{
			name:       "watch-only neutered key empty passphrase",
			passphrase: nil,
			rootKey: func(t *testing.T) *hdkeychain.ExtendedKey {
				t.Helper()

				neutered, err := testGenesisRootKey(t).Neuter()
				require.NoError(t, err)

				return neutered
			},
			watchOnly: true,
			wantErr:   ErrEmptyPassphrase,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			secrets, err := createWalletSecretsFast(
				tc.passphrase, tc.rootKey(t), tc.watchOnly,
			)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, secrets)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, secrets)
		})
	}
}

// TestCreateWalletSecretsCiphertextOnly verifies that no persisted secret
// field carries the plaintext master HD private key. This is the observable
// half of the function's zeroing guarantee: the xprv is only ever handed to
// the caller as ciphertext, never in the clear.
func TestCreateWalletSecretsCiphertextOnly(t *testing.T) {
	t.Parallel()

	passphrase := []byte("correct horse battery staple")
	hdRootKey := testGenesisRootKey(t)
	plaintextXPriv := []byte(hdRootKey.String())

	secrets, err := createWalletSecretsFast(passphrase, hdRootKey, false)
	require.NoError(t, err)

	// None of the returned fields may embed the plaintext xprv bytes.
	require.NotContains(t, string(secrets.MasterPrivParams),
		string(plaintextXPriv))
	require.False(t, bytes.Contains(
		secrets.EncryptedCryptoPrivKey, plaintextXPriv,
	))
	require.False(t, bytes.Contains(
		secrets.EncryptedCryptoScriptKey, plaintextXPriv,
	))
	require.False(t, bytes.Contains(
		secrets.EncryptedMasterHdPrivKey, plaintextXPriv,
	))
}

// createWalletSecretsFast is CreateWalletSecrets at a key-derivation cost cheap
// enough for tests. The exported path's production cost is asserted separately
// by TestCreateWalletSecretsUsesProductionScrypt.
func createWalletSecretsFast(privatePassphrase []byte,
	hdRootKey *hdkeychain.ExtendedKey, watchOnly bool) (*db.WalletSecrets,
	error) {

	return createWalletSecretsWithScrypt(
		privatePassphrase, hdRootKey, watchOnly,
		&waddrmgr.FastScryptOptions,
	)
}

// TestCreateWalletSecretsUsesProductionScrypt pins the key-derivation cost of
// new SQL wallets to waddrmgr's production options.
//
// snacl's own defaults are 2^14, sixteen times cheaper than the 2^18 every
// existing wallet uses, and the parameters are persisted with the wallet — so a
// weaker cost here would permanently lower the offline passphrase-cracking cost
// for every wallet created, with no way to raise it later.
func TestCreateWalletSecretsUsesProductionScrypt(t *testing.T) {
	t.Parallel()

	secrets, err := CreateWalletSecrets([]byte("passphrase"), nil, true)
	require.NoError(t, err)

	var masterKey snacl.SecretKey
	require.NoError(t, masterKey.Unmarshal(secrets.MasterPrivParams))

	require.Equal(t, waddrmgr.DefaultScryptOptions.N, masterKey.Parameters.N,
		"new SQL wallets must use the production scrypt cost")
	require.Equal(t, waddrmgr.DefaultScryptOptions.R, masterKey.Parameters.R)
	require.Equal(t, waddrmgr.DefaultScryptOptions.P, masterKey.Parameters.P)
}
