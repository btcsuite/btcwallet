package wallet

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// BenchmarkDerivePubKey benchmarks the DerivePubKey method across different
// wallet sizes. The benchmark measures the performance of deriving a public
// key from a BIP-32 path, which involves database lookups and cryptographic
// operations.
func BenchmarkDerivePubKey(b *testing.B) {
	const (
		startGrowthIteration = 0
		maxGrowthIteration   = 5
	)

	var (
		// accountGrowth uses linearGrowth to test how performance
		// scales with the number of accounts in the wallet. Key
		// derivation uses the account index in the BIP-32 path, so
		// database lookup time should remain constant due to indexed
		// lookups.
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		// addressGrowth uses constantGrowth since address count doesn't
		// affect the key derivation's time complexity - it derives from
		// an explicit path without address search.
		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		// utxoGrowth uses constantGrowth since UTXO count doesn't
		// affect the key derivation's time complexity.
		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{
			waddrmgr.KeyScopeBIP0084,
			waddrmgr.KeyScopeBIP0086,
		}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("Accounts-%0*d", accountGrowthPadding,
			accountGrowth[i])

		b.Run(name, func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			// Use a path from the middle of the account range
			// for representative performance.
			accountIndex := uint32(accountGrowth[i] / 2)
			path := BIP32Path{
				KeyScope: scopes[0],
				DerivationPath: waddrmgr.DerivationPath{
					InternalAccount: accountIndex,
					Branch:          0,
					Index:           0,
				},
			}

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.DerivePubKey(b.Context(), path)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkECDH benchmarks the ECDH method across different wallet sizes.
// The benchmark measures the performance of performing an ECDH operation
// between a wallet key and a remote public key.
func BenchmarkECDH(b *testing.B) {
	const (
		startGrowthIteration = 0
		maxGrowthIteration   = 5
	)

	var (
		// accountGrowth uses linearGrowth to test scaling with wallet
		// size. ECDH derives the wallet's private key using the account
		// index in the BIP-32 path for the scalar multiplication.
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		// addressGrowth uses constantGrowth since address count doesn't
		// the ECDH operation's time complexity. It uses an explicit
		// path.
		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		// utxoGrowth uses constantGrowth since UTXO count doesn't
		// affect the cryptographic operation's time complexity.
		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}
	)

	// Generate a remote public key for ECDH.
	remotePrivKey, err := btcec.NewPrivateKey()
	require.NoError(b, err)

	remotePubKey := remotePrivKey.PubKey()

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("Accounts-%0*d", accountGrowthPadding,
			accountGrowth[i])

		b.Run(name, func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			accountIndex := uint32(accountGrowth[i] / 2)
			path := BIP32Path{
				KeyScope: scopes[0],
				DerivationPath: waddrmgr.DerivationPath{
					InternalAccount: accountIndex,
					Branch:          0,
					Index:           0,
				},
			}

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.ECDH(
					b.Context(), path, remotePubKey,
				)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkSignDigestECDSA benchmarks the SignDigest method for ECDSA
// signatures across different wallet sizes. The benchmark measures the
// performance of signing a digest with ECDSA.
func BenchmarkSignDigestECDSA(b *testing.B) {
	const (
		startGrowthIteration = 0
		maxGrowthIteration   = 5
	)

	var (
		// accountGrowth uses linearGrowth to test scaling with wallet
		// size. Signature operations derive keys using the account
		// index in the BIP-32 path.
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		// addressGrowth uses constantGrowth since address count doesn't
		// affect the signature generation's time complexity when using
		// an explicit path.
		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		// utxoGrowth uses constantGrowth since UTXO count doesn't
		// affect the signature generation's time complexity.
		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}
	)

	// Create a test digest to sign.
	digest := chainhash.HashB([]byte("test message"))

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("Accounts-%0*d", accountGrowthPadding,
			accountGrowth[i])

		b.Run(name, func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			accountIndex := uint32(accountGrowth[i] / 2)
			path := BIP32Path{
				KeyScope: scopes[0],
				DerivationPath: waddrmgr.DerivationPath{
					InternalAccount: accountIndex,
					Branch:          0,
					Index:           0,
				},
			}

			intent := &SignDigestIntent{
				Digest:  digest,
				SigType: SigTypeECDSA,
			}

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				sig, err := w.SignDigest(
					b.Context(), path, intent,
				)
				require.NoError(b, err)
				require.NotNil(b, sig)
			}
		})
	}
}

// BenchmarkSignDigestECDSACompact benchmarks the SignDigest method for
// compact ECDSA signatures across different wallet sizes.
func BenchmarkSignDigestECDSACompact(b *testing.B) {
	const (
		startGrowthIteration = 0
		maxGrowthIteration   = 5
	)

	var (
		// accountGrowth uses linearGrowth to test scaling with wallet
		// size. Signature operations derive keys using the account
		// index in the BIP-32 path.
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		// addressGrowth uses constantGrowth since address count doesn't
		// affect the signature generation's time complexity when using
		// an explicit path.
		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		// utxoGrowth uses constantGrowth since UTXO count doesn't
		// affect the signature generation's time complexity.
		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}
	)

	digest := chainhash.DoubleHashB([]byte("test message"))

	for i := 0; i <= maxGrowthIteration; i++ {
		name := fmt.Sprintf("Accounts-%0*d", accountGrowthPadding,
			accountGrowth[i])

		b.Run(name, func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			accountIndex := uint32(accountGrowth[i] / 2)

			path := BIP32Path{
				KeyScope: scopes[0],
				DerivationPath: waddrmgr.DerivationPath{
					InternalAccount: accountIndex,
					Branch:          0,
					Index:           0,
				},
			}

			intent := &SignDigestIntent{
				Digest:     digest,
				SigType:    SigTypeECDSA,
				CompactSig: true,
			}

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				sig, err := w.SignDigest(
					b.Context(), path, intent,
				)
				require.NoError(b, err)
				require.NotNil(b, sig)
			}
		})
	}
}
