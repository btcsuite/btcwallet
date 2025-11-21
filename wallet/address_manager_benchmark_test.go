package wallet

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// BenchmarkListAddressesAPI benchmarks ListAddresses API and a deprecated
// variant of it using same key scope and identical test data across multiple
// dataset sizes. Test names start with dataset size to group API comparisons
// for benchstat analysis.
func BenchmarkListAddressesAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// endGrowthIteration is the maximum iteration index for the
		// growth sequence.
		endGrowthIteration = 5
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		addressGrowthPadding = decimalWidth(
			addressGrowth[len(addressGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}

		addrType = waddrmgr.PubKeyHash
	)

	for i := 0; i <= endGrowthIteration; i++ {
		accountName, accountNumber := generateAccountName(
			accountGrowth[i], scopes,
		)

		name := fmt.Sprintf("%0*d-Accounts-%0*d-Addresses-%0*d-UTXOs",
			accountGrowthPadding, accountGrowth[i],
			addressGrowthPadding, addressGrowth[i],
			utxoGrowthPadding, utxoGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := listAddressesDeprecated(
					bw.Wallet, accountNumber,
				)
				require.NoError(b, err)
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.ListAddresses(
					b.Context(), accountName, addrType,
				)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkAddressInfoAPI benchmarks AddressInfo API and its deprecated
// variant using same key scope and identical test data across multiple
// dataset sizes. Test names start with dataset size to group API comparisons
// for benchstat analysis.
func BenchmarkAddressInfoAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// endGrowthIteration is the maximum iteration index for the
		// growth sequence.
		endGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			exponentialGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		addressGrowthPadding = decimalWidth(
			addressGrowth[len(addressGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}
	)

	for i := 0; i <= endGrowthIteration; i++ {
		name := fmt.Sprintf("%0*d-Accounts-%0*d-Addresses",
			accountGrowthPadding, accountGrowth[i],
			addressGrowthPadding, addressGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			testAddr := getTestAddress(
				b, bw.Wallet, accountGrowth[i],
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := bw.AddressInfoDeprecated(testAddr)
				require.NoError(b, err)
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			testAddr := getTestAddress(
				b, bw.Wallet, accountGrowth[i],
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := bw.AddressInfo(b.Context(), testAddr)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkGetUnusedAddressAPI benchmarks GetUnusedAddress API and its
// deprecated variant NewAddressDeprecated using same key scope and identical
// address datasets across multiple dataset sizes. Test names start with dataset
// size to group API comparisons for benchstat analysis. The benchmark
// demonstrates the trade-off between performance (O(1) vs O(n)) and safety
// (preventing address reuse and BIP44 gap limit violations).
func BenchmarkGetUnusedAddressAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// endGrowthIteration is the maximum iteration index for the
		// growth sequence.
		endGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			exponentialGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		addressGrowthPadding = decimalWidth(
			addressGrowth[len(addressGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}

		addrType = waddrmgr.PubKeyHash
	)

	for i := 0; i <= endGrowthIteration; i++ {
		accountName, accountNumber := generateAccountName(
			accountGrowth[i], scopes,
		)

		name := fmt.Sprintf("%0*d-Accounts-%0*d-Addresses",
			accountGrowthPadding, accountGrowth[i],
			addressGrowthPadding, addressGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				addr, err := bw.NewAddressDeprecated(
					accountNumber, scopes[0],
				)
				require.NoError(b, err)

				// Mark the address as used to make the
				// benchmark iteration idempotent.
				markAddressAsUsed(b, bw.Wallet, addr)
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				addr, err := bw.GetUnusedAddress(
					b.Context(), accountName, addrType,
					false,
				)
				require.NoError(b, err)

				// Mark the address as used to make the
				// benchmark iteration idempotent.
				markAddressAsUsed(b, bw.Wallet, addr)
			}
		})
	}
}

// BenchmarkNewAddressAPI benchmarks NewAddress API and its deprecated variant
// NewAddressDeprecated using same key scope and identical address datasets
// across multiple dataset sizes. Test names start with dataset size to group
// API comparisons for benchstat analysis. The benchmark demonstrates that the
// new API maintains performance parity with the deprecated API.
func BenchmarkNewAddressAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// endGrowthIteration is the maximum iteration index for the
		// growth sequence.
		endGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			exponentialGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		addressGrowthPadding = decimalWidth(
			addressGrowth[len(addressGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}

		addrType = waddrmgr.PubKeyHash
	)

	for i := 0; i <= endGrowthIteration; i++ {
		accountName, accountNumber := generateAccountName(
			accountGrowth[i], scopes,
		)

		name := fmt.Sprintf("%0*d-Accounts-%0*d-Addresses",
			accountGrowthPadding, accountGrowth[i],
			addressGrowthPadding, addressGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := bw.NewAddressDeprecated(
					accountNumber, scopes[0],
				)
				require.NoError(b, err)
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.NewAddress(
					b.Context(), accountName, addrType,
					false,
				)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkImportPublicKeyAPI benchmarks ImportPublicKey API and its deprecated
// variant ImportPublicKeyDeprecated using identical public key datasets across
// multiple dataset sizes. Test names start with dataset size to group API
// comparisons for benchstat analysis. The benchmark demonstrates that the new
// API maintains performance parity with the deprecated API.
func BenchmarkImportPublicKeyAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// endGrowthIteration is the maximum iteration index for the
		// growth sequence.
		endGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		addressGrowthPadding = decimalWidth(
			addressGrowth[len(addressGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}

		addrType = waddrmgr.WitnessPubKey
	)

	for i := 0; i <= endGrowthIteration; i++ {
		name := fmt.Sprintf("%0*d-Accounts-%0*d-Addresses",
			accountGrowthPadding, accountGrowth[i],
			addressGrowthPadding, addressGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			iterCount := 0
			for b.Loop() {
				// Generate a unique key for each iteration to
				// avoid in-memory cache collision and for an
				// idempotent benchmark iteration test.
				seedIndex := accountGrowth[i] + iterCount
				key, _, _ := generateTestExtendedKey(
					b, seedIndex,
				)
				pubKey, err := key.ECPubKey()
				require.NoError(b, err)

				err = w.ImportPublicKeyDeprecated(
					pubKey, addrType,
				)
				require.NoError(b, err)

				iterCount++
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			iterCount := 0
			for b.Loop() {
				// Generate a unique key for each iteration to
				// avoid in-memory cache collision and for an
				// idempotent benchmark iteration test.
				seedIndex := accountGrowth[i] + iterCount
				key, _, _ := generateTestExtendedKey(
					b, seedIndex,
				)
				pubKey, err := key.ECPubKey()
				require.NoError(b, err)

				err = w.ImportPublicKey(
					b.Context(), pubKey, addrType,
				)
				require.NoError(b, err)

				iterCount++
			}
		})
	}
}

// BenchmarkImportTaprootScriptAPI benchmarks ImportTaprootScript API and its
// deprecated variant ImportTaprootScriptDeprecated using identical tapscript
// datasets across multiple dataset sizes. Test names start with dataset size
// to group API comparisons for benchstat analysis. The benchmark demonstrates
// that the new API maintains performance parity with the deprecated API.
func BenchmarkImportTaprootScriptAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// endGrowthIteration is the maximum iteration index for the
		// growth sequence.
		endGrowthIteration = 10
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		addressGrowthPadding = decimalWidth(
			addressGrowth[len(addressGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0086}

		witnessVersion = 1

		isSecretScript = false
	)

	for i := 0; i <= endGrowthIteration; i++ {
		name := fmt.Sprintf("%0*d-Accounts-%0*d-Addresses",
			accountGrowthPadding, accountGrowth[i],
			addressGrowthPadding, addressGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			iterCount := 0
			for b.Loop() {
				// Generate a unique tapscript for each
				// iteration to avoid in-memory cache collision
				// and for an idempotent benchmark iteration
				// test.
				seedIndex := accountGrowth[i] + iterCount
				key, _, _ := generateTestExtendedKey(
					b, seedIndex,
				)
				pubKey, err := key.ECPubKey()
				require.NoError(b, err)

				tapscript := generateTestTapscript(b, pubKey)

				syncedTo := w.addrStore.SyncedTo()
				_, err = w.ImportTaprootScriptDeprecated(
					scopes[0], &tapscript, &syncedTo,
					byte(witnessVersion), isSecretScript,
				)
				require.NoError(b, err)

				iterCount++
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			iterCount := 0
			for b.Loop() {
				// Generate a unique tapscript for each
				// iteration to avoid in-memory cache collision
				// and for an idempotent benchmark iteration
				// test.
				seedIndex := accountGrowth[i] + iterCount
				key, _, _ := generateTestExtendedKey(
					b, seedIndex,
				)
				pubKey, err := key.ECPubKey()
				require.NoError(b, err)

				tapscript := generateTestTapscript(b, pubKey)

				_, err = w.ImportTaprootScript(
					b.Context(), tapscript,
				)
				require.NoError(b, err)

				iterCount++
			}
		})
	}
}

// BenchmarkScriptForOutputAPI benchmarks ScriptForOutput API and its deprecated
// variant ScriptForOutputDeprecated using identical TxOut datasets across
// multiple dataset sizes. Test names start with dataset size to group API
// comparisons for benchstat analysis. The benchmark demonstrates that the new
// API maintains performance parity with the deprecated API.
func BenchmarkScriptForOutputAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// endGrowthIteration is the maximum iteration index for the
		// growth sequence.
		endGrowthIteration = 10
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			exponentialGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		addressGrowthPadding = decimalWidth(
			addressGrowth[len(addressGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}
	)

	for i := 0; i <= endGrowthIteration; i++ {
		name := fmt.Sprintf("%0*d-Accounts-%0*d-Addresses-%0*d-UTXOs",
			accountGrowthPadding, accountGrowth[i],
			addressGrowthPadding, addressGrowth[i],
			utxoGrowthPadding, utxoGrowth[i])

		b.Run(name+"/0-Before", func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)
			fmt.Println("SETUP benchmarking wallet")

			testAddr := getTestAddress(
				b, bw.Wallet, accountGrowth[i],
			)
			testTxOut := generateTestTxOut(b, testAddr)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, _, _, err := bw.ScriptForOutputDeprecated(
					&testTxOut,
				)
				require.NoError(b, err)
			}
		})

		b.Run(name+"/1-After", func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			testAddr := getTestAddress(
				b, bw.Wallet, accountGrowth[i],
			)
			testTxOut := generateTestTxOut(b, testAddr)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := bw.ScriptForOutput(
					b.Context(), testTxOut,
				)
				require.NoError(b, err)
			}
		})
	}
}
