package wallet

import (
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// BenchmarkListAddressesAPI benchmarks ListAddresses API and a deprecated
// variant of it using same key scope and identical test data across multiple
// dataset sizes. Test names start with dataset size to group API comparisons
// for benchstat analysis.
func BenchmarkListAddressesAPI(b *testing.B) {
	benchmarkSizes, namingInfo := generateBenchmarkSizes(
		benchmarkConfig{
			accountGrowth: linearGrowth,
			utxoGrowth:    exponentialGrowth,
			addressGrowth: exponentialGrowth,
			maxIterations: 14,
			startIndex:    0,
		},
	)
	scopes := []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}
	addrType := waddrmgr.PubKeyHash

	for _, size := range benchmarkSizes {
		accountName, accountNumber := generateAccountName(
			size.numAccounts, scopes,
		)

		b.Run(size.name(namingInfo)+"/0-Before", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  size.numAccounts,
					numAddresses: size.numAddresses,
					numUTXOs:     size.numUTXOs,
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := listAddressesDeprecated(
					w, accountNumber,
				)
				require.NoError(b, err)
			}
		})

		b.Run(size.name(namingInfo)+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  size.numAccounts,
					numAddresses: size.numAddresses,
					numUTXOs:     size.numUTXOs,
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
	benchmarkSizes, namingInfo := generateBenchmarkSizes(
		benchmarkConfig{
			accountGrowth: linearGrowth,
			utxoGrowth:    constantGrowth,
			addressGrowth: exponentialGrowth,
			maxIterations: 14,
			startIndex:    0,
		},
	)
	scopes := []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}

	for _, size := range benchmarkSizes {
		b.Run(size.name(namingInfo)+"/0-Before", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  size.numAccounts,
					numAddresses: size.numAddresses,
					numUTXOs:     size.numUTXOs,
				},
			)

			testAddr := getTestAddress(b, w, size.numAccounts)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.AddressInfoDeprecated(testAddr)
				require.NoError(b, err)
			}
		})

		b.Run(size.name(namingInfo)+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  size.numAccounts,
					numAddresses: size.numAddresses,
					numUTXOs:     size.numUTXOs,
				},
			)

			testAddr := getTestAddress(b, w, size.numAccounts)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.AddressInfo(b.Context(), testAddr)
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
	benchmarkSizes, namingInfo := generateBenchmarkSizes(
		benchmarkConfig{
			accountGrowth: linearGrowth,
			utxoGrowth:    constantGrowth,
			addressGrowth: exponentialGrowth,
			maxIterations: 14,
			startIndex:    0,
		},
	)
	scopes := []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}
	addrType := waddrmgr.PubKeyHash

	for _, size := range benchmarkSizes {
		accountName, accountNumber := generateAccountName(
			size.numAccounts, scopes,
		)

		b.Run(size.name(namingInfo)+"/0-Before", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  size.numAccounts,
					numAddresses: size.numAddresses,
					numUTXOs:     size.numUTXOs,
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				addr, err := w.NewAddressDeprecated(
					accountNumber, scopes[0],
				)
				require.NoError(b, err)

				// Mark the address as used to make the
				// benchmark iteration idempotent.
				markAddressAsUsed(b, w, addr)
			}
		})

		b.Run(size.name(namingInfo)+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  size.numAccounts,
					numAddresses: size.numAddresses,
					numUTXOs:     size.numUTXOs,
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				addr, err := w.GetUnusedAddress(
					b.Context(), accountName, addrType,
					false,
				)
				require.NoError(b, err)

				// Mark the address as used to make the
				// benchmark iteration idempotent.
				markAddressAsUsed(b, w, addr)
			}
		})
	}
}
