package wallet

import (
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// BenchmarkGetUtxoAPI benchmarks GetUtxo API and its deprecated variant
// FetchOutpointInfo using same key scope and identical test data across
// multiple dataset sizes. Test names start with dataset size to group API
// comparisons for benchstat analysis.
func BenchmarkGetUtxoAPI(b *testing.B) {
	benchmarkSizes, namingInfo := generateBenchmarkSizes(
		benchmarkConfig{
			accountGrowth: linearGrowth,
			utxoGrowth:    exponentialGrowth,
			addressGrowth: linearGrowth,
			maxIterations: 14,
			startIndex:    0,
		},
	)
	scopes := []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}

	for _, size := range benchmarkSizes {
		b.Run(size.name(namingInfo)+"/0-Before", func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  size.numAccounts,
					numAddresses: size.numAddresses,
					numUTXOs:     size.numUTXOs,
				},
			)

			testOutpoint := getTestUtxoOutpoint(bw.outpoints)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := getUtxoDeprecated(
					bw.Wallet, testOutpoint,
				)
				require.NoError(b, err)
			}
		})

		b.Run(size.name(namingInfo)+"/1-After", func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  size.numAccounts,
					numAddresses: size.numAddresses,
					numUTXOs:     size.numUTXOs,
				},
			)

			testOutpoint := getTestUtxoOutpoint(bw.outpoints)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := bw.GetUtxo(
					b.Context(), testOutpoint,
				)
				require.NoError(b, err)
			}
		})
	}
}
