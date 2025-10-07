package wallet

import (
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
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

// BenchmarkListUnspentAPI benchmarks ListUnspent API and its deprecated
// variant ListUnspentDeprecated using same key scope and identical test data
// across multiple dataset sizes. Test names start with dataset size to group
// API comparisons for benchstat analysis.
func BenchmarkListUnspentAPI(b *testing.B) {
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
	minConfs := 0
	maxConfs := math.MaxInt32

	for _, size := range benchmarkSizes {
		accountName, _ := generateAccountName(size.numAccounts, scopes)

		b.Run(size.name(namingInfo)+"/0-Before", func(b *testing.B) {
			bw := setupBenchmarkWallet(
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
				_, err := bw.ListUnspentDeprecated(
					int32(minConfs), int32(maxConfs),
					accountName,
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

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := bw.ListUnspent(
					b.Context(), UtxoQuery{
						Account:  accountName,
						MinConfs: int32(minConfs),
						MaxConfs: int32(maxConfs),
					},
				)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkLeaseOutputAPI benchmarks LeaseOutput API and its deprecated
// variant LeaseOutputDeprecated. Although LeaseOutput is an O(1) operation,
// testing across different dataset sizes helps identify any database bucket
// depth effects or positional bias as the UTXO set grows.
func BenchmarkLeaseOutputAPI(b *testing.B) {
	benchmarkSizes, namingInfo := generateBenchmarkSizes(
		benchmarkConfig{
			accountGrowth: constantGrowth,
			utxoGrowth:    linearGrowth,
			addressGrowth: constantGrowth,
			maxIterations: 14,
			startIndex:    0,
		},
	)
	scopes := []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}
	lockID := wtxmgr.LockID{0x01, 0x02, 0x03, 0x04}
	duration := time.Hour

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
				_, err := bw.LeaseOutputDeprecated(
					lockID, testOutpoint, duration,
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
				_, err := bw.LeaseOutput(
					b.Context(), lockID, testOutpoint,
					duration,
				)
				require.NoError(b, err)
			}
		})
	}
}
