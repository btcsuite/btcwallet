package wallet

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// BenchmarkListAccountsByScopeAPI benchmarks ListAccountsByScope API and a
// deprecated variant of it using same key scope and identical test data across
// multiple dataset sizes. Test names start with dataset size to group API
// comparisons for benchstat analysis.
func BenchmarkListAccountsByScopeAPI(b *testing.B) {
	benchmarkSizes := generateBenchmarkSizes(
		benchmarkConfig{
			accountGrowth: linearGrowth,
			utxoGrowth:    exponentialGrowth,
			maxIterations: 14,
			startIndex:    0,
		},
	)
	scopes := []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}

	for _, size := range benchmarkSizes {
		b.Run(size.name()+"/0-Before", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:      scopes,
					numAccounts: size.numAccounts,
					numUTXOs:    size.numUTXOs,
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.Accounts(scopes[0])
				require.NoError(b, err)
			}
		})

		b.Run(size.name()+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:      scopes,
					numAccounts: size.numAccounts,
					numUTXOs:    size.numUTXOs,
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.ListAccountsByScope(
					b.Context(), scopes[0],
				)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkListAccountsAPI benchmarks ListAccounts API and a deprecated variant
// of it using same key scopes and identical test data across multiple dataset
// sizes. Test names start with dataset size to group API comparisons for
// benchstat analysis.
func BenchmarkListAccountsAPI(b *testing.B) {
	benchmarkSizes := generateBenchmarkSizes(
		benchmarkConfig{
			accountGrowth: linearGrowth,
			utxoGrowth:    exponentialGrowth,
			maxIterations: 14,
			startIndex:    0,
		},
	)
	scopes := waddrmgr.DefaultKeyScopes

	for _, size := range benchmarkSizes {
		b.Run(size.name()+"/0-Before", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:      scopes,
					numAccounts: size.numAccounts,
					numUTXOs:    size.numUTXOs,
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := listAccountsDeprecated(w)
				require.NoError(b, err)
			}
		})

		b.Run(size.name()+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:      scopes,
					numAccounts: size.numAccounts,
					numUTXOs:    size.numUTXOs,
				},
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.ListAccounts(b.Context())
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkListAccountsByNameAPI benchmarks ListAccountsByName API and a
// deprecated variant of it using same key scopes and identical test data across
// multiple dataset sizes. Test names start with dataset size to group API
// comparisons for benchstat analysis.
func BenchmarkListAccountsByNameAPI(b *testing.B) {
	benchmarkSizes := generateBenchmarkSizes(
		benchmarkConfig{
			accountGrowth: linearGrowth,
			utxoGrowth:    exponentialGrowth,
			maxIterations: 14,
			startIndex:    0,
		},
	)
	scopes := waddrmgr.DefaultKeyScopes

	for _, size := range benchmarkSizes {
		accountName, _ := generateAccountName(size.numAccounts, scopes)

		b.Run(size.name()+"/0-Before", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:      scopes,
					numAccounts: size.numAccounts,
					numUTXOs:    size.numUTXOs,
				},
			)

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_, err := listAccountsByNameDeprecated(
					w, accountName,
				)
				require.NoError(b, err)
			}
		})

		b.Run(size.name()+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:      scopes,
					numAccounts: size.numAccounts,
					numUTXOs:    size.numUTXOs,
				},
			)

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				_, err := w.ListAccountsByName(
					b.Context(), accountName,
				)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkNewAccountAPI benchmarks NewAccount API and NextAccount API using
// identical account creation operations across multiple dataset sizes. Test
// names start with dataset size to group API comparisons for benchstat
// analysis.
func BenchmarkNewAccountAPI(b *testing.B) {
	benchmarkSizes := generateBenchmarkSizes(benchmarkConfig{
		accountGrowth: linearGrowth,
		utxoGrowth:    constantGrowth,
		maxIterations: 10,
		startIndex:    0,
	})
	scopes := []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}

	for _, size := range benchmarkSizes {
		b.Run(size.name()+"/0-Before", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:      scopes,
					numAccounts: size.numAccounts,
					skipUTXOs:   true,
				},
			)

			b.ReportAllocs()
			b.ResetTimer()
			count := 0
			for b.Loop() {
				// Generate a unique account name for each
				// iteration to ensure the idempotent nature of
				// the benchmark.
				accountName := fmt.Sprintf("new-account-%d",
					count)

				_, err := w.NextAccount(scopes[0], accountName)
				require.NoError(b, err)
				count++
			}
		})

		b.Run(size.name()+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:      scopes,
					numAccounts: size.numAccounts,
					skipUTXOs:   true,
				},
			)

			b.ReportAllocs()
			b.ResetTimer()
			count := 0
			for b.Loop() {
				// Generate a unique account name for each
				// iteration to ensure the idempotent nature of
				// the benchmark.
				accountName := fmt.Sprintf("new-account-%d",
					count)

				_, err := w.NewAccount(
					b.Context(), scopes[0], accountName,
				)
				require.NoError(b, err)
				count++
			}
		})
	}
}
