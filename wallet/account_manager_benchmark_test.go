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
	benchmarkSizes, namingInfo := generateBenchmarkSizes(
		benchmarkConfig{
			accountGrowth: linearGrowth,
			addressGrowth: constantGrowth,
			utxoGrowth:    exponentialGrowth,
			maxIterations: 14,
			startIndex:    0,
		},
	)
	scopes := []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}

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

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.Accounts(scopes[0])
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
	benchmarkSizes, namingInfo := generateBenchmarkSizes(
		benchmarkConfig{
			accountGrowth: linearGrowth,
			addressGrowth: constantGrowth,
			utxoGrowth:    exponentialGrowth,
			maxIterations: 14,
			startIndex:    0,
		},
	)
	scopes := waddrmgr.DefaultKeyScopes

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

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := listAccountsDeprecated(bw.Wallet)
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
	benchmarkSizes, namingInfo := generateBenchmarkSizes(
		benchmarkConfig{
			accountGrowth: linearGrowth,
			addressGrowth: constantGrowth,
			utxoGrowth:    exponentialGrowth,
			maxIterations: 14,
			startIndex:    0,
		},
	)
	scopes := waddrmgr.DefaultKeyScopes

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
				_, err := listAccountsByNameDeprecated(
					bw.Wallet, accountName,
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
	benchmarkSizes, namingInfo := generateBenchmarkSizes(benchmarkConfig{
		accountGrowth: linearGrowth,
		addressGrowth: constantGrowth,
		utxoGrowth:    constantGrowth,
		maxIterations: 10,
		startIndex:    0,
	})
	scopes := []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}

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

			b.ReportAllocs()
			b.ResetTimer()

			count := 0
			for b.Loop() {
				// Generate a unique account name for each
				// iteration to ensure the idempotent nature of
				// the benchmark.
				accountName := fmt.Sprintf("new-account-%d",
					count)

				_, err := bw.NextAccount(
					scopes[0], accountName,
				)
				require.NoError(b, err)

				count++
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

// BenchmarkGetAccountAPI benchmarks GetAccount API and a deprecated wrapper API
// using identical account lookups across multiple dataset sizes. Test names
// start with dataset size to group API comparisons for benchstat analysis.
func BenchmarkGetAccountAPI(b *testing.B) {
	benchmarkSizes, namingInfo := generateBenchmarkSizes(benchmarkConfig{
		accountGrowth: exponentialGrowth,
		addressGrowth: constantGrowth,
		utxoGrowth:    exponentialGrowth,
		maxIterations: 14,
		startIndex:    0,
	})
	scopes := []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}

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
				_, err := getAccountDeprecated(
					bw.Wallet, scopes[0], accountName,
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
				_, err := w.GetAccount(
					b.Context(), scopes[0], accountName,
				)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkRenameAccountAPI benchmarks RenameAccount API and
// RenameAccountDeprecated API using identical rename operations across multiple
// dataset sizes. Test names start with dataset size to group API comparisons
// for benchstat analysis.
func BenchmarkRenameAccountAPI(b *testing.B) {
	benchmarkSizes, namingInfo := generateBenchmarkSizes(benchmarkConfig{
		accountGrowth: exponentialGrowth,
		addressGrowth: constantGrowth,
		utxoGrowth:    constantGrowth,
		maxIterations: 11,
		startIndex:    0,
	})
	scopes := []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}

	for _, size := range benchmarkSizes {
		accountName, accountNumber := generateAccountName(
			size.numAccounts, scopes,
		)
		newName := accountName + "-renamed"

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

			count := 0
			for b.Loop() {
				newName2 := fmt.Sprintf("%s-%d", newName, count)
				err := w.RenameAccountDeprecated(
					scopes[0], accountNumber, newName2,
				)
				require.NoError(b, err)

				// Rename back to original to keep the benchmark
				// idempotent.
				err = w.RenameAccountDeprecated(
					scopes[0], accountNumber, accountName,
				)
				require.NoError(b, err)

				count++
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

			count := 0
			for b.Loop() {
				newName2 := fmt.Sprintf("%s-%d", newName, count)
				err := w.RenameAccount(
					b.Context(), scopes[0], accountName,
					newName2,
				)
				require.NoError(b, err)

				// Rename back to original to keep the benchmark
				// idempotent.
				err = w.RenameAccount(
					b.Context(), scopes[0], newName2,
					accountName,
				)
				require.NoError(b, err)

				count++
			}
		})
	}
}

// BenchmarkGetBalanceAPI benchmarks Balance API and a deprecated wrapper API
// using identical balance lookups across multiple dataset sizes. Test names
// start with dataset size to group API comparisons for benchstat analysis.
func BenchmarkGetBalanceAPI(b *testing.B) {
	benchmarkSizes, namingInfo := generateBenchmarkSizes(benchmarkConfig{
		accountGrowth: linearGrowth,
		addressGrowth: constantGrowth,
		utxoGrowth:    exponentialGrowth,
		maxIterations: 14,
		startIndex:    0,
	})
	scopes := []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}
	confirmations := int32(0)

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
				_, err := getBalanceDeprecated(
					bw.Wallet, scopes[0], accountName,
					confirmations,
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
				_, err := bw.Balance(
					b.Context(), uint32(confirmations),
					scopes[0], accountName,
				)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkImportAccountAPI benchmarks ImportAccount API and
// ImportAccountDeprecated API using identical account import operations
// across multiple dataset sizes. Test names start with dataset size to group
// API comparisons for benchstat analysis.
func BenchmarkImportAccountAPI(b *testing.B) {
	benchmarkSizes, namingInfo := generateBenchmarkSizes(benchmarkConfig{
		accountGrowth: linearGrowth,
		addressGrowth: constantGrowth,
		utxoGrowth:    constantGrowth,
		maxIterations: 10,
		startIndex:    0,
	})
	scopes := []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}
	dryRun := false

	for _, size := range benchmarkSizes {
		accountKey, masterFingerprint, addrT := generateTestExtendedKey(
			b, size.numAccounts,
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

			count := 0
			for b.Loop() {
				// Generate a unique account name for each
				// iteration to ensure the idempotent nature of
				// the benchmark.
				accountName := fmt.Sprintf("import-account-%d",
					count)

				_, err := w.ImportAccountDeprecated(
					accountName, accountKey,
					masterFingerprint, &addrT,
				)
				require.NoError(b, err)

				count++
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

			count := 0
			for b.Loop() {
				// Generate a unique account name for each
				// iteration to ensure the idempotent nature of
				// the benchmark.
				accountName := fmt.Sprintf("import-account-%d",
					count)

				_, err := w.ImportAccount(
					b.Context(), accountName, accountKey,
					masterFingerprint, addrT, dryRun,
				)
				require.NoError(b, err)

				count++
			}
		})
	}
}
