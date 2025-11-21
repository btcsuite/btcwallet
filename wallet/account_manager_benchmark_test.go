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
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}
	)

	for i := 0; i <= endGrowthIteration; i++ {
		name := fmt.Sprintf("%0*d-Accounts-%0*d-UTXOs",
			accountGrowthPadding, accountGrowth[i],
			utxoGrowthPadding, utxoGrowth[i])

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

			for b.Loop() {
				_, err := w.Accounts(scopes[0])
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
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// maxGrowthIteration is the maximum iteration index for the
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
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = waddrmgr.DefaultKeyScopes
	)

	for i := 0; i <= endGrowthIteration; i++ {
		name := fmt.Sprintf("%0*d-Accounts-%0*d-UTXOs",
			accountGrowthPadding, accountGrowth[i],
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
				_, err := listAccountsDeprecated(bw.Wallet)
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
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// maxGrowthIteration is the maximum iteration index for the
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
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = waddrmgr.DefaultKeyScopes
	)

	for i := 0; i <= endGrowthIteration; i++ {
		accountName, _ := generateAccountName(accountGrowth[i], scopes)

		name := fmt.Sprintf("%0*d-Accounts-%0*d-UTXOs",
			accountGrowthPadding, accountGrowth[i],
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
				_, err := listAccountsByNameDeprecated(
					bw.Wallet, accountName,
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
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}
	)

	for i := 0; i <= endGrowthIteration; i++ {
		name := fmt.Sprintf("%0*d-Accounts", accountGrowthPadding,
			accountGrowth[i])

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
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}
	)

	for i := 0; i <= endGrowthIteration; i++ {
		accountName, _ := generateAccountName(accountGrowth[i], scopes)

		name := fmt.Sprintf("%0*d-Accounts-%0*d-UTXOs",
			accountGrowthPadding, accountGrowth[i],
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
				_, err := getAccountDeprecated(
					bw.Wallet, scopes[0], accountName,
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
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}
	)

	for i := 0; i <= endGrowthIteration; i++ {
		accountName, accountNumber := generateAccountName(
			accountGrowth[i], scopes,
		)
		newAccountName := accountName + "-renamed"

		name := fmt.Sprintf("%0*d-Accounts", accountGrowthPadding,
			accountGrowth[i])

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

			count := 0
			for b.Loop() {
				newAccountName2 := fmt.Sprintf("%s-%d",
					newAccountName, count)

				err := w.RenameAccountDeprecated(
					scopes[0], accountNumber,
					newAccountName2,
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

		b.Run(name+"/1-After", func(b *testing.B) {
			w := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: utxoGrowth[i],
				},
			)

			newAccountName := accountName + "-renamed"

			b.ReportAllocs()
			b.ResetTimer()

			count := 0
			for b.Loop() {
				newAccountName2 := fmt.Sprintf("%s-%d",
					newAccountName, count)

				err := w.RenameAccount(
					b.Context(), scopes[0], accountName,
					newAccountName2,
				)
				require.NoError(b, err)

				// Rename back to original to keep the benchmark
				// idempotent.
				err = w.RenameAccount(
					b.Context(), scopes[0], newAccountName2,
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
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}

		confirmations = int32(0)
	)

	for i := 0; i <= endGrowthIteration; i++ {
		accountName, _ := generateAccountName(accountGrowth[i], scopes)

		name := fmt.Sprintf("%0*d-Accounts-%0*d-UTXOs",
			accountGrowthPadding, accountGrowth[i],
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
				_, err := getBalanceDeprecated(
					bw.Wallet, scopes[0], accountName,
					confirmations,
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
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}

		dryRun = false
	)

	for i := 0; i <= endGrowthIteration; i++ {
		accountKey, masterFingerprint, addrT := generateTestExtendedKey(
			b, accountGrowth[i],
		)

		name := fmt.Sprintf("%0*d-Accounts", accountGrowthPadding,
			accountGrowth[i])

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
