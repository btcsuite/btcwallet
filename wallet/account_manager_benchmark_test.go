package wallet

import (
	"errors"
	"fmt"
	"runtime"
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
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

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
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
		maxGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = waddrmgr.DefaultKeyScopes
	)

	for i := 0; i <= maxGrowthIteration; i++ {
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
		maxGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = waddrmgr.DefaultKeyScopes
	)

	for i := 0; i <= maxGrowthIteration; i++ {
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

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 10
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
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

				_, err := w.NewAccount(b.Context(), NewAccountParams{
					Scope: scopes[0],
					Name:  accountName,
				})
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

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
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

	// Use shared node data alongside the original growth matrix.
	b.Run("matched", func(b *testing.B) {
		RunKVDBBenchmark(b,
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				// Keep full legacy account result construction
				// inside each measured call.
				return func() error {
					result, err := getAccountDeprecated(
						w, waddrmgr.KeyScopeBIP0086,
						"default",
					)

					// Retain the complete result so the
					// call includes its construction.
					runtime.KeepAlive(result)

					return err
				}
			},
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				// Resolve request inputs before timing;
				// repeat only the native API operation.
				ctx := b.Context()

				return func() error {
					result, err := w.GetAccount(
						ctx, waddrmgr.KeyScopeBIP0086,
						"default",
					)

					// Retain the complete result so the
					// call includes its construction.
					runtime.KeepAlive(result)

					return err
				}
			},
		)
	})
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

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 11
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0044}
	)

	for i := 0; i <= maxGrowthIteration; i++ {
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

// BenchmarkImportAccountAPI benchmarks ImportAccount API and
// ImportAccountDeprecated API using identical account import operations
// across multiple dataset sizes. Test names start with dataset size to group
// API comparisons for benchstat analysis.
func BenchmarkImportAccountAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 10
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			linearGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		accountGrowthPadding = decimalWidth(
			accountGrowth[len(accountGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}

		dryRun = false
	)

	for i := 0; i <= maxGrowthIteration; i++ {
		accountKey, masterFingerprint, addrT := generateTestExtendedKey(
			b, accountGrowth[i],
		)
		inputFingerprint := MasterFingerprint(masterFingerprint)

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
					b.Context(), ImportAccountParams{
						Name:                 accountName,
						XPub:                 accountKey,
						AddrType:             addrT,
						MasterKeyFingerprint: &inputFingerprint,
					}, dryRun,
				)
				require.NoError(b, err)

				count++
			}
		})
	}
}

// BenchmarkGetAccountDifferentAPI reads a different existing item on each call.
func BenchmarkGetAccountDifferentAPI(b *testing.B) {
	b.Run("matched", func(b *testing.B) {
		RunKVDBBenchmark(b,
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				return benchmarkGetAccountRequests(
					b, w, workload, true, false,
				)
			},
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				return benchmarkGetAccountRequests(
					b, w, workload, false, false,
				)
			},
		)
	})
}

// BenchmarkGetAccountNotFoundAPI reads a different missing item on each call.
func BenchmarkGetAccountNotFoundAPI(b *testing.B) {
	b.Run("matched", func(b *testing.B) {
		RunKVDBBenchmark(b,
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				return benchmarkGetAccountRequests(
					b, w, workload, true, true,
				)
			},
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				return benchmarkGetAccountRequests(
					b, w, workload, false, true,
				)
			},
		)
	})
}

// benchmarkGetAccountRequests prepares different inputs before timing.
// BenchmarkRead uses the first input for its separate untimed call.
func benchmarkGetAccountRequests(b *testing.B, w *Wallet,
	workload bwtest.NodeBenchmarkWorkload, legacy, missing bool) func() error {

	b.Helper()

	// Prepare the shared account mix before timing; each suite keeps
	// its native lookup and not-found error handling.
	count := bwtest.BenchmarkReadCount(b) + 1
	scopes, names := bwtest.NodeBenchmarkAccountReadTargets(
		b, workload, count, missing,
	)

	expected := ErrAccountNotFound
	if legacy {
		expected = errAccountNotFound
	}

	ctx := b.Context()
	// The first item is for warmup; measured calls read the rest once.
	index := 0

	// Resolve the native operation inside each call, without request data
	// generation, result validation or interaction-recording mocks.
	read := func() error {
		scope, name := scopes[index], names[index]
		index++
		// Keep native result types so benchmark bookkeeping does not
		// box the modern value into an interface and add allocations.
		var err error
		if legacy {
			result, readErr := getAccountDeprecated(w, scope, name)
			runtime.KeepAlive(result)

			err = readErr
		} else {
			result, readErr := w.GetAccount(ctx, scope, name)
			runtime.KeepAlive(result)

			err = readErr
		}

		if !missing {
			return err
		}

		// Different native APIs expose different miss identities. Only
		// that expected response completes this request successfully.
		if errors.Is(err, expected) {
			return nil
		}

		return errors.Join(
			errors.New("expected not-found response"), err,
		)
	}

	return read
}
