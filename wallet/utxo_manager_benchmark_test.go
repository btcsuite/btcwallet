package wallet

import (
	"fmt"
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

			outpoints := txsToOutpoints(bw.confirmedTxs)
			testOutpoint := getTestUtxoOutpoint(outpoints)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := getUtxoDeprecated(
					bw.Wallet, testOutpoint,
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

			outpoints := txsToOutpoints(bw.confirmedTxs)
			testOutpoint := getTestUtxoOutpoint(outpoints)

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

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}

		minConfs = 0

		maxConfs = math.MaxInt32
	)

	for i := 0; i <= endGrowthIteration; i++ {
		accountName, _ := generateAccountName(accountGrowth[i], scopes)

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
				_, err := bw.ListUnspentDeprecated(
					int32(minConfs), int32(maxConfs),
					accountName,
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
			constantGrowth,
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

		addressGrowthPadding = decimalWidth(
			addressGrowth[len(addressGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}

		lockID = wtxmgr.LockID{0x01, 0x02, 0x03, 0x04}

		duration = time.Hour
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

			outpoints := txsToOutpoints(bw.confirmedTxs)
			testOutpoint := getTestUtxoOutpoint(outpoints)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := bw.LeaseOutputDeprecated(
					lockID, testOutpoint, duration,
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

			outpoints := txsToOutpoints(bw.confirmedTxs)
			testOutpoint := getTestUtxoOutpoint(outpoints)

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

// BenchmarkReleaseOutputAPI benchmarks ReleaseOutput API and its deprecated
// variant ReleaseOutputDeprecated. Although ReleaseOutput is an O(1) operation,
// testing across different dataset sizes helps identify any database bucket
// depth effects or positional bias as the UTXO set grows. Outputs must be
// leased before they can be released.
func BenchmarkReleaseOutputAPI(b *testing.B) {
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
			constantGrowth,
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

		addressGrowthPadding = decimalWidth(
			addressGrowth[len(addressGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}

		lockID = wtxmgr.LockID{0x01, 0x02, 0x03, 0x04}

		duration = time.Hour
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

			outpoints := txsToOutpoints(bw.confirmedTxs)
			testOutpoint := getTestUtxoOutpoint(outpoints)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := bw.LeaseOutputDeprecated(
					lockID, testOutpoint, duration,
				)
				require.NoError(b, err)

				err = bw.ReleaseOutputDeprecated(
					lockID, testOutpoint,
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

			outpoints := txsToOutpoints(bw.confirmedTxs)
			testOutpoint := getTestUtxoOutpoint(outpoints)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := bw.LeaseOutput(
					b.Context(), lockID, testOutpoint,
					duration,
				)
				require.NoError(b, err)

				err = bw.ReleaseOutput(
					b.Context(), lockID, testOutpoint,
				)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkListLeasedOutputsAPI benchmarks ListLeasedOutputs API and its
// deprecated variant ListLeasedOutputsDeprecated. The deprecated API performs
// N+1 transaction lookups to enrich each leased output with value and pkScript,
// while the new API returns minimal lock metadata in a single scan. Performance
// difference scales with the number of leased outputs.
func BenchmarkListLeasedOutputsAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// linearGrowthIteration is the maximum iteration index for the
		// growth sequence.
		linearGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, linearGrowthIteration,
			constantGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, linearGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, linearGrowthIteration,
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

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}

		duration = time.Hour
	)

	for i := 0; i <= linearGrowthIteration; i++ {
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

			// Lease all outputs to maximize the N+1 query impact.
			leaseAllOutputs(
				b, bw.Wallet, txsToOutpoints(bw.confirmedTxs),
				duration,
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := bw.ListLeasedOutputsDeprecated()
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

			// Lease all outputs to maximize the N+1 query impact.
			leaseAllOutputs(
				b, bw.Wallet, txsToOutpoints(bw.confirmedTxs),
				duration,
			)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := bw.ListLeasedOutputs(b.Context())
				require.NoError(b, err)
			}
		})
	}
}
