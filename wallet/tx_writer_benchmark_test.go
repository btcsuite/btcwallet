package wallet

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// BenchmarkLabelTxAPI benchmarks LabelTx API against its deprecated variant
// LabelTransaction (when overwrite is true) using identical test data.
// Test names use the wallet size metric to group API comparisons for benchstat
// analysis.
//
// Time Complexity Analysis:
// Both APIs are dominated by a single key-value write (PutTxLabel) operation,
// which is typically O(log n) on a B-tree where n is the number of transactions
// (keys). Since the new API eliminates an initial read operation
// (FetchTxLabel), it should show better performance.
func BenchmarkLabelTxAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// endGrowthIteration is the maximum iteration index for the
		// growth sequence.
		endGrowthIteration = 5
	)

	var (
		// accountGrowth and addressGrowth use constantGrowth since
		// ccount/address count doesn't directly affect the API's time
		// complexity for a single tx label.
		accountGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		// txPoolGrowth uses linearGrowth to test O(log n) B-tree write
		// scaling. As database size grows linearly, write time should
		// grow logarithmically.
		txPoolGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		// txIOGrowth uses constantGrowth since I/O count doesn't affect
		// the LabelTx API's time complexity.
		txIOGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		txPoolGrowthPadding = decimalWidth(
			txPoolGrowth[len(txPoolGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}

		// testLabel is the string used for labeling the transaction.
		testLabel = "bench_label"
	)

	for i := 0; i <= endGrowthIteration; i++ {
		name := fmt.Sprintf("TxPool-%0*d", txPoolGrowthPadding,
			txPoolGrowth[i])

		b.Run(name, func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: txPoolGrowth[i],
					numTxInputs:  txIOGrowth[i],
					numTxOutputs: txIOGrowth[i],
				},
			)

			// Get a transaction hash from the middle of the dataset
			// for representative benchmarking.
			medianIndex := len(bw.unconfirmedTxs) / 2
			testTxHash := bw.unconfirmedTxs[medianIndex].TxHash()

			// Initial write of the label to ensure both APIs are
			// testing the _overwrite_ case, which aligns the
			// functional behavior of LabelTransaction
			// (overwrite=true) with LabelTx.
			err := bw.LabelTx(b.Context(), testTxHash, testLabel)
			require.NoError(b, err)

			b.Run("0-Before", func(b *testing.B) {
				const overwrite = true

				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; b.Loop(); i++ {
					err = bw.LabelTransaction(
						testTxHash, testLabel,
						overwrite,
					)
					require.NoError(b, err)
				}
			})

			b.Run("1-After", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()

				// INTENTIONAL REGRESSION: Store allocations to prevent optimization
				var sink []byte
				var sinkSlice [][]byte

				for i := 0; b.Loop(); i++ {
					// Allocate extra memory to test CI detection
					sink = make([]byte, 5000)  // ~5KB extra bytes
					for j := 0; j < 20; j++ {  // 20 extra allocations
						sinkSlice = append(sinkSlice[:0], make([]byte, 1))
					}

					err = bw.LabelTx(
						b.Context(), testTxHash,
						testLabel,
					)
					require.NoError(b, err)
				}
				// Use sink to prevent dead code elimination
				_ = sink
				_ = sinkSlice
			})

			// Verification: Ensure the label was successfully
			// written and is identical after both benchmarks. Since
			// we are testing the overwrite case repeatedly, we only
			// need to check the final state. That way we are sure
			// that we are benchmarking the thing right.
			assertLabelTxAPIsEquivalent(
				b, bw.Wallet, testTxHash, testLabel,
			)
		})
	}
}

// BenchmarkLabelTxAPIConcurrently benchmarks LabelTx API and its deprecated
// variant LabelTransaction (when overwrite is true) using identical test data
// under concurrent load. Test names use the wallet size metric to group API
// comparisons for benchstat analysis.
//
// Time Complexity Analysis:
// Under concurrent load, the API maintains the same per-transaction complexity
// of O(log n) as the sequential benchmark, where n is the number of
// transactions in the database (B-tree write operation). Since the new API
// eliminates an initial read operation (FetchTxLabel), it should show better
// performance even under concurrent load.
//
// This benchmark stresses the lock contention characteristics during database
// writes, demonstrating scalability under concurrent write operations.
func BenchmarkLabelTxAPIConcurrently(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// endGrowthIteration is the maximum iteration index for the
		// growth sequence.
		endGrowthIteration = 5
	)

	var (
		// accountGrowth and addressGrowth use constantGrowth since
		// account/address count doesn't directly affect the API's time
		// complexity for a single tx label.
		accountGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		// txPoolGrowth uses linearGrowth to test O(log n) B-tree write
		// scaling. As database size grows linearly, write time should
		// grow logarithmically.
		txPoolGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		// txIOGrowth uses constantGrowth since I/O count doesn't affect
		// the LabelTx API's time complexity.
		txIOGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		txPoolGrowthPadding = decimalWidth(
			txPoolGrowth[len(txPoolGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}

		// testLabel is the string used for labeling the transaction.
		testLabel = "bench_label"
	)

	for i := 0; i <= endGrowthIteration; i++ {
		name := fmt.Sprintf("TxPool-%0*d", txPoolGrowthPadding,
			txPoolGrowth[i])

		b.Run(name, func(b *testing.B) {
			bw := setupBenchmarkWallet(
				b, benchmarkWalletConfig{
					scopes:       scopes,
					numAccounts:  accountGrowth[i],
					numAddresses: addressGrowth[i],
					numWalletTxs: txPoolGrowth[i],
					numTxInputs:  txIOGrowth[i],
					numTxOutputs: txIOGrowth[i],
				},
			)

			// Get a transaction hash from the middle of the dataset
			// for representative benchmarking.
			medianIndex := len(bw.unconfirmedTxs) / 2
			testTxHash := bw.unconfirmedTxs[medianIndex].TxHash()

			// Initial write of the label to ensure both APIs are
			// testing the _overwrite_ case, which aligns the
			// functional behavior of LabelTransaction
			// (overwrite=true) with LabelTx.
			err := bw.LabelTx(b.Context(), testTxHash, testLabel)
			require.NoError(b, err)

			b.Run("0-Before", func(b *testing.B) {
				const overwrite = true

				b.ReportAllocs()
				b.ResetTimer()

				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						err := bw.LabelTransaction(
							testTxHash, testLabel,
							overwrite,
						)
						require.NoError(b, err)
					}
				})
			})

			b.Run("1-After", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()

				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						err := bw.LabelTx(
							b.Context(), testTxHash,
							testLabel,
						)
						require.NoError(b, err)
					}
				})
			})

			// Verification: Ensure the label was successfully
			// written and is identical after both benchmarks. Since
			// we are testing the overwrite case repeatedly, we only
			// need to check the final state. That way we are sure
			// that we are benchmarking the thing right.
			assertLabelTxAPIsEquivalent(
				b, bw.Wallet, testTxHash, testLabel,
			)
		})
	}
}

// assertLabelTxAPIsEquivalent verifies that the transaction label is correctly
// set after the benchmark run.
func assertLabelTxAPIsEquivalent(b *testing.B, w *Wallet, hash chainhash.Hash,
	expectedLabel string) {

	b.Helper()

	var actualLabel string

	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

		var err error

		actualLabel, err = w.txStore.FetchTxLabel(txmgrNs, hash)

		return err
	})

	require.NoError(b, err)
	require.Equal(
		b, expectedLabel, actualLabel,
		"LabelTx and LabelTransaction should result in the same label "+
			"value",
	)
}
