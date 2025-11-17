package wallet

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// BenchmarkGetTxAPI benchmarks GetTx API and its deprecated variant
// GetTransaction using identical test data across transactions with varying
// complexity (input/output counts). Test names start with transaction
// complexity to group API comparisons for benchstat analysis.
//
// Time Complexity Analysis:
// GetTx has no amortization - it's a read operation with consistent upper/tight
// bound cost every time. The time complexity is O(log n + I + O) where:
//   - n: number of transactions in the database (B-tree lookup)
//   - I: number of inputs in the transaction
//   - O: number of outputs in the transaction
func BenchmarkGetTxAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// endGrowthIteration is the maximum iteration index for the
		// growth sequence.
		endGrowthIteration = 5
	)

	var (
		// accountGrowth uses constantGrowth since account count doesn't
		// affect the API's time complexity.
		accountGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		// addressGrowth uses constantGrowth since address count doesn't
		// affect the API's time complexity.
		addressGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		// txPoolGrowth uses linearGrowth to test O(log n) B-tree lookup
		// scaling. As database size grows linearly, lookup time should
		// grow logarithmically, demonstrating sublinear scaling.
		txPoolGrowth = mapRange(
			startGrowthIteration, endGrowthIteration, linearGrowth,
		)

		// txIOGrowth uses symmetric linearGrowth for both inputs
		// and outputs to stress test the O(I + O) processing cost with
		// rapidly growing transaction complexity, exposing potential
		// performance bottlenecks in input/output iteration and address
		// extraction.
		txIOGrowth = mapRange(
			startGrowthIteration, endGrowthIteration, linearGrowth,
		)

		txPoolGrowthPadding = decimalWidth(
			txPoolGrowth[len(txPoolGrowth)-1],
		)

		txIOGrowthPadding = decimalWidth(
			txIOGrowth[len(txIOGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}
	)

	for i := 0; i <= endGrowthIteration; i++ {
		name := fmt.Sprintf("TxPool-%0*d-Ins-%0*d-Outs-%0*d",
			txPoolGrowthPadding, txPoolGrowth[i], txIOGrowthPadding,
			txIOGrowth[i], txIOGrowthPadding, txIOGrowth[i])

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
			medianIndex := len(bw.allTxs) / 2
			testTxHash := bw.allTxs[medianIndex].TxHash()

			var (
				beforeResult *GetTransactionResult
				afterResult  *TxDetail
			)

			b.Run("0-Before", func(b *testing.B) {
				var (
					result         *GetTransactionResult
					baselineResult *GetTransactionResult
					err            error
				)

				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; b.Loop(); i++ {
					result, err = bw.GetTransaction(
						testTxHash,
					)
					require.NoError(b, err)

					// Capture first result only.
					if i == 0 {
						baselineResult = result
					}
				}

				require.Equal(
					b, baselineResult, result,
					"GetTransaction API should be "+
						"idempotent",
				)

				beforeResult = result
			})

			b.Run("1-After", func(b *testing.B) {
				var (
					result         *TxDetail
					baselineResult *TxDetail
					err            error
				)

				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; b.Loop(); i++ {
					result, err = bw.GetTx(
						b.Context(), testTxHash,
					)
					require.NoError(b, err)

					// Capture first baseline result only.
					if i == 0 {
						baselineResult = result
					}
				}

				require.Equal(
					b, baselineResult, result,
					"GetTx API should be idempotent",
				)

				afterResult = result
			})

			// Verify API equivalence after benchmarks complete.
			// This ensures:
			//   - Both APIs return consistent results for the same
			//     transaction
			//   - The new API maintains compatibility with the
			//     legacy API
			//   - Regression prevention for future changes
			assertGetTxAPIsEquivalent(
				b, bw.Wallet, beforeResult, afterResult,
			)
		})
	}
}

// assertGetTxAPIsEquivalent verifies that GetTransaction (legacy) and GetTx
// (new) return equivalent data for the same transaction.
func assertGetTxAPIsEquivalent(b *testing.B, w *Wallet,
	before *GetTransactionResult, after *TxDetail) {

	b.Helper()

	require.NotNil(b, before)
	require.NotNil(b, after)

	afterConverted, err := w.GetTransaction(after.Hash)
	require.NoError(b, err)

	require.GreaterOrEqual(b, afterConverted.Confirmations, int32(0))

	require.Equal(b, before, afterConverted)
}
