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

// BenchmarkGetTxAPIConcurrently benchmarks GetTx API and its deprecated
// variant GetTransaction using identical test data under concurrent load.
// Test names start with transaction pool size to group API comparisons for
// benchstat analysis.
//
// Time Complexity Analysis:
// Under concurrent load, the API maintains the same per-transaction complexity
// of O(log n + I + O) as the sequential benchmark, where:
//   - n: number of transactions in the database (B-tree lookup)
//   - I: number of inputs in the transaction
//   - O: number of outputs in the transaction
//
// This benchmark stresses the lock contention characteristics during database
// reads, demonstrating scalability under concurrent read operations.
func BenchmarkGetTxAPIConcurrently(b *testing.B) {
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
				before *GetTransactionResult
				after  *TxDetail
			)

			b.Run("0-Before", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()

				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						res, err := bw.GetTransaction(
							testTxHash,
						)
						before = res

						require.NoError(b, err)
						require.NotNil(b, before)
					}
				})
			})

			b.Run("1-After", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()

				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						res, err := bw.GetTx(
							b.Context(), testTxHash,
						)
						after = res

						require.NoError(b, err)
						require.NotNil(b, after)
					}
				})
			})

			assertGetTxAPIsEquivalent(b, bw.Wallet, before, after)
		})
	}
}

// BenchmarkListTxnsAPI benchmarks ListTxns API and its deprecated variant
// GetTransactions using identical test data across varying block ranges and
// transaction densities. Test names start with complexity metrics to group API
// comparisons for benchstat analysis.
//
// Time Complexity Analysis:
// ListTxns has no amortization - it's a read operation with consistent
// upper/tight bound cost. The time complexity is O(B * T * (I + O)) where:
//   - B: number of blocks in the range [startHeight, endHeight]
//   - T: average transactions per block
//   - I: average inputs per transaction
//   - O: average outputs per transaction
//
// This simplifies to O(N) where N = total inputs + outputs across all
// transactions in the block range.
func BenchmarkListTxnsAPI(b *testing.B) {
	const (
		// startGrowthIteration is the starting iteration index for the
		// growth sequence.
		startGrowthIteration = 0

		// endGrowthIteration is the maximum iteration index for the
		// growth sequence.
		endGrowthIteration = 10
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

		// txPoolGrowth uses exponentialGrowth to stress test the
		// O(B * T) component - total transactions across blocks.
		txPoolGrowth = mapRange(
			startGrowthIteration, endGrowthIteration, linearGrowth,
		)

		// txIOGrowth uses exponentialGrowth for both inputs and outputs
		// to stress test the O(I + O) per-transaction processing cost
		// with rapidly growing transaction complexity.
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
			// Setup wallet once for both API benchmarks.
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

			// List all transactions (no height filter).
			// For GetTransactions (old): nil, nil means all blocks
			// For ListTxns (new): 0, -1 means all blocks
			// (0=genesis, -1=unlimited).
			var (
				startBlock  *BlockIdentifier
				endBlock    *BlockIdentifier
				startHeight int32 = 0
				endHeight   int32 = -1
			)

			var (
				beforeResult *GetTransactionsResult
				afterResult  []*TxDetail
			)

			b.Run("0-Before", func(b *testing.B) {
				var (
					result      *GetTransactionsResult
					firstResult *GetTransactionsResult
					err         error
				)

				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; b.Loop(); i++ {
					result, err = bw.GetTransactions(
						startBlock, endBlock, "", nil,
					)
					require.NoError(b, err)

					// Capture first result only.
					if i == 0 {
						firstResult = result
					}
				}

				require.Equal(
					b, firstResult, result,
					"GetTransactions API should be "+
						"idempotent",
				)

				beforeResult = result
			})

			b.Run("1-After", func(b *testing.B) {
				var (
					result      []*TxDetail
					firstResult []*TxDetail
					err         error
				)

				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; b.Loop(); i++ {
					result, err = bw.ListTxns(
						b.Context(), startHeight,
						endHeight,
					)
					require.NoError(b, err)

					// Capture first result only.
					if i == 0 {
						firstResult = result
					}
				}

				require.Equal(
					b, firstResult, result,
					"ListTxns API should be idempotent ",
				)

				afterResult = result
			})

			// Verify API equivalence after benchmarks complete.
			// This ensures:
			//   - Both APIs return consistent results for the same
			//     block range
			//   - The new API maintains compatibility with the
			//     legacy API
			//   - Regression prevention for future changes
			assertListTxnsAPIsEquivalent(
				b, bw.Wallet, beforeResult, afterResult,
			)
		})
	}
}

// BenchmarkListTxnsAPIConcurrently benchmarks ListTxns API and its deprecated
// variant GetTransactions using identical test data under concurrent load.
// Test names start with complexity metrics to group API comparisons for
// benchstat analysis.
//
// Time Complexity Analysis:
// Under concurrent load, the API maintains the same per-request complexity
// of O(B * T * (I + O)) as the sequential benchmark, where:
//   - B: number of blocks in the range [startHeight, endHeight]
//   - T: average transactions per block
//   - I: average inputs per transaction
//   - O: average outputs per transaction
//
// This benchmark stresses lock contention characteristics during database
// reads, demonstrating scalability under concurrent read operations.
func BenchmarkListTxnsAPIConcurrently(b *testing.B) {
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

		// txPoolGrowth uses linearGrowth for CI-friendly execution
		// while still testing scaling behavior.
		txPoolGrowth = mapRange(
			startGrowthIteration, endGrowthIteration, linearGrowth,
		)

		// txIOGrowth uses linearGrowth for CI-friendly execution
		// while still testing scaling behavior.
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

			// List all transactions (no height filter).
			var (
				startBlock  *BlockIdentifier
				endBlock    *BlockIdentifier
				startHeight int32 = 0
				endHeight   int32 = -1
			)

			var (
				beforeResult *GetTransactionsResult
				afterResult  []*TxDetail
			)

			b.Run("0-Before", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()

				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						res, err := bw.GetTransactions(
							startBlock, endBlock,
							"", nil,
						)
						beforeResult = res

						require.NoError(b, err)
						require.NotNil(b, res)
					}
				})
			})

			b.Run("1-After", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()

				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						res, err := bw.ListTxns(
							b.Context(),
							startHeight, endHeight,
						)
						afterResult = res

						require.NoError(b, err)
						require.NotNil(b, res)
					}
				})
			})

			assertListTxnsAPIsEquivalent(
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

// assertListTxnsAPIsEquivalent verifies that GetTransactions (legacy) and
// ListTxns (new) return equivalent data for the same block range.
func assertListTxnsAPIsEquivalent(b *testing.B, w *Wallet,
	before *GetTransactionsResult, after []*TxDetail) {

	b.Helper()

	require.NotNil(b, before)
	require.NotNil(b, after)

	// Use GetTransactions API to fetch all transactions (both confirmed
	// and unconfirmed) for comparison. Parameters match the benchmark's
	// "before" case:
	// - startBlock: nil (from genesis)
	// - endBlock: nil (to current tip)
	// - accountName: "" (all accounts)
	// - cancel: nil (no cancellation)
	var (
		startBlock  *BlockIdentifier
		endBlock    *BlockIdentifier
		accountName string
		cancel      <-chan struct{}
	)

	afterConverted, err := w.GetTransactions(
		startBlock, endBlock, accountName, cancel,
	)
	require.NoError(b, err)

	require.NotEmpty(b, before.MinedTransactions)
	require.NotEmpty(b, before.UnminedTransactions)

	require.Equal(
		b, before, afterConverted,
		"GetTransactions and ListTxns APIs should return equivalent "+
			"data",
	)
}
