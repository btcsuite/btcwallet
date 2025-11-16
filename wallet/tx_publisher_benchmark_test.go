// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// BenchmarkBroadcastAPI benchmarks the Broadcast API against the legacy
// PublishTransaction API using identical test data under sequential load.
// Test names start with transaction pool size to group API comparisons for
// benchstat analysis.
//
// Time Complexity Analysis:
// Broadcast is a write operation with amortized cost. The time complexity is
// O(n + m·log(k)) where:
//   - n: number of transaction outputs (address extraction)
//   - m: number of unique addresses extracted from outputs
//   - k: total number of addresses in the wallet (B-tree lookup)
//
// The API is optimized with a 4-stage pipeline:
//  1. Extract: O(n) - CPU-intensive address extraction (no DB locks)
//  2. Filter: O(m·log(k)) - Read-only DB transaction to filter owned addresses
//  3. Plan: O(n·m) - In-memory write plan preparation (typically O(n) as m≈1-2)
//  4. Execute: O(c) - Atomic write transaction
//     (c = owned outputs, typically c << n)
//
// This design ensures DB locks are held only during minimal read/write
// operations, maximizing throughput under concurrent load.
func BenchmarkBroadcastAPI(b *testing.B) {
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
		// affect the Broadcast API's time complexity.
		accountGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		// addressGrowth uses linearGrowth to test O(log k) wallet
		// address lookup scaling. As the address count grows linearly,
		// the filterOwnedAddresses lookup time should grow
		// logarithmically due to B-tree indexing.
		addressGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		// txPoolGrowth uses linearGrowth to establish baseline
		// transaction pool size. This represents the number of
		// unconfirmed transactions being broadcast, stressing the
		// idempotency checks and mempool state management.
		txPoolGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		// txIOGrowth uses linearGrowth for both inputs and outputs to
		// test the O(n) address extraction and O(n·m) write plan
		// preparation costs. As transaction complexity grows linearly,
		// processing time should scale linearly with output count.
		txIOGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		txPoolGrowthPadding = decimalWidth(
			txPoolGrowth[len(txPoolGrowth)-1],
		)

		txIOGrowthPadding = decimalWidth(
			txIOGrowth[len(txIOGrowth)-1],
		)

		addressGrowthPadding = decimalWidth(
			addressGrowth[len(addressGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}

		chainBackend = &mockChainClient{}
	)

	err := chainBackend.Start()
	require.NoError(b, err)
	b.Cleanup(chainBackend.Stop)

	for i := 0; i <= endGrowthIteration; i++ {
		name := fmt.Sprintf("TxPool-%0*d-Addrs-%0*d-Ins-%0*d-Outs-%0*d",
			txPoolGrowthPadding, txPoolGrowth[i],
			addressGrowthPadding, addressGrowth[i],
			txIOGrowthPadding, txIOGrowth[i],
			txIOGrowthPadding, txIOGrowth[i])

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
			bw.chainClient = chainBackend

			var (
				beforeResult map[chainhash.Hash]*wire.MsgTx
				afterResult  map[chainhash.Hash]*wire.MsgTx
			)

			b.Run("0-Before", func(b *testing.B) {
				result := make(map[chainhash.Hash]*wire.MsgTx)
				baselineResult := make(
					map[chainhash.Hash]*wire.MsgTx,
				)

				broadcastLabel := "sequential-before"

				// Clear mempool to ensure clean state for
				// benchmark baseline.
				chainBackend.ResetMempool()

				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; b.Loop(); i++ {
					index := i % len(bw.unconfirmedTxs)
					tx := bw.unconfirmedTxs[index]

					err := bw.PublishTransaction(
						tx, broadcastLabel,
					)
					require.NoError(b, err)

					result, err = chainBackend.GetMempool()
					require.NoError(b, err)

					// Capture baseline after each
					// transaction in the first cycle. This
					// ensures we get the complete mempool
					// state after all transactions are
					// published, since benchmark iteration
					// count varies based on runtime
					// performance.
					if i < len(bw.unconfirmedTxs) {
						baselineResult = result
					}
				}

				require.Equal(
					b, baselineResult, result,
					"PublishTransaction API should be "+
						"idempotent",
				)

				beforeResult = result
			})

			b.Run("1-After", func(b *testing.B) {
				result := make(map[chainhash.Hash]*wire.MsgTx)
				baselineResult := make(
					map[chainhash.Hash]*wire.MsgTx,
				)

				broadcastLabel := "sequential-after"

				// Clear mempool to ensure clean state for
				// benchmark baseline.
				chainBackend.ResetMempool()

				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; b.Loop(); i++ {
					index := i % len(bw.unconfirmedTxs)
					tx := bw.unconfirmedTxs[index]

					err := bw.Broadcast(
						b.Context(), tx, broadcastLabel,
					)
					require.NoError(b, err)

					result, err = chainBackend.GetMempool()
					require.NoError(b, err)

					// Capture baseline after each
					// transaction in the first cycle. This
					// ensures we get the complete mempool
					// state after all transactions are
					// published, since benchmark iteration
					// count varies based on runtime
					// performance.
					if i < len(bw.unconfirmedTxs) {
						baselineResult = result
					}
				}

				require.Equal(
					b, baselineResult, result,
					"PublishTransaction API should be "+
						"idempotent",
				)

				afterResult = result
			})

			assertBroadcastAPIsEquivalent(
				b, beforeResult, afterResult,
			)
		})
	}
}

// BenchmarkBroadcastAPIConcurrently benchmarks the Broadcast API against the
// legacy PublishTransaction API using identical test data under concurrent
// load. Test names start with transaction pool size to group API comparisons
// for benchstat analysis.
//
// Time Complexity Analysis:
// Under concurrent load, the API maintains the same per-transaction complexity
// of O(n + m·log(k)) as the sequential benchmark, where:
//   - n: number of transaction outputs (address extraction)
//   - m: number of unique addresses extracted from outputs
//   - k: total number of addresses in the wallet (B-tree lookup)
//
// The 4-stage pipeline design provides excellent concurrent performance:
//  1. Extract: O(n) - Parallel CPU work, no contention
//  2. Filter: O(m·log(k)) - Read-only transactions, minimal lock contention
//  3. Plan: O(n·m) - Parallel in-memory work, no contention
//  4. Execute: O(c) - Short write transactions reduce lock contention
//
// This benchmark stresses the lock contention characteristics during Stage 2
// (read locks) and Stage 4 (write locks), demonstrating scalability under
// concurrent broadcast operations.
func BenchmarkBroadcastAPIConcurrently(b *testing.B) {
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
		// affect the Broadcast API's time complexity.
		accountGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			constantGrowth,
		)

		// addressGrowth uses linearGrowth to test O(log k) wallet
		// address lookup scaling. As the address count grows linearly,
		// the filterOwnedAddresses lookup time should grow
		// logarithmically due to B-tree indexing.
		addressGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		// txPoolGrowth uses linearGrowth to establish baseline
		// transaction pool size. This represents the number of
		// unconfirmed transactions being broadcast, stressing the
		// idempotency checks and mempool state management.
		txPoolGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		// txIOGrowth uses linearGrowth for both inputs and outputs to
		// test the O(n) address extraction and O(n·m) write plan
		// preparation costs. As transaction complexity grows linearly,
		// processing time should scale linearly with output count.
		txIOGrowth = mapRange(
			startGrowthIteration, endGrowthIteration,
			linearGrowth,
		)

		txPoolGrowthPadding = decimalWidth(
			txPoolGrowth[len(txPoolGrowth)-1],
		)

		txIOGrowthPadding = decimalWidth(
			txIOGrowth[len(txIOGrowth)-1],
		)

		addressGrowthPadding = decimalWidth(
			addressGrowth[len(addressGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}

		chainBackend = &mockChainClient{}
	)

	err := chainBackend.Start()
	require.NoError(b, err)
	b.Cleanup(chainBackend.Stop)

	for i := 0; i <= endGrowthIteration; i++ {
		name := fmt.Sprintf("TxPool-%0*d-Addrs-%0*d-Ins-%0*d-Outs-%0*d",
			txPoolGrowthPadding, txPoolGrowth[i],
			addressGrowthPadding, addressGrowth[i],
			txIOGrowthPadding, txIOGrowth[i],
			txIOGrowthPadding, txIOGrowth[i])

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
			bw.chainClient = chainBackend

			var (
				beforeResult map[chainhash.Hash]*wire.MsgTx
				afterResult  map[chainhash.Hash]*wire.MsgTx
			)

			b.Run("0-Before", func(b *testing.B) {
				broadcastLabel := "concurrent-before"

				// Clear mempool to ensure clean state for
				// benchmark baseline.
				chainBackend.ResetMempool()

				b.ReportAllocs()
				b.ResetTimer()

				b.RunParallel(func(pb *testing.PB) {
					j := len(bw.unconfirmedTxs)
					for i := 0; pb.Next(); i++ {
						k := i % j
						tx := bw.unconfirmedTxs[k]
						err := bw.PublishTransaction(
							tx, broadcastLabel,
						)
						require.NoError(b, err)
					}
				})

				var err error

				beforeResult, err = chainBackend.GetMempool()
				require.NoError(b, err)
			})

			b.Run("1-After", func(b *testing.B) {
				broadcastAfter := "concurrent-after"

				// Clear mempool to ensure clean state for
				// benchmark baseline.
				chainBackend.ResetMempool()

				b.ReportAllocs()
				b.ResetTimer()

				b.RunParallel(func(pb *testing.PB) {
					j := len(bw.unconfirmedTxs)
					for i := 0; pb.Next(); i++ {
						k := i % j
						tx := bw.unconfirmedTxs[k]
						err := bw.Broadcast(
							b.Context(), tx,
							broadcastAfter,
						)
						require.NoError(b, err)
					}
				})

				var err error

				afterResult, err = chainBackend.GetMempool()
				require.NoError(b, err)
			})

			assertBroadcastAPIsEquivalent(
				b, beforeResult, afterResult,
			)
		})
	}
}

// assertBroadcastAPIsEquivalent verifies that PublishTransaction (legacy) and
// Broadcast (new) produce equivalent results by comparing the transactions
// that ended up in the mock mempool.
func assertBroadcastAPIsEquivalent(b *testing.B,
	before, after map[chainhash.Hash]*wire.MsgTx) {

	b.Helper()

	require.NotNil(b, before)
	require.NotNil(b, after)

	// require.Equal uses reflect.DeepEqual internally which compares maps
	// by matching corresponding keys to deeply equal values, regardless of
	// iteration order as stated in the official go package dev docs.
	require.Equal(
		b, before, after,
		"PublishTransaction and Broadcast APIs should produce "+
			"equivalent mempool state",
	)
}
