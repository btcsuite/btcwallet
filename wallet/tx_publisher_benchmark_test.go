// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
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
//  2. Filter: O(m·log(k)) - Single batched read-only store lookup that resolves
//     all m unique scripts to the owned subset in one DB operation
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

		chainBackend = &bwmock.MempoolChain{}
	)

	err := chainBackend.Start(b.Context())
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
			bw.cfg.Chain = chainBackend

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
				chainBackend.Reset()

				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; b.Loop(); i++ {
					index := i % len(bw.unconfirmedTxs)
					tx := bw.unconfirmedTxs[index]

					err := bw.PublishTransaction(
						tx, broadcastLabel,
					)
					require.NoError(b, err)

					result = chainBackend.Snapshot()

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
				chainBackend.Reset()

				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; b.Loop(); i++ {
					index := i % len(bw.unconfirmedTxs)
					tx := bw.unconfirmedTxs[index]

					err := bw.Broadcast(
						b.Context(), tx, broadcastLabel,
					)
					require.NoError(b, err)

					result = chainBackend.Snapshot()

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
//  2. Filter: O(m·log(k)) - Single batched read-only store lookup per tx,
//     minimal lock contention
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

		chainBackend = &bwmock.MempoolChain{}
	)

	err := chainBackend.Start(b.Context())
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
			bw.cfg.Chain = chainBackend

			var (
				beforeResult map[chainhash.Hash]*wire.MsgTx
				afterResult  map[chainhash.Hash]*wire.MsgTx
			)

			b.Run("0-Before", func(b *testing.B) {
				broadcastLabel := "concurrent-before"

				// Clear mempool to ensure clean state for
				// benchmark baseline.
				chainBackend.Reset()

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

				beforeResult = chainBackend.Snapshot()
			})

			b.Run("1-After", func(b *testing.B) {
				broadcastAfter := "concurrent-after"

				// Clear mempool to ensure clean state for
				// benchmark baseline.
				chainBackend.Reset()

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

				afterResult = chainBackend.Snapshot()
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

// countingAddrStore is a minimal db.Store whose only purpose is to count how
// many times ResolveOwnedAddresses is invoked, so a benchmark can assert that
// the output-ownership filter issues a single batched lookup regardless of how
// many outputs a transaction has. Every other Store method is intentionally
// left unimplemented because filterOwnedAddresses only calls
// ResolveOwnedAddresses; the embedded nil interface is therefore never
// dereferenced.
type countingAddrStore struct {
	db.Store

	// owned is the set of wallet-owned scripts, keyed by string(script).
	owned map[string]*db.AddressInfo

	// calls counts the number of ResolveOwnedAddresses invocations.
	calls atomic.Int64
}

// ResolveOwnedAddresses records the call and returns the owned subset of the
// requested scripts in a single operation, mirroring the real backends'
// contract.
func (c *countingAddrStore) ResolveOwnedAddresses(_ context.Context,
	query db.ResolveOwnedAddressesQuery) (map[string]*db.AddressInfo, error) {

	c.calls.Add(1)

	result := make(map[string]*db.AddressInfo)
	for _, script := range query.ScriptPubKeys {
		if info, ok := c.owned[string(script)]; ok {
			result[string(script)] = info
		}
	}

	return result, nil
}

// BenchmarkFilterOwnedAddresses measures the output-ownership filter on a tx
// with a growing number of distinct output addresses (half wallet-owned). It
// reports a store_ops/op metric to demonstrate that the batched lookup keeps
// the filter stage at a single store operation per transaction (N -> 1),
// independent of the output count N.
func BenchmarkFilterOwnedAddresses(b *testing.B) {
	outputCounts := []int{1, 8, 64, 256, 1024}

	for _, n := range outputCounts {
		b.Run(fmt.Sprintf("Outputs-%04d", n), func(b *testing.B) {
			// Build n distinct output addresses; every other one is
			// wallet-owned.
			txOutAddrs := make(map[uint32][]btcutil.Address, n)
			owned := make(map[string]*db.AddressInfo)

			for i := range n {
				privKey, err := btcec.NewPrivateKey()
				require.NoError(b, err)

				addr, err := btcutil.NewAddressPubKey(
					privKey.PubKey().SerializeCompressed(),
					&chainParams,
				)
				require.NoError(b, err)

				txOutAddrs[uint32(i)] = []btcutil.Address{addr}

				if i%2 != 0 {
					continue
				}

				script, err := txscript.PayToAddrScript(addr)
				require.NoError(b, err)

				owned[string(script)] = &db.AddressInfo{
					ScriptPubKey: script,
				}
			}

			store := &countingAddrStore{owned: owned}
			w := &Wallet{store: store}
			w.cache = newStoreRuntimeCache(store)

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				_, err := w.filterOwnedAddresses(
					b.Context(), txOutAddrs,
				)
				require.NoError(b, err)
			}

			b.StopTimer()

			// The filter must issue exactly one store lookup per
			// call, no matter how many outputs the tx has.
			opsPerCall := float64(store.calls.Load()) /
				float64(b.N)
			require.InDelta(b, 1.0, opsPerCall, 1e-9,
				"filter stage must be a single store op per tx")
			b.ReportMetric(opsPerCall, "store_ops/op")
		})
	}
}
