package wallet

import (
	"errors"
	"fmt"
	"math"
	"runtime"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// legacyBenchmarkChain supplies the prepared tip without recording each read.
// Unused chain methods retain the shared mock's unexpected-call checks.
type legacyBenchmarkChain struct {
	*bwmock.Chain

	tip waddrmgr.BlockStamp
}

// Keep the benchmark dependency aligned with the Wallet's existing contract.
var _ chain.Interface = (*legacyBenchmarkChain)(nil)

// GetBestBlock excludes RPC transport and mock bookkeeping from Wallet work.
func (c *legacyBenchmarkChain) GetBestBlock() (*chainhash.Hash, int32, error) {
	return &c.tip.Hash, c.tip.Height, nil
}

// BenchmarkGetUtxoAPI benchmarks GetUtxo API and its deprecated variant
// FetchOutpointInfo using same key scope and identical test data across
// multiple dataset sizes. Test names start with dataset size to group API
// comparisons for benchstat analysis.
func BenchmarkGetUtxoAPI(b *testing.B) {
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
			linearGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
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

	for i := 0; i <= maxGrowthIteration; i++ {
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

	// Use shared node data alongside the original growth matrix.
	// Retain the legacy caller workflow and its confirmation semantics.
	b.Run("matched", func(b *testing.B) {
		RunKVDBBenchmark(b,
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				// Resolve the shared point and fixed tip before timing.
				// The original wrapper needs DB and chain dependencies.
				point := KVDBBenchmarkTarget(b, w, true).OutPoint
				client := &legacyBenchmarkChain{
					Chain: &bwmock.Chain{},
					tip:   w.addrStore.SyncedTo(),
				}
				w.cfg.DB = w.db
				w.chainClientLock.Lock()
				w.chainClient = client
				w.chainClientLock.Unlock()
				b.Cleanup(func() {
					// This tip has no workers; detach it before Loader
					// shutdown reaches unused chain mock methods.
					w.chainClientLock.Lock()
					w.chainClient = nil
					w.chainClientLock.Unlock()
				})

				// Include all existing ownership and lock lookups.
				return func() error {
					result, err := getUtxoDeprecated(w, point)

					// Retain the result without inspecting its contents.
					runtime.KeepAlive(result)

					return err
				}
			},
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				// Resolve request inputs before timing;
				// repeat only the native API operation.
				point := KVDBBenchmarkTarget(b, w, false).OutPoint
				ctx := b.Context()

				return func() error {
					_, err := w.GetUtxo(ctx, point)

					return err
				}
			},
		)
	})
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
			linearGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			exponentialGrowth,
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

	for i := 0; i <= maxGrowthIteration; i++ {
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

	// Use shared node data alongside the original growth matrix.
	b.Run("matched", func(b *testing.B) {
		RunKVDBBenchmark(b,
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				// Resolve request inputs before timing;
				// repeat only the native API operation.
				return func() error {
					_, err := w.ListUnspentDeprecated(
						workload.MinConfs, workload.MaxConfs, workload.Account,
					)

					return err
				}
			},
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				// Resolve request inputs before timing;
				// repeat only the native API operation.
				query := UtxoQuery{
					Account: workload.Account, MinConfs: workload.MinConfs,
					MaxConfs: workload.MaxConfs,
				}
				ctx := b.Context()

				return func() error {
					_, err := w.ListUnspent(ctx, query)

					return err
				}
			},
		)
	})
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

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
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

	for i := 0; i <= maxGrowthIteration; i++ {
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

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		addressGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
		)

		utxoGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
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

	for i := 0; i <= maxGrowthIteration; i++ {
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

		// maxGrowthIteration is the maximum iteration index for the
		// growth sequence.
		maxGrowthIteration = 14
	)

	var (
		accountGrowth = mapRange(
			startGrowthIteration, maxGrowthIteration,
			constantGrowth,
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

		addressGrowthPadding = decimalWidth(
			addressGrowth[len(addressGrowth)-1],
		)

		utxoGrowthPadding = decimalWidth(
			utxoGrowth[len(utxoGrowth)-1],
		)

		scopes = []waddrmgr.KeyScope{waddrmgr.KeyScopeBIP0084}

		duration = time.Hour
	)

	for i := 0; i <= maxGrowthIteration; i++ {
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

// BenchmarkGetUtxoDifferentAPI reads a different existing item on each call.
func BenchmarkGetUtxoDifferentAPI(b *testing.B) {
	b.Run("matched", func(b *testing.B) {
		RunKVDBBenchmark(b,
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				return benchmarkGetUtxoRequests(b, w, true, false)
			},
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				return benchmarkGetUtxoRequests(b, w, false, false)
			},
		)
	})
}

// BenchmarkGetUtxoNotFoundAPI reads a different missing item on each call.
func BenchmarkGetUtxoNotFoundAPI(b *testing.B) {
	b.Run("matched", func(b *testing.B) {
		RunKVDBBenchmark(b,
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				return benchmarkGetUtxoRequests(b, w, true, true)
			},
			func(b *testing.B, w *Wallet,
				workload bwtest.NodeBenchmarkWorkload) func() error {

				b.Helper()

				return benchmarkGetUtxoRequests(b, w, false, true)
			},
		)
	})
}

// benchmarkGetUtxoRequests prepares different inputs before timing.
// BenchmarkRead uses the first input for its separate untimed call.
func benchmarkGetUtxoRequests(b *testing.B, w *Wallet, legacy,
	missing bool) func() error {

	b.Helper()

	// Keep native enumeration outside measurement; canonical keys match SQL.
	// Reserve a different item for BenchmarkRead's untimed first call.
	count := bwtest.BenchmarkReadCount(b) + 1

	var targets []*Utxo
	if missing {
		targets = benchmarkMissingReadTargets(b, count)
	} else {
		targets = benchmarkPointReadTargets(b, w, legacy, count)
	}

	expected := ErrUnknownOutput
	if legacy {
		expected = ErrNotMine
	}

	if legacy && !missing {
		// The existing successful legacy workflow needs a DB and a fixed
		// chain tip. Missing transactions exit before those extra reads.
		w.cfg.DB = w.db
		client := &legacyBenchmarkChain{
			Chain: &bwmock.Chain{},
			tip:   w.addrStore.SyncedTo(),
		}
		w.chainClientLock.Lock()
		w.chainClient = client
		w.chainClientLock.Unlock()
		b.Cleanup(func() {
			// Detach this worker-free dependency before Loader cleanup.
			w.chainClientLock.Lock()
			w.chainClient = nil
			w.chainClientLock.Unlock()
		})
	}

	ctx := b.Context()
	// The first item is for warmup; measured calls read the rest once.
	index := 0

	// Resolve the native operation inside each call, without request data
	// generation, result validation or interaction-recording mocks.
	read := func() error {
		target := targets[index]
		index++

		var (
			result *Utxo
			err    error
		)
		if legacy {
			result, err = getUtxoDeprecated(w, target.OutPoint)
		} else {
			result, err = w.GetUtxo(ctx, target.OutPoint)
		}

		runtime.KeepAlive(result)

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
