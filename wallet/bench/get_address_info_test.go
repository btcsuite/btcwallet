package bench

import (
	"errors"
	"math"
	"runtime"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
	"github.com/stretchr/testify/require"
)

// BenchmarkGetAddressInfo selects one native SQL backend on shared
// node data.
func BenchmarkGetAddressInfo(b *testing.B) {
	RunSQLBenchmark(
		b,
		func(b *testing.B, w *wallet.Wallet,
			workload bwtest.NodeBenchmarkWorkload) func() error {

			b.Helper()

			// Resolve request inputs before timing;
			// repeat only the native API operation.
			addr := SQLBenchmarkTarget(b, w).Address
			ctx := b.Context()

			return func() error {
				_, err := w.GetAddressInfo(ctx, addr)

				return err
			}
		},
	)
}

// BenchmarkGetAddressInfoDifferent reads a different existing item
// on each call.
func BenchmarkGetAddressInfoDifferent(b *testing.B) {
	benchmarkGetAddressInfoRequests(b, false)
}

// BenchmarkGetAddressInfoNotFound reads a different missing item on each call.
func BenchmarkGetAddressInfoNotFound(b *testing.B) {
	benchmarkGetAddressInfoRequests(b, true)
}

// benchmarkGetAddressInfoRequests prepares different inputs before timing.
// BenchmarkRead uses the first input for its separate untimed call.
func benchmarkGetAddressInfoRequests(b *testing.B,
	missing bool) {

	b.Helper()

	RunSQLBenchmark(b,
		func(b *testing.B, w *wallet.Wallet,
			workload bwtest.NodeBenchmarkWorkload) func() error {

			b.Helper()

			// Native enumeration stays outside timing and uses canonical
			// cooperative returns for the same shape on each backend.
			// Reserve a different item for BenchmarkRead's untimed first call.
			count := bwtest.BenchmarkReadCount(b) + 1

			var targets []*wallet.Utxo
			if missing {
				targets = benchmarkMissingReadTargets(b, count)
			} else {
				targets = benchmarkPointReadTargets(b, w, count)
			}

			ctx := b.Context()
			// The first item is for warmup; measured calls read the rest once.
			index := 0

			// Select one prepared key per call; request generation and
			// result inspection do not enter the measured operation.
			read := func() error {
				target := targets[index]
				index++
				result, err := w.GetAddressInfo(ctx, target.Address)
				runtime.KeepAlive(result)

				if !missing {
					return err
				}

				// Only the native not-found response completes a miss;
				// a successful read or any other error invalidates it.
				if errors.Is(err, wallet.ErrAddressNotFound) {
					return nil
				}

				return errors.Join(
					errors.New("expected not-found response"), err,
				)
			}

			return read
		},
	)
}

// benchmarkPointReadTargets prepares different cooperative returns.
// Shared selection keeps their order equal across the native backends.
func benchmarkPointReadTargets(tb testing.TB, w *wallet.Wallet,
	count int) []*wallet.Utxo {

	tb.Helper()

	utxos, err := w.ListUnspent(tb.Context(), wallet.UtxoQuery{
		MaxConfs: math.MaxInt32,
	})
	require.NoError(tb, err)

	// Native fields supply requests; shared policy selects the same pool
	// for every backend before its benchmark timer starts.
	return bwtest.SelectNodeBenchmarkTargets(
		tb, utxos, count,
		func(utxo *wallet.Utxo) (btcutil.Amount, string, uint32) {
			return utxo.Amount, utxo.OutPoint.Hash.String(),
				utxo.OutPoint.Index
		},
	)
}

// benchmarkMissingReadTargets prepares valid identifiers from a domain outside
// the saved Wallet model. All suites use this sequence without inserting rows.
func benchmarkMissingReadTargets(tb testing.TB, count int) []*wallet.Utxo {
	tb.Helper()

	// The shared generator owns keys and order; this adapter retains the
	// native request shape used by the three point APIs in this suite.
	return bwtest.NodeBenchmarkMissingReadTargets(
		tb, count,
		func(point wire.OutPoint, addr address.Address) *wallet.Utxo {
			return &wallet.Utxo{
				OutPoint: point,
				Address:  addr,
			}
		},
	)
}
