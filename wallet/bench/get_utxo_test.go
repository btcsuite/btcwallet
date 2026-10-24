package bench

import (
	"errors"
	"runtime"
	"testing"

	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
)

// BenchmarkGetUtxo selects one native SQL backend on shared node data.
func BenchmarkGetUtxo(b *testing.B) {
	RunSQLBenchmark(
		b,
		func(b *testing.B, w *wallet.Wallet,
			workload bwtest.NodeBenchmarkWorkload) func() error {

			b.Helper()

			// Resolve request inputs before timing;
			// repeat only the native API operation.
			point := SQLBenchmarkTarget(b, w).OutPoint
			ctx := b.Context()

			return func() error {
				_, err := w.GetUtxo(ctx, point)

				return err
			}
		},
	)
}

// BenchmarkGetUtxoDifferent reads a different existing item on each call.
func BenchmarkGetUtxoDifferent(b *testing.B) {
	benchmarkGetUtxoRequests(b, false)
}

// BenchmarkGetUtxoNotFound reads a different missing item on each call.
func BenchmarkGetUtxoNotFound(b *testing.B) {
	benchmarkGetUtxoRequests(b, true)
}

// benchmarkGetUtxoRequests prepares different inputs before timing.
// BenchmarkRead uses the first input for its separate untimed call.
func benchmarkGetUtxoRequests(b *testing.B,
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
				result, err := w.GetUtxo(ctx, target.OutPoint)
				runtime.KeepAlive(result)

				if !missing {
					return err
				}

				// Only the native not-found response completes a miss;
				// a successful read or any other error invalidates it.
				if errors.Is(err, wallet.ErrUnknownOutput) {
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
