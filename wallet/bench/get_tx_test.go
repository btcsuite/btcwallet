package bench

import (
	"errors"
	"runtime"
	"testing"

	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
)

// BenchmarkGetTx selects one native SQL backend on shared node data.
func BenchmarkGetTx(b *testing.B) {
	RunSQLBenchmark(
		b,
		func(b *testing.B, w *wallet.Wallet,
			workload bwtest.NodeBenchmarkWorkload) func() error {

			b.Helper()

			// Resolve request inputs before timing;
			// repeat only the native API operation.
			hash := SQLBenchmarkTarget(b, w).OutPoint.Hash
			ctx := b.Context()

			return func() error {
				_, err := w.GetTx(ctx, hash)

				return err
			}
		},
	)
}

// BenchmarkGetTxDifferent reads a different existing item on each call.
func BenchmarkGetTxDifferent(b *testing.B) {
	benchmarkGetTxRequests(b, false)
}

// BenchmarkGetTxNotFound reads a different missing item on each call.
func BenchmarkGetTxNotFound(b *testing.B) {
	benchmarkGetTxRequests(b, true)
}

// benchmarkGetTxRequests prepares different inputs before timing.
// BenchmarkRead uses the first input for its separate untimed call.
func benchmarkGetTxRequests(b *testing.B,
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
				result, err := w.GetTx(ctx, target.OutPoint.Hash)
				runtime.KeepAlive(result)

				if !missing {
					return err
				}

				// Only the native not-found response completes a miss;
				// a successful read or any other error invalidates it.
				if errors.Is(err, wallet.ErrTxNotFound) {
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
