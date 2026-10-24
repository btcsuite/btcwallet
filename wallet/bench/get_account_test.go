package bench

import (
	"errors"
	"runtime"
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
)

// BenchmarkGetAccount selects one native SQL backend on shared node data.
func BenchmarkGetAccount(b *testing.B) {
	RunSQLBenchmark(
		b,
		func(b *testing.B, w *wallet.Wallet,
			workload bwtest.NodeBenchmarkWorkload) func() error {

			b.Helper()

			// Resolve request inputs before timing;
			// repeat only the native API operation.
			ctx := b.Context()

			return func() error {
				result, err := w.GetAccount(
					ctx, waddrmgr.KeyScopeBIP0086,
					"default",
				)

				// Retain the complete result so the
				// call includes its construction.
				runtime.KeepAlive(result)

				return err
			}
		},
	)
}

// BenchmarkGetAccountDifferent reads a different existing item on each call.
func BenchmarkGetAccountDifferent(b *testing.B) {
	benchmarkGetAccountRequests(b, false)
}

// BenchmarkGetAccountNotFound reads a different missing item on each call.
func BenchmarkGetAccountNotFound(b *testing.B) {
	benchmarkGetAccountRequests(b, true)
}

// benchmarkGetAccountRequests prepares different inputs before timing.
// BenchmarkRead uses the first input for its separate untimed call.
func benchmarkGetAccountRequests(b *testing.B,
	missing bool) {

	b.Helper()

	RunSQLBenchmark(b,
		func(b *testing.B, w *wallet.Wallet,
			workload bwtest.NodeBenchmarkWorkload) func() error {

			b.Helper()

			// Prepare the shared account mix before timing; each suite keeps
			// its native lookup and not-found error handling.
			count := bwtest.BenchmarkReadCount(b) + 1
			scopes, names := bwtest.NodeBenchmarkAccountReadTargets(
				b, workload, count, missing,
			)

			ctx := b.Context()
			// The first item is for warmup; measured calls read the rest once.
			index := 0

			// Select one prepared key per call; request generation and
			// result inspection do not enter the measured operation.
			read := func() error {
				scope, name := scopes[index], names[index]
				index++
				result, err := w.GetAccount(ctx, scope, name)
				runtime.KeepAlive(result)

				if !missing {
					return err
				}

				// Only the native not-found response completes a miss;
				// a successful read or any other error invalidates it.
				if errors.Is(err, wallet.ErrAccountNotFound) {
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
