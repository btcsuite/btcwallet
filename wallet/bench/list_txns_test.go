package bench

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
)

// BenchmarkListTxns selects one native SQL backend on shared node data.
func BenchmarkListTxns(b *testing.B) {
	RunSQLBenchmark(
		b,
		func(b *testing.B, w *wallet.Wallet,
			workload bwtest.NodeBenchmarkWorkload) func() error {

			b.Helper()

			// Resolve request inputs before timing;
			// repeat only the native API operation.
			ctx := b.Context()

			return func() error {
				_, err := w.ListTxns(ctx, 0, -1)

				return err
			}
		},
	)
}
