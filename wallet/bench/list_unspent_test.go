package bench

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
)

// BenchmarkListUnspent selects one native SQL backend on shared node
// data.
func BenchmarkListUnspent(b *testing.B) {
	RunSQLBenchmark(
		b,
		func(b *testing.B, w *wallet.Wallet,
			workload bwtest.NodeBenchmarkWorkload) func() error {

			b.Helper()

			// Resolve request inputs before timing;
			// repeat only the native API operation.
			query := wallet.UtxoQuery{
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
}
