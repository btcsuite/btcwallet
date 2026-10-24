package bench

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
)

// BenchmarkGetUtxoSQLite selects one native SQL backend on shared node data.
func BenchmarkGetUtxoSQLite(b *testing.B) {
	benchmarkGetUtxo(b, wallet.DBBackendSQLite)
}

// BenchmarkGetUtxoPostgres selects one native SQL backend on shared node data.
func BenchmarkGetUtxoPostgres(b *testing.B) {
	benchmarkGetUtxo(b, wallet.DBBackendPostgres)
}

// benchmarkGetUtxo prepares a fixed request before the shared read boundary.
func benchmarkGetUtxo(b *testing.B, backend wallet.DBBackend) {
	b.Helper()

	RunSQLBenchmark(
		b, backend,
		func(b *testing.B, w *wallet.Wallet,
			workload bwtest.ListUnspentWorkload) func() error {

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
