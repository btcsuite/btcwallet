package bench

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
)

// BenchmarkGetTxSQLite selects one native SQL backend on shared node data.
func BenchmarkGetTxSQLite(b *testing.B) {
	benchmarkGetTx(b, wallet.DBBackendSQLite)
}

// BenchmarkGetTxPostgres selects one native SQL backend on shared node data.
func BenchmarkGetTxPostgres(b *testing.B) {
	benchmarkGetTx(b, wallet.DBBackendPostgres)
}

// benchmarkGetTx prepares a fixed request before the shared read boundary.
func benchmarkGetTx(b *testing.B, backend wallet.DBBackend) {
	b.Helper()

	RunSQLBenchmark(
		b, backend,
		func(b *testing.B, w *wallet.Wallet,
			workload bwtest.ListUnspentWorkload) func() error {

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
