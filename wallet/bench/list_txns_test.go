package bench

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
)

// BenchmarkListTxnsSQLite selects one native SQL backend on shared node data.
func BenchmarkListTxnsSQLite(b *testing.B) {
	benchmarkListTxns(b, wallet.DBBackendSQLite)
}

// BenchmarkListTxnsPostgres selects one native SQL backend on shared node data.
func BenchmarkListTxnsPostgres(b *testing.B) {
	benchmarkListTxns(b, wallet.DBBackendPostgres)
}

// benchmarkListTxns prepares a fixed request before the shared read boundary.
func benchmarkListTxns(b *testing.B, backend wallet.DBBackend) {
	b.Helper()

	RunSQLBenchmark(
		b, backend,
		func(b *testing.B, w *wallet.Wallet,
			workload bwtest.ListUnspentWorkload) func() error {

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
