package bench

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
)

// BenchmarkListUnspentSQLite selects one native SQL backend on shared node
// data.
func BenchmarkListUnspentSQLite(b *testing.B) {
	benchmarkListUnspent(b, wallet.DBBackendSQLite)
}

// BenchmarkListUnspentPostgres selects one native SQL backend on shared node
// data.
func BenchmarkListUnspentPostgres(b *testing.B) {
	benchmarkListUnspent(b, wallet.DBBackendPostgres)
}

// benchmarkListUnspent prepares a fixed request before the shared read
// boundary.
func benchmarkListUnspent(b *testing.B, backend wallet.DBBackend) {
	b.Helper()

	RunSQLBenchmark(
		b, backend,
		func(b *testing.B, w *wallet.Wallet,
			workload bwtest.ListUnspentWorkload) func() error {

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
