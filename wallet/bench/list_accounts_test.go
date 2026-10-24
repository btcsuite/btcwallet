package bench

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
)

// BenchmarkListAccountsSQLite selects one native SQL backend on shared node
// data.
func BenchmarkListAccountsSQLite(b *testing.B) {
	benchmarkListAccounts(b, wallet.DBBackendSQLite)
}

// BenchmarkListAccountsPostgres selects one native SQL backend on shared
// node data.
func BenchmarkListAccountsPostgres(b *testing.B) {
	benchmarkListAccounts(b, wallet.DBBackendPostgres)
}

// benchmarkListAccounts prepares a fixed request before the shared read
// boundary.
func benchmarkListAccounts(b *testing.B, backend wallet.DBBackend) {
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
				_, err := w.ListAccounts(ctx)

				return err
			}
		},
	)
}
