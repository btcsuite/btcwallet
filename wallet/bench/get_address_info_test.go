package bench

import (
	"testing"

	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
)

// BenchmarkGetAddressInfoSQLite selects one native SQL backend on shared
// node data.
func BenchmarkGetAddressInfoSQLite(b *testing.B) {
	benchmarkGetAddressInfo(b, wallet.DBBackendSQLite)
}

// BenchmarkGetAddressInfoPostgres selects one native SQL backend on shared
// node data.
func BenchmarkGetAddressInfoPostgres(b *testing.B) {
	benchmarkGetAddressInfo(b, wallet.DBBackendPostgres)
}

// benchmarkGetAddressInfo prepares a fixed request before the shared read
// boundary.
func benchmarkGetAddressInfo(b *testing.B, backend wallet.DBBackend) {
	b.Helper()

	RunSQLBenchmark(
		b, backend,
		func(b *testing.B, w *wallet.Wallet,
			workload bwtest.ListUnspentWorkload) func() error {

			b.Helper()

			// Resolve request inputs before timing;
			// repeat only the native API operation.
			addr := SQLBenchmarkTarget(b, w).Address
			ctx := b.Context()

			return func() error {
				_, err := w.GetAddressInfo(ctx, addr)

				return err
			}
		},
	)
}
