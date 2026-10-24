package bench

import (
	"runtime"
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
)

// BenchmarkGetAccountSQLite selects one native SQL backend on shared node data.
func BenchmarkGetAccountSQLite(b *testing.B) {
	benchmarkGetAccount(b, wallet.DBBackendSQLite)
}

// BenchmarkGetAccountPostgres selects one native SQL backend on shared node
// data.
func BenchmarkGetAccountPostgres(b *testing.B) {
	benchmarkGetAccount(b, wallet.DBBackendPostgres)
}

// benchmarkGetAccount prepares a fixed request before the shared read boundary.
func benchmarkGetAccount(b *testing.B, backend wallet.DBBackend) {
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
