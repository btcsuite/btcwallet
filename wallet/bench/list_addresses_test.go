package bench

import (
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
)

// BenchmarkListAddressesSQLite selects one native SQL backend on shared node
// data.
func BenchmarkListAddressesSQLite(b *testing.B) {
	benchmarkListAddresses(b, wallet.DBBackendSQLite)
}

// BenchmarkListAddressesPostgres selects one native SQL backend on shared
// node data.
func BenchmarkListAddressesPostgres(b *testing.B) {
	benchmarkListAddresses(b, wallet.DBBackendPostgres)
}

// benchmarkListAddresses prepares a fixed request before the shared read
// boundary.
func benchmarkListAddresses(b *testing.B, backend wallet.DBBackend) {
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
				_, err := w.ListAddresses(
					ctx, "default", waddrmgr.TaprootPubKey,
				)

				return err
			}
		},
	)
}
