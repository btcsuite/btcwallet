package bench

import (
	"testing"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
)

// BenchmarkListAddresses selects one native SQL backend on shared node
// data.
func BenchmarkListAddresses(b *testing.B) {
	RunSQLBenchmark(
		b,
		func(b *testing.B, w *wallet.Wallet,
			workload bwtest.NodeBenchmarkWorkload) func() error {

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
