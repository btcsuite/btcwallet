package bench

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
	"github.com/stretchr/testify/require"
)

// BenchmarkStartToSynced restores closed build-selected SQL storage before
// each sample. Only Manager.Start through exact public readiness is timed,
// including observation, with native SQLite and PostgreSQL fixtures.
func BenchmarkStartToSynced(b *testing.B) {
	b.Helper()

	for _, scenario := range bwtest.SyncBenchmarkCases() {
		b.Run(scenario.ID, func(b *testing.B) {
			native, fixture, target := prepareSQLSyncBenchmarkWallet(
				b, scenario,
			)
			config := native.config
			_, node, rpc, _ := bwtest.RestoreSyncBenchmarkNode(
				b.Context(), b, target,
			)
			hash, err := rpc.GetBestBlockHash()
			require.NoError(b, err)
			header, err := rpc.GetBlockHeaderVerbose(hash)
			require.NoError(b, err)

			height := header.Height
			b.Logf("startup target: %d:%s", height, hash)

			if os.Getenv("BTCWALLET_BENCH_PROFILE") != "" {
				require.Equal(
					b, 1, b.N, "startup profiles require benchtime=1x",
				)
			}

			b.ReportAllocs()
			b.ResetTimer()
			b.StopTimer()

			for range b.N {
				// A per-sample scope drains all owners before the next restore;
				// it adds no priming call, worker or alternate lifecycle.
				func() {
					ctx, cancel := context.WithTimeout(
						b.Context(), 30*time.Minute,
					)
					defer cancel()

					started := time.Now()

					native.restore(b, fixture)
					b.Logf("fixture restoration: %s", time.Since(started))

					source, stopSource := bwtest.NewSyncBenchmarkClient(
						ctx, b, node,
					)
					defer stopSource()

					config.ChainSource = source
					manager, err := wallet.NewManager(ctx, config)

					require.NoError(b, err)
					defer func() { require.NoError(b, manager.Stop()) }()

					finishProfile := bwtest.StartBenchmarkProfile(b)
					defer finishProfile()

					b.StartTimer()

					wallets, err := manager.Start(ctx)
					require.NoError(b, err)

					for {
						info, err := wallets[0].Info(ctx)
						require.NoError(b, err)

						if info.Synced && info.SyncedTo.Height == height &&
							info.SyncedTo.Hash.IsEqual(hash) {

							break
						}

						require.NoError(b, ctx.Err())
						runtime.Gosched()
					}

					b.StopTimer()
					finishProfile()
				}()
			}
		})
	}
}
