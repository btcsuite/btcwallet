package bench

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
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
	benchmarkStartToSynced(b, wallet.SyncMethodFullBlocks)
}

// BenchmarkStartToSyncedCFilters forces compact filters on the same native SQL
// fixtures, making an unavailable filter source a failure rather than Auto.
func BenchmarkStartToSyncedCFilters(b *testing.B) {
	benchmarkStartToSynced(b, wallet.SyncMethodCFilters)
}

// benchmarkStartToSynced keeps both strategies on the existing closed restore
// and public readiness boundary; preparation remains independent of the mode.
func benchmarkStartToSynced(b *testing.B, method wallet.SyncMethod) {
	b.Helper()

	for _, scenario := range bwtest.SyncBenchmarkCases() {
		b.Run(scenario.ID, func(b *testing.B) {
			native, fixture, target := prepareSQLSyncBenchmarkWallet(
				b, scenario,
			)
			config := native.config
			config.SyncMethod = method
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

					// A public output census after time/profile capture lets
					// receipts verify equivalent discovery across native modes.
					utxos, err := wallets[0].ListUnspent(ctx, wallet.UtxoQuery{
						MinConfs: 0,
						MaxConfs: 999999,
					})
					require.NoError(b, err)
					b.Logf("startup outputs: %d", len(utxos))

					outputs := make([]string, 0, len(utxos))
					for _, utxo := range utxos {
						outputs = append(outputs, fmt.Sprintf(
							"%s=%d", utxo.OutPoint.String(), utxo.Amount,
						))
					}
					// Keep the complete census within Go's log-line limit.
					b.Logf("startup output set: %s", strings.Join(outputs, ","))
				}()
			}
		})
	}
}
