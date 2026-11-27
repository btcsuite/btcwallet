package bwtest

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

// Closed fixtures stay private on the shared volume; base mining matures
// the first coinbase before the first modeled deposit is broadcast.
const (
	syncBenchmarkDirectoryMode  = 0o700
	syncBenchmarkMaturityBlocks = 103
)

// PrepareSyncBenchmarkBase saves one maturity/fan-out base for all cases.
// Returned target paths use the chain case ID independently of Wallet inputs.
func PrepareSyncBenchmarkBase(ctx context.Context, tb testing.TB,
	scenario SyncBenchmarkCase) (string, string) {

	tb.Helper()

	root := os.Getenv("BTCWALLET_BENCH_SYNC_FIXTURE_DIR")
	require.NotEmpty(tb, root, "use the shared Docker benchmark runner")
	base := filepath.Join(root, "chain", "base")
	target := filepath.Join(root, "chain", scenario.ID, "target")

	_, err := os.Stat(base)
	if !errors.Is(err, os.ErrNotExist) {
		require.NoError(tb, err)
		return base, target
	}

	// The fixed miner key owns all coinbases; model deposits can later spend
	// distinct mature ancestors without a daemon wallet or synthetic funding.
	started := time.Now()
	dir, err := syncBenchmarkScratch()
	require.NoError(tb, err)
	tb.Cleanup(func() { require.NoError(tb, os.RemoveAll(dir)) })
	_, rpc, stop := StartSyncBenchmarkNode(ctx, tb, dir)
	addr, key, err := syncBenchmarkMinerAddress()
	require.NoError(tb, err)
	key.Zero()

	_, err = rpc.GenerateToAddress(syncBenchmarkMaturityBlocks, addr, nil)
	require.NoError(tb, err)

	// Three mature coinbases fund every lane through 1,000 history blocks;
	// coinbase one stays independent for the lnd-shaped Wallet deposit.
	const (
		firstFundingHeight int64 = 2
		lastFundingHeight  int64 = 4
	)

	var funding []*wire.MsgTx
	for height := firstFundingHeight; height <= lastFundingHeight; height++ {
		hash, err := rpc.GetBlockHash(height)
		require.NoError(tb, err)
		block, err := rpc.GetBlock(hash)
		require.NoError(tb, err)

		funding = append(funding, block.Transactions[0])
	}

	fanout, err := BuildSyncBenchmarkFunding(
		funding, syncBenchmarkBackgroundLanes,
	)
	require.NoError(tb, err)

	var raw bytes.Buffer
	require.NoError(tb, fanout.Serialize(&raw))

	addressJSON, err := json.Marshal(addr.EncodeAddress())
	require.NoError(tb, err)
	transactionsJSON, err := json.Marshal([]string{
		hex.EncodeToString(raw.Bytes()),
	})
	require.NoError(tb, err)
	result, err := rpc.RawRequest("generateblock", []json.RawMessage{
		addressJSON, transactionsJSON,
	})
	require.NoError(tb, err)
	stop()
	saveSyncBenchmarkDirectory(tb, dir, base)
	tb.Logf("chain base preparation: %s; lanes=%d result=%s",
		time.Since(started), syncBenchmarkBackgroundLanes, result)

	return base, target
}

// SaveSyncBenchmarkTarget mines the already signed model only after its Wallet
// has stopped. Publish this target before saving the still-closed native DB.
func SaveSyncBenchmarkTarget(ctx context.Context, tb testing.TB, dir,
	target string, rpc *rpcclient.Client, stop func(),
	scenario SyncBenchmarkCase, history []*wire.MsgTx) {

	tb.Helper()

	started := time.Now()
	addr, key, err := syncBenchmarkMinerAddress()
	require.NoError(tb, err)
	key.Zero()

	addressJSON, err := json.Marshal(addr.EncodeAddress())
	require.NoError(tb, err)

	var previous []*wire.MsgTx
	if scenario.BackgroundTransactions != 0 {
		// The common base ends with exactly the miner fan-out. Later blocks
		// consume only its rolling change, never a retained full-chain graph.
		hash, err := rpc.GetBestBlockHash()
		require.NoError(tb, err)
		block, err := rpc.GetBlock(hash)
		require.NoError(tb, err)

		previous = block.Transactions[1:]
	}

	next := 0

	background := 0
	for height := int32(1); height <= scenario.Blocks; height++ {
		require.NoError(tb, ctx.Err())

		var transactions []*wire.MsgTx
		if scenario.BackgroundTransactions != 0 {
			previous, err = BuildSyncBenchmarkBackground(ctx, previous)
			require.NoError(tb, err)

			// Keep only the selected lanes from the common fan-out;
			// subsequent blocks roll their change without extra traffic.
			previous = previous[:scenario.BackgroundTransactions]
			transactions = append(transactions, previous...)
		}

		// Append same-block ancestors before descendants in the shared
		// graph's original order. Empty controls have no Wallet history.
		for next < len(history) && scenario.HistoryBlocks[next] == height {
			transactions = append(transactions, history[next])
			next++
		}

		// An allocated empty slice encodes as [], which generateblock
		// requires for coinbase-only blocks. Mining stays outside timing.
		raw := make([]string, 0, len(transactions))
		for _, tx := range transactions {
			var serialized bytes.Buffer
			require.NoError(tb, tx.Serialize(&serialized))
			raw = append(raw, hex.EncodeToString(serialized.Bytes()))
		}

		transactionsJSON, err := json.Marshal(raw)
		require.NoError(tb, err)
		_, err = rpc.RawRequest("generateblock", []json.RawMessage{
			addressJSON, transactionsJSON,
		})
		require.NoError(tb, err)

		background += len(previous)
	}

	tip, err := rpc.GetBlockChainInfo()
	require.NoError(tb, err)
	stop()
	saveSyncBenchmarkDirectory(tb, dir, target)
	// One summary survives Go's ten-line successful benchmark log limit.
	// Per-block identities remain in the closed target for separate inspection.
	tb.Logf("chain target preparation: %s; tip=%d:%s "+
		"blocks=%d background=%d graph=%d", time.Since(started),
		tip.Blocks, tip.BestBlockHash, scenario.Blocks, background, next)
}

// RestoreSyncBenchmarkNode opens a private copy. Scratch cleanup is registered
// before daemon cleanup, so the node releases every writer before removal.
func RestoreSyncBenchmarkNode(ctx context.Context, tb testing.TB,
	fixture string) (string, *testcontainers.DockerContainer,
	*rpcclient.Client, func()) {

	tb.Helper()

	started := time.Now()
	dir, err := syncBenchmarkScratch()
	require.NoError(tb, err)
	tb.Cleanup(func() { require.NoError(tb, os.RemoveAll(dir)) })
	require.NoError(tb, os.CopyFS(dir, os.DirFS(fixture)))
	tb.Logf("chain fixture restoration: %s", time.Since(started))
	node, rpc, stop := StartSyncBenchmarkNode(ctx, tb, dir)

	return dir, node, rpc, stop
}

// syncBenchmarkScratch keeps both containers on the same filesystem while
// assigning each invocation its own disposable database directory.
func syncBenchmarkScratch() (string, error) {
	root := filepath.Join(
		os.Getenv("BTCWALLET_BENCH_SYNC_FIXTURE_DIR"), "scratch",
	)

	err := os.MkdirAll(root, syncBenchmarkDirectoryMode)
	if err != nil {
		return "", fmt.Errorf("create shared scratch root: %w", err)
	}

	dir, err := os.MkdirTemp(root, "node-")
	if err != nil {
		return "", fmt.Errorf("create shared scratch directory: %w", err)
	}

	return dir, nil
}

// saveSyncBenchmarkDirectory publishes only complete stopped copies. Failed
// copies are removed like the read suite's existing partial-file snapshots.
func saveSyncBenchmarkDirectory(tb testing.TB, source, target string) {
	tb.Helper()

	pending, err := syncBenchmarkScratch()

	require.NoError(tb, err)
	defer func() { require.NoError(tb, os.RemoveAll(pending)) }()

	require.NoError(tb, os.CopyFS(pending, os.DirFS(source)))
	require.NoError(
		tb, os.MkdirAll(filepath.Dir(target), syncBenchmarkDirectoryMode),
	)
	require.NoError(tb, os.Rename(pending, target))
}
