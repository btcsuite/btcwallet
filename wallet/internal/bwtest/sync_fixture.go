package bwtest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

// Closed fixtures stay private on the shared volume; base mining matures
// the first coinbase before the first modeled deposit is broadcast.
const (
	syncBenchmarkDirectoryMode = 0o700
)

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
