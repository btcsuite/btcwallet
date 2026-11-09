package bwtest

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/rpcclient"
	bwwait "github.com/btcsuite/btcwallet/bwtest/wait"
	"github.com/btcsuite/btcwallet/chain"
	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// syncBenchmarkCoreImage fixes daemon behavior across all native consumers.
const syncBenchmarkCoreImage = "lightninglabs/bitcoin-core:30@sha256:" +
	"844f2a308e243ce3aa3df7918bd2fe230259419280f7826a62b896510ad3dcbd"

// syncBenchmarkRPCAuth shares a test credential between daemon and clients.
const syncBenchmarkRPCAuth = "weks"

// Daemon binds, exposed ports and client lookups share one protocol definition.
const (
	syncBenchmarkRPCPort   = "18443"
	syncBenchmarkBlockPort = "28332"
	syncBenchmarkTxPort    = "28333"
)

// Native daemon resources and notification cadence match every implementation.
const (
	syncBenchmarkMemory          = 12 << 30
	syncBenchmarkZMQDeadline     = 5 * time.Second
	syncBenchmarkMempoolInterval = 100 * time.Millisecond
)

// StartSyncBenchmarkNode opens a private directory on the runner's fixture
// volume. The fixed future regtest clock keeps saved tips current across runs;
// Wallet timing uses the real Go clock. Stop before copying the directory.
func StartSyncBenchmarkNode(ctx context.Context, tb testing.TB, dir string) (
	*testcontainers.DockerContainer, *rpcclient.Client, func()) {

	tb.Helper()

	volume := os.Getenv("BTCWALLET_BENCH_FIXTURE_VOLUME")
	root := os.Getenv("BTCWALLET_BENCH_FIXTURE_ROOT")

	require.NotEmpty(tb, volume, "use the shared Docker benchmark runner")
	require.NotEmpty(tb, root, "runner fixture mount root is required")

	// Both containers see this directory through the same named volume.
	// No daemon binary, image build or second host execution path is needed.
	node, err := testcontainers.Run(
		ctx, syncBenchmarkCoreImage,
		testcontainers.WithEntrypoint("bitcoind"),
		testcontainers.WithCmd(
			"-regtest", "-server", "-datadir="+dir, "-disablewallet",
			"-rpcbind=0.0.0.0", "-rpcallowip=0.0.0.0/0",
			"-rpcport="+syncBenchmarkRPCPort,
			"-rpcuser="+syncBenchmarkRPCAuth,
			"-rpcpassword="+syncBenchmarkRPCAuth,
			"-txindex", "-blockfilterindex=1", "-listen=0",
			"-mocktime=2100000000", "-printtoconsole=1",
			"-zmqpubrawblock=tcp://0.0.0.0:"+syncBenchmarkBlockPort,
			"-zmqpubrawtx=tcp://0.0.0.0:"+syncBenchmarkTxPort,
		),
		testcontainers.WithExposedPorts(
			syncBenchmarkRPCPort+"/tcp", syncBenchmarkBlockPort+"/tcp",
			syncBenchmarkTxPort+"/tcp",
		),
		testcontainers.WithMounts(
			testcontainers.VolumeMount(
				volume, testcontainers.ContainerMountTarget(root),
			),
		),
		testcontainers.WithHostConfigModifier(
			func(config *dockercontainer.HostConfig) {
				config.NanoCPUs = 1_000_000_000
				config.Memory = syncBenchmarkMemory
				config.MemorySwap = syncBenchmarkMemory
			},
		),
		testcontainers.WithWaitStrategy(
			wait.ForLog("Done loading").WithStartupTimeout(time.Minute),
		),
	)

	var rpc *rpcclient.Client

	stop := sync.OnceFunc(func() {
		cleanupCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx), time.Minute,
		)
		defer cancel()
		// Removal still runs when partial setup or graceful shutdown fails.
		defer func() { require.NoError(tb, node.Terminate(cleanupCtx)) }()

		if rpc != nil {
			StopSyncBenchmarkNode(cleanupCtx, tb, node, rpc)
		}
	})
	if node != nil {
		tb.Cleanup(stop)
	}

	require.NoError(tb, err)
	host, err := node.PortEndpoint(ctx, syncBenchmarkRPCPort+"/tcp", "")
	require.NoError(tb, err)
	rpc, err = rpcclient.New(&rpcclient.ConnConfig{
		Host: host, User: syncBenchmarkRPCAuth, Pass: syncBenchmarkRPCAuth,
		HTTPPostMode: true, DisableTLS: true,
	}, nil)
	require.NoError(tb, err)
	// Filter indexing can finish after RPC starts. Complete that readiness
	// work here, including the native legacy client's filter dependency.
	require.NoError(tb, bwwait.NoError(func() error {
		height, err := rpc.GetBlockCount()
		if err != nil || height == 0 {
			return err
		}

		hash, err := rpc.GetBlockHash(height)
		if err != nil {
			return err
		}

		_, err = rpc.GetBlockFilter(*hash, nil)

		return err
	}, time.Minute))

	return node, rpc, stop
}

// StopSyncBenchmarkNode waits for successful RPC shutdown before callers copy
// chainstate. Container termination alone could kill a live database writer.
func StopSyncBenchmarkNode(ctx context.Context, tb testing.TB,
	node *testcontainers.DockerContainer, rpc *rpcclient.Client) {

	tb.Helper()

	defer func() {
		rpc.Shutdown()
		rpc.WaitForShutdown()
	}()

	_, err := rpc.RawRequest("stop", nil)
	require.NoError(tb, err)
	require.NoError(
		tb, wait.ForExit().WithExitTimeout(time.Minute).
			WaitUntilReady(ctx, node),
	)
}

// NewSyncBenchmarkClient follows the legacy real RPC/ZMQ connection order.
// Each sample gets its own client; explicit stop joins it before the next one.
func NewSyncBenchmarkClient(ctx context.Context, tb testing.TB,
	node *testcontainers.DockerContainer) (chain.Interface, func()) {

	tb.Helper()

	host, err := node.PortEndpoint(ctx, syncBenchmarkRPCPort+"/tcp", "")
	require.NoError(tb, err)
	blocks, err := node.PortEndpoint(ctx, syncBenchmarkBlockPort+"/tcp", "tcp")
	require.NoError(tb, err)
	txs, err := node.PortEndpoint(ctx, syncBenchmarkTxPort+"/tcp", "tcp")
	require.NoError(tb, err)
	conn, err := chain.NewBitcoindConn(&chain.BitcoindConfig{
		ChainParams: &chaincfg.RegressionNetParams,
		Host:        host,
		User:        syncBenchmarkRPCAuth, Pass: syncBenchmarkRPCAuth,
		ZMQConfig: &chain.ZMQConfig{
			ZMQBlockHost: blocks, ZMQTxHost: txs,
			ZMQReadDeadline:        syncBenchmarkZMQDeadline,
			MempoolPollingInterval: syncBenchmarkMempoolInterval,
		},
	})
	require.NoError(tb, err)
	tb.Cleanup(conn.Stop)
	require.NoError(tb, conn.Start())
	client, err := conn.NewBitcoindClient()
	require.NoError(tb, err)

	stop := func() {
		client.Stop()
		client.WaitForShutdown()
		conn.Stop()
	}
	tb.Cleanup(stop)
	require.NoError(tb, client.Start(ctx))
	require.True(tb, client.IsCurrent(), "restored chain must be current")

	return client, stop
}
