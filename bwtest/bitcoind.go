package bwtest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcwallet/bwtest/wait"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/chain/port"
	"github.com/stretchr/testify/require"
)

const (
	// bitcoindRPCUser/bitcoindRPCPass are test-only credentials used by the
	// chain client. They match the static rpcauth entry below.
	bitcoindRPCUser = "weks"
	bitcoindRPCPass = "weks"

	// bitcoindLogFilePerm protects daemon stdout/stderr logs written by the
	// harness.
	bitcoindLogFilePerm = 0o600

	// bitcoindZMQReadDeadline bounds how long we wait on each ZMQ read.
	bitcoindZMQReadDeadline = 5 * time.Second
	// bitcoindMempoolPollingInterval controls fallback mempool polling cadence.
	bitcoindMempoolPollingInterval = 100 * time.Millisecond
	// bitcoindMaxConnections keeps descriptor requirements low in CI.
	bitcoindMaxConnections = 16
	// bitcoindMaxMempoolMB reduces memory usage for short-lived test runs.
	bitcoindMaxMempoolMB = 50

	// bitcoindRPCAuthorization enables RPC access with user/pass without
	// storing cleartext credentials in the datadir.
	//
	// Generated with: bitcoind -rpcauth=weks:weks.
	bitcoindRPCAuthorization = "weks:469e9bb14ab2360f8e226efed5ca6f" +
		"d$507c670e800a95284294edb5773b05544b" +
		"220110063096c221be9933c82d38e1"
)

var (
	errBitcoindNotSynced = errors.New("bitcoind not synced")
)

// BitcoindBackend is a ChainBackend backed by a bitcoind process.
type BitcoindBackend struct {
	// binary is the resolved bitcoind executable path.
	binary string

	// cmd is the running bitcoind process.
	cmd *exec.Cmd

	// logDir is the bitcoind data directory used by this backend instance.
	logDir string

	// rpcPort is the HTTP-RPC port used by bitcoind.
	rpcPort int
	// p2pPort is the inbound/outbound p2p port used by bitcoind.
	p2pPort int

	// zmqBlockHost publishes raw block notifications for chain clients.
	zmqBlockHost string
	// zmqTxHost publishes raw transaction notifications for chain clients.
	zmqTxHost string

	// minerAddr is the shared miner peer address that bitcoind connects to.
	minerAddr string

	// stdoutPath/stderrPath are harness-managed daemon log files.
	stdoutPath string
	stderrPath string

	// stdoutFile/stderrFile stay open for the lifetime of the daemon process.
	stdoutFile *os.File
	stderrFile *os.File

	// cmdCancel cancels the process context to unblock shutdown paths.
	cmdCancel context.CancelFunc
}

// NewBitcoindBackend creates a new BitcoindBackend.
//
// The backend writes its stdout/stderr into the passed logDir and uses ZMQ for
// block and transaction notifications.
func NewBitcoindBackend(t *testing.T, logDir string) *BitcoindBackend {
	t.Helper()

	bitcoindBinary, err := GetBitcoindBinary()
	require.NoError(t, err, "unable to find bitcoind binary")

	absLogDir, err := filepath.Abs(logDir)
	require.NoError(t, err, "unable to get absolute bitcoind log dir")

	err = ensureLogDir(absLogDir)
	require.NoError(t, err, "unable to create bitcoind log dir")

	// Reserve ports in a stable order so diagnostics are easier to read when a
	// setup step fails and reports one of these endpoints.
	zmqBlockPort := port.NextAvailablePort()
	zmqTxPort := port.NextAvailablePort()
	rpcPort := port.NextAvailablePort()
	p2pPort := port.NextAvailablePort()

	zmqBlockHost := fmt.Sprintf("tcp://127.0.0.1:%d", zmqBlockPort)
	zmqTxHost := fmt.Sprintf("tcp://127.0.0.1:%d", zmqTxPort)

	return &BitcoindBackend{
		binary:       bitcoindBinary,
		logDir:       absLogDir,
		rpcPort:      rpcPort,
		p2pPort:      p2pPort,
		zmqBlockHost: zmqBlockHost,
		zmqTxHost:    zmqTxHost,
		stdoutPath:   filepath.Join(absLogDir, "bitcoind.stdout.log"),
		stderrPath:   filepath.Join(absLogDir, "bitcoind.stderr.log"),
	}
}

// Name returns the identifier of the backend.
func (b *BitcoindBackend) Name() string {
	return backendBitcoind
}

// Start launches the backend daemon.
func (b *BitcoindBackend) Start() error {
	// Startup sequence overview:
	//  1. Validate harness wiring (miner address + process limits).
	//  2. Build daemon arguments (regtest, rpc, zmq, resource limits).
	//  3. Redirect stdout/stderr to harness-managed log files.
	//  4. Start the daemon process and retain file handles.
	//  5. Probe RPC until the node is responsive and chain-synced.
	//
	// If any step fails we return an error that points to the collected logs so
	// CI failures can be diagnosed from artifacts.
	if b.minerAddr == "" {
		return fmt.Errorf("bitcoind: %w", errMissingMinerAddr)
	}

	// Best-effort attempt to increase the file descriptor limit before starting
	// bitcoind. This helps avoid startup failures on systems with a low default
	// RLIMIT_NOFILE.
	_ = raiseNoFileLimit()

	args := []string{
		// Core regtest + connectivity setup.
		"-datadir=" + b.logDir,
		"-regtest",
		"-connect=" + b.minerAddr,

		// Enable wallet-required indexing and RPC auth.
		"-txindex",
		"-disablewallet",
		"-rpcauth=" + bitcoindRPCAuthorization,
		fmt.Sprintf("-rpcport=%d", b.rpcPort),
		fmt.Sprintf("-port=%d", b.p2pPort),

		// Use ZMQ notifications (blocks + txs) for low-latency chain updates.
		"-zmqpubrawblock=" + b.zmqBlockHost,
		"-zmqpubrawtx=" + b.zmqTxHost,
		"-blockfilterindex=1",

		// Reduce resource usage for test environments.
		//
		// NOTE: bitcoind performs a file descriptor sanity check on startup.
		// Keeping the connection count low reduces the required number of file
		// descriptors.
		fmt.Sprintf("-maxconnections=%d", bitcoindMaxConnections),
		fmt.Sprintf("-maxmempool=%d", bitcoindMaxMempoolMB),
	}

	cmdCtx, cmdCancel := context.WithCancel(context.Background())
	b.cmdCancel = cmdCancel

	// #nosec G204 -- b.binary is looked up from PATH and args are controlled.
	cmd := exec.CommandContext(cmdCtx, b.binary, args...)

	// #nosec G304 -- b.stdoutPath is created by the test harness.
	stdout, err := os.OpenFile(
		b.stdoutPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, bitcoindLogFilePerm,
	)
	if err != nil {
		return fmt.Errorf("open bitcoind stdout log: %w", err)
	}

	// #nosec G304 -- b.stderrPath is created by the test harness.
	stderr, err := os.OpenFile(
		b.stderrPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, bitcoindLogFilePerm,
	)
	if err != nil {
		_ = stdout.Close()
		return fmt.Errorf("open bitcoind stderr log: %w", err)
	}

	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err = cmd.Start()
	if err != nil {
		_ = stdout.Close()
		_ = stderr.Close()

		return fmt.Errorf("start bitcoind: %w", err)
	}

	// Keep handles alive for the duration of the process.
	b.cmd = cmd
	b.stdoutFile = stdout
	b.stderrFile = stderr

	// Wait until bitcoind is ready to serve RPC calls.
	//
	// This readiness check also verifies that bitcoind has synced to the
	// pre-mined harness chain height.
	host := fmt.Sprintf("127.0.0.1:%d", b.rpcPort)
	clientCfg := &rpcclient.ConnConfig{
		Host:                 host,
		User:                 bitcoindRPCUser,
		Pass:                 bitcoindRPCPass,
		DisableAutoReconnect: false,
		DisableConnectOnNew:  true,
		DisableTLS:           true,
		HTTPPostMode:         true,
	}

	err = wait.NoError(func() error {
		// Construct a short-lived RPC client for readiness probing.
		client, err := rpcclient.New(clientCfg, nil)
		if err != nil {
			return fmt.Errorf("create bitcoind rpc client: %w", err)
		}

		defer func() {
			client.Shutdown()
			client.WaitForShutdown()
		}()

		_, err = client.GetBlockChainInfo()
		if err != nil {
			return fmt.Errorf("get blockchain info: %w", err)
		}

		count, err := client.GetBlockCount()
		if err != nil {
			return fmt.Errorf("get block count: %w", err)
		}

		if count < int64(minMatureBlocks) {
			return fmt.Errorf("%w (height=%d)", errBitcoindNotSynced,
				count)
		}

		return nil
	}, defaultTestTimeout)
	if err != nil {
		_ = b.Stop()

		const errFmt = "bitcoind not ready: %w; logs: %s %s"

		return fmt.Errorf(errFmt, err, b.stdoutPath, b.stderrPath)
	}

	return nil
}

// Stop shuts down the backend daemon.
func (b *BitcoindBackend) Stop() error {
	if b.cmdCancel != nil {
		b.cmdCancel()
		b.cmdCancel = nil
	}

	if b.cmd != nil && b.cmd.Process != nil {
		_ = b.cmd.Process.Kill()
		_ = b.cmd.Wait()
	}

	// Mark the process handle as stopped so repeated Stop calls are no-ops.
	b.cmd = nil

	if b.stdoutFile != nil {
		_ = b.stdoutFile.Close()
		b.stdoutFile = nil
	}

	if b.stderrFile != nil {
		_ = b.stderrFile.Close()
		b.stderrFile = nil
	}

	return nil
}

// ConnectMiner records the miner address for later use.
func (b *BitcoindBackend) ConnectMiner(minerAddr string) error {
	b.minerAddr = minerAddr

	return nil
}

// NewChainClient creates a new bitcoind-backed chain.Interface connected to
// this backend.
//
// For each subtest, we create a fresh BitcoindConn and client pair so test
// teardown can fully dispose chain resources without affecting other subtests.
// Startup order matters:
//  1. Construct BitcoindConn.
//  2. Start the connection so RPC + ZMQ subscriptions become active.
//  3. Construct and start the chain client that wallets will use.
//
// Cleanup runs in reverse order to avoid races between client shutdown and
// connection teardown.
func (b *BitcoindBackend) NewChainClient(ctx context.Context) (chain.Interface,
	func(), error) {

	// Create a fresh chain connection for each subtest.
	host := fmt.Sprintf("127.0.0.1:%d", b.rpcPort)
	cfg := &chain.BitcoindConfig{
		ChainParams:        harnessNetParams,
		Host:               host,
		User:               bitcoindRPCUser,
		Pass:               bitcoindRPCPass,
		Dialer:             nil,
		PrunedModeMaxPeers: 0,
		// ZMQ endpoints are passed in the same block/tx order used by the
		// daemon startup flags above.
		ZMQConfig: &chain.ZMQConfig{
			ZMQBlockHost:           b.zmqBlockHost,
			ZMQTxHost:              b.zmqTxHost,
			ZMQReadDeadline:        bitcoindZMQReadDeadline,
			MempoolPollingInterval: bitcoindMempoolPollingInterval,
		},
	}

	var (
		conn *chain.BitcoindConn
		err  error
	)

	err = wait.NoError(func() error {
		conn, err = chain.NewBitcoindConn(cfg)
		if err != nil {
			return fmt.Errorf("create bitcoind conn: %w", err)
		}

		return nil
	}, defaultTestTimeout)
	if err != nil {
		return nil, nil, fmt.Errorf("create bitcoind conn: %w", err)
	}

	err = conn.Start()
	if err != nil {
		return nil, nil, fmt.Errorf("start bitcoind conn: %w", err)
	}

	client, err := conn.NewBitcoindClient()
	if err != nil {
		conn.Stop()
		return nil, nil, fmt.Errorf("create bitcoind client: %w", err)
	}

	err = client.Start(ctx)
	if err != nil {
		conn.Stop()
		return nil, nil, fmt.Errorf("start bitcoind client: %w", err)
	}

	cleanup := func() {
		client.Stop()
		conn.Stop()
	}

	return client, cleanup, nil
}

// LogDir returns the directory where bitcoind wrote its logs for this run.
func (b *BitcoindBackend) LogDir() string {
	return b.logDir
}

var _ ChainBackend = (*BitcoindBackend)(nil)
