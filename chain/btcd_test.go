package chain

import (
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// setupBtcd starts up a btcd node with cfilters enabled and returns a client
// wrapper of this connection.
func setupBtcd(t *testing.T) (*rpctest.Harness, *RPCClient) {
	t.Helper()

	trickle := fmt.Sprintf("--trickleinterval=%v", 10*time.Millisecond)
	args := []string{trickle}

	miner, err := rpctest.New(
		&chaincfg.RegressionNetParams, nil, args, "",
	)
	require.NoError(t, err)

	require.NoError(t, miner.SetUp(true, 1))

	t.Cleanup(func() {
		require.NoError(t, miner.TearDown())
	})

	rpcConf := miner.RPCConfig()
	client, err := NewRPCClientWithConfig(&RPCClientConfig{
		ReconnectAttempts: 1,
		Chain:             &chaincfg.RegressionNetParams,
		Conn: &rpcclient.ConnConfig{
			Host:                 rpcConf.Host,
			User:                 rpcConf.User,
			Pass:                 rpcConf.Pass,
			Certificates:         rpcConf.Certificates,
			DisableTLS:           false,
			DisableAutoReconnect: false,
			DisableConnectOnNew:  true,
			HTTPPostMode:         false,
			Endpoint:             "ws",
		},
	})
	require.NoError(t, err)

	err = client.Start(t.Context())
	require.NoError(t, err)

	t.Cleanup(func() {
		client.Stop()
	})

	return miner, client
}

// TestValidateConfig checks the `validate` method on the RPCClientConfig
// behaves as expected.
func TestValidateConfig(t *testing.T) {
	t.Parallel()

	rt := require.New(t)

	// ReconnectAttempts must be positive.
	cfg := &RPCClientConfig{
		ReconnectAttempts: -1,
	}
	rt.ErrorContains(cfg.validate(), "reconnectAttempts")

	// Must specify a chain params.
	cfg = &RPCClientConfig{
		ReconnectAttempts: 1,
	}
	rt.ErrorContains(cfg.validate(), "chain params")

	// Must specify a connection config.
	cfg = &RPCClientConfig{
		ReconnectAttempts: 1,
		Chain:             &chaincfg.Params{},
	}
	rt.ErrorContains(cfg.validate(), "conn config")

	// Must specify a certificate when using TLS.
	cfg = &RPCClientConfig{
		ReconnectAttempts: 1,
		Chain:             &chaincfg.Params{},
		Conn:              &rpcclient.ConnConfig{},
	}
	rt.ErrorContains(cfg.validate(), "certs")

	// Validate config.
	cfg = &RPCClientConfig{
		ReconnectAttempts: 1,
		Chain:             &chaincfg.Params{},
		Conn: &rpcclient.ConnConfig{
			DisableTLS: true,
		},
	}
	rt.NoError(cfg.validate())

	// When a nil config is provided, it should return an error.
	_, err := NewRPCClientWithConfig(nil)
	rt.ErrorContains(err, "missing rpc config")
}

// testInterfaceBatchMethods verifies the batch fetching methods implementation
// for a given chain.Interface client.
func testInterfaceBatchMethods(t *testing.T, miner *rpctest.Harness,
	client Interface) {

	t.Helper()

	require := require.New(t)

	// Generate blocks to have a chain to query.
	const numBlocks = 5

	_, err := miner.Client.Generate(numBlocks)
	require.NoError(err)

	// Test GetBlockHashes.
	// Query from height 1 to 3.
	startHeight := int64(1)
	endHeight := int64(3)
	hashes, err := client.GetBlockHashes(startHeight, endHeight)
	require.NoError(err, "GetBlockHashes failed")
	require.Len(hashes, 3)

	// Verify hashes match miner.
	for i, hash := range hashes {
		minerHash, err := miner.Client.GetBlockHash(int64(i) + 1)
		require.NoError(err)
		require.Equal(*minerHash, hash)
	}

	// Test GetBlocks.
	blocks, err := client.GetBlocks(hashes)
	require.NoError(err, "GetBlocks failed")
	require.Len(blocks, 3)

	for i, block := range blocks {
		require.Equal(hashes[i], block.BlockHash())
	}

	// Test GetBlockHeaders.
	headers, err := client.GetBlockHeaders(hashes)
	require.NoError(err, "GetBlockHeaders failed")
	require.Len(headers, 3)

	for i, header := range headers {
		require.Equal(hashes[i], header.BlockHash())
	}

	// Test GetCFilters.
	// Note: bitcoind needs -blockfilterindex=1 for this to work, which is
	// set in setupBitcoind.
	// We use Eventually because filter indexing is asynchronous.
	require.Eventually(func() bool {
		filters, err := client.GetCFilters(
			hashes, wire.GCSFilterRegular,
		)
		if err != nil {
			return false
		}

		if len(filters) != 3 {
			return false
		}
		// Verify filters are not empty/nil.
		for _, f := range filters {
			if f == nil || f.N() == 0 {
				return false
			}
		}

		return true
	}, defaultTestTimeout, 100*time.Millisecond,
		"GetCFilters failed or timed out")
}

// TestRPCClientBatchMethods verifies the RPCClient's batch fetching methods
// implementation against a live btcd node.
func TestRPCClientBatchMethods(t *testing.T) {
	t.Parallel()

	// Set up a miner (btcd node) and client.
	miner, client := setupBtcd(t)

	// Run batch method tests.
	testInterfaceBatchMethods(t, miner, client)
}
