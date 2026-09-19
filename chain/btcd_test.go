package chain

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// setupBtcd starts up a btcd node with cfilters enabled and returns a client
// wrapper of this connection.
func setupBtcd(t *testing.T) (*rpctest.Harness, *RPCClient) {
	t.Helper()

	miner := setupBtcdMiner(t)
	client := setupBtcdClient(t, miner)

	return miner, client
}

// setupBtcdMiner starts a cfilter-enabled btcd harness independently from its
// notification client so tests can establish chain history before subscribing.
func setupBtcdMiner(t *testing.T) *rpctest.Harness {
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

	return miner
}

// setupBtcdClient connects the production websocket adapter after any test
// history exists, preventing pre-subscription transactions from entering its
// notification stream.
func setupBtcdClient(t *testing.T, miner *rpctest.Harness) *RPCClient {
	t.Helper()

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

	return client
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

// TestRPCClientWatchAddrsFromTip verifies btcd against the shared live-tip
// registration contract.
func TestRPCClientWatchAddrsFromTip(t *testing.T) {
	t.Parallel()

	// Arrange: mine the historical payment before starting the production
	// websocket client, ensuring no pre-registration event remains in flight.
	miner := setupBtcdMiner(t)
	addr := mineHistoricalWatchAddr(t, miner)
	client := setupBtcdClient(t, miner)

	// Act: run the backend-neutral sequence against the established history,
	// repeat registration, and publish a distinct future payment.
	testWatchAddrsFromTipConformance(t, miner, client, addr)

	// Assert: the shared routine returns only after exactly one future payment
	// and a later block barrier exclude historical or duplicate delivery.
}

// mineHistoricalWatchAddr confirms a payment before a notification client is
// started, proving later registration does not initiate a backend history scan
// without relying on ordering between independent transport event streams.
func mineHistoricalWatchAddr(t *testing.T,
	miner *rpctest.Harness) address.Address {

	t.Helper()

	addr, err := miner.NewAddress()
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)
	historicalTx, err := miner.CreateTransaction(
		[]*wire.TxOut{{Value: 1000, PkScript: pkScript}}, 5, false,
	)
	require.NoError(t, err)
	_, err = miner.GenerateAndSubmitBlock(
		[]*btcutil.Tx{btcutil.NewTx(historicalTx)}, -1, time.Time{},
	)
	require.NoError(t, err)

	return addr
}

// testWatchAddrsFromTipConformance proves the public no-history, idempotence,
// and future-delivery contract through the production backend interface.
func testWatchAddrsFromTipConformance(t *testing.T, miner *rpctest.Harness,
	client Interface, addr address.Address) {

	t.Helper()

	// Arrange: enable block notifications and drain the connection marker. The
	// supplied address was paid before this client started, so any delivery of
	// that confirmed payment can only come from an unintended historical scan.
	err := client.NotifyBlocks()
	require.NoError(t, err)

	ntfns := client.Notifications()
	waitForClientConnected(t, ntfns)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// Act: register the same address twice, then create and publish a distinct
	// transaction whose first possible delivery is after both calls return.
	err = client.WatchAddrsFromTip(t.Context(), []address.Address{addr})
	require.NoError(t, err)
	err = client.WatchAddrsFromTip(t.Context(), []address.Address{addr})
	require.NoError(t, err)

	futureTx, err := miner.CreateTransaction(
		[]*wire.TxOut{{Value: 2000, PkScript: pkScript}}, 5, false,
	)
	require.NoError(t, err)
	_, err = client.SendRawTransaction(futureTx, true)
	require.NoError(t, err)

	// Assert: accept only the future transaction, then mine an empty block as a
	// post-delivery synchronization barrier. Any historical or duplicate
	// relevant transaction observed before that later block fails the contract.
	futureHash := futureTx.TxHash()
	waitForExclusiveRelevantTx(t, ntfns, &futureHash)

	barrierBlock, err := miner.GenerateAndSubmitBlock(nil, -1, time.Time{})
	require.NoError(t, err)
	waitForNoRelevantTxUntilBlock(t, ntfns, barrierBlock.Hash())
}

// TestRPCClientWatchAddrsFromTipCanceled verifies that cancellation is checked
// before the concrete btcd client is used or any registration can occur.
func TestRPCClientWatchAddrsFromTipCanceled(t *testing.T) {
	t.Parallel()

	// Arrange: create an intentionally uninitialized client and an already
	// canceled context. The test would panic if registration reached btcd.
	client := &RPCClient{}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Act: invoke the live-tip API with no addresses after cancellation.
	err := client.WatchAddrsFromTip(ctx, nil)

	// Assert: require the context error, proving cancellation was evaluated
	// before dereferencing or mutating the backend client.
	require.ErrorIs(t, err, context.Canceled)
}
