package chain

import (
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2/gcs"
	"github.com/btcsuite/btcd/btcutil/v2/gcs/builder"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain/port"
	"github.com/stretchr/testify/require"
)

const (
	// defaultTestTimeout is the default timeout used for tests in this
	// file. It is set to 30 seconds to allow for slow test environments.
	defaultTestTimeout = 30 * time.Second
)

// TestBitcoindEventsZMQ runs all bitcoind event tests using ZMQ subscriptions.
//
// We cannot run these tests in parallel as it involves running multiple
// bitcoind servers and btcd servers in the background. While running multiple
// bitcoind servers is fine, the current integration test setup in `btcd`
// doesn't allow it as the created RPC client will share the same ports.
//
//nolint:paralleltest
func TestBitcoindEventsZMQ(t *testing.T) {
	runBitcoindEventsTests(t, false)
}

// TestBitcoindEventsRPC runs all bitcoind event tests using RPC polling.
//
// We cannot run these tests in parallel as it involves running multiple
// bitcoind servers and btcd servers in the background. While running multiple
// bitcoind servers is fine, the current integration test setup in `btcd`
// doesn't allow it as the created RPC client will share the same ports.
//
//nolint:paralleltest
func TestBitcoindEventsRPC(t *testing.T) {
	runBitcoindEventsTests(t, true)
}

// runBitcoindEventsTests runs the suite of bitcoind event tests with the
// specified polling mode.
func runBitcoindEventsTests(t *testing.T, rpcPolling bool) {
	t.Helper()

	tests := []struct {
		name   string
		testFn func(*testing.T, *rpctest.Harness, *BitcoindClient)
	}{
		{
			name:   "Reorg",
			testFn: testReorg,
		},
		{
			name:   "NotifyBlocks",
			testFn: testNotifyBlocks,
		},
		{
			name:   "NotifyTx",
			testFn: testNotifyTx,
		},
		{
			name:   "NotifySpentMempool",
			testFn: testNotifySpentMempool,
		},
		{
			name:   "LookupInputMempoolSpend",
			testFn: testLookupInputMempoolSpend,
		},
		{
			name:   "GetCFilter",
			testFn: testBitcoindClientGetCFilter,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Initialize a fresh miner for the test case.
			miner1 := setupMiner(t)
			addr := miner1.P2PAddress()

			// Initialize a fresh bitcoind client for EVERY test
			// case.
			btcClient := setupBitcoind(t, addr, rpcPolling)

			test.testFn(t, miner1, btcClient)
		})
	}
}

// testNotifyTx tests that the correct notifications are received for the
// subscribed tx.
func testNotifyTx(t *testing.T, miner *rpctest.Harness, client *BitcoindClient) {
	require := require.New(t)

	script, _, err := randPubKeyHashScript()
	require.NoError(err)

	tx, err := miner.CreateTransaction(
		[]*wire.TxOut{{Value: 1000, PkScript: script}}, 5, false,
	)
	require.NoError(err)

	hash := tx.TxHash()

	err = client.NotifyTx([]chainhash.Hash{hash})
	require.NoError(err)

	// Send the transaction. This might fail if the bitcoind node hasn't
	// synced the inputs yet, so we'll retry until it succeeds.
	require.Eventually(func() bool {
		_, err = client.SendRawTransaction(tx, true)
		return err == nil
	}, defaultTestTimeout, 100*time.Millisecond,
		"SendRawTransaction failed")

	ntfns := client.Notifications()

	// We expect to get a ClientConnected notification.
	waitForClientConnected(t, ntfns)

	// We expect to get a RelevantTx notification.
	waitForRelevantTx(t, ntfns, &hash)
}

// testNotifyBlocks tests that the correct notifications are received for
// blocks in the simple non-reorg case.
func testNotifyBlocks(t *testing.T, miner *rpctest.Harness,
	client *BitcoindClient) {

	require := require.New(t)

	require.NoError(client.NotifyBlocks())
	ntfns := client.Notifications()

	// Send an event to the ntfns after the tx event has been received.
	// Otherwise the orders of the events might get messed up if we send
	// events shortly.
	miner.Client.Generate(1)

	// We expect to get a ClientConnected notification.
	waitForClientConnected(t, ntfns)

	// We expect to get a FilteredBlockConnected notification.
	select {
	case ntfn := <-ntfns:
		_, ok := ntfn.(FilteredBlockConnected)
		require.Truef(ok, "Expected type FilteredBlockConnected, "+
			"got %T", ntfn)

	case <-time.After(defaultTestTimeout):
		require.Fail("timed out for FilteredBlockConnected " +
			"notification")
	}

	// We expect to get a BlockConnected notification.
	select {
	case ntfn := <-ntfns:
		_, ok := ntfn.(BlockConnected)
		require.Truef(ok, "Expected type BlockConnected, got %T", ntfn)

	case <-time.After(defaultTestTimeout):
		require.Fail("timed out for BlockConnected notification")
	}
}

// testNotifySpentMempool tests that the client correctly notifies the caller
// when the requested input has already been spent in mempool.
func testNotifySpentMempool(t *testing.T, miner *rpctest.Harness,
	client *BitcoindClient) {

	require := require.New(t)

	script, _, err := randPubKeyHashScript()
	require.NoError(err)

	// Create a test tx.
	tx, err := miner.CreateTransaction(
		[]*wire.TxOut{{Value: 1000, PkScript: script}}, 5, false,
	)
	require.NoError(err)
	txid := tx.TxHash()

	// Send the tx which will put it in the mempool.
	_, err = client.SendRawTransaction(tx, true)
	require.NoError(err)

	// Subscribe the input of the above tx.
	op := tx.TxIn[0].PreviousOutPoint
	err = client.NotifySpent([]*wire.OutPoint{&op})
	require.NoError(err)

	ntfns := client.Notifications()

	// We expect to get a ClientConnected notification.
	waitForClientConnected(t, ntfns)

	// We expect to get a RelevantTx notification.
	waitForRelevantTx(t, ntfns, &txid)
}

// testLookupInputMempoolSpend tests that LookupInputMempoolSpend returns the
// correct tx hash and whether the input has been spent in the mempool.
func testLookupInputMempoolSpend(t *testing.T, miner *rpctest.Harness,
	client *BitcoindClient) {

	rt := require.New(t)

	script, _, err := randPubKeyHashScript()
	rt.NoError(err)

	// Create a test tx.
	tx, err := miner.CreateTransaction(
		[]*wire.TxOut{{Value: 1000, PkScript: script}}, 5, false,
	)
	rt.NoError(err)

	// Lookup the input in mempool.
	op := tx.TxIn[0].PreviousOutPoint
	txid, found := client.LookupInputMempoolSpend(op)

	// Expect that the input has not been spent in the mempool.
	rt.False(found)
	rt.Zero(txid)

	// Send the tx which will put it in the mempool.
	_, err = client.SendRawTransaction(tx, true)
	rt.NoError(err)

	// Lookup the input again should return the spending tx.
	//
	// NOTE: We need to wait for the tx to propagate to the mempool.
	rt.Eventually(func() bool {
		txid, found = client.LookupInputMempoolSpend(op)
		return found
	}, defaultTestTimeout, 100*time.Millisecond)

	// Check the expected txid is returned.
	rt.Equal(tx.TxHash(), txid)
}

// testReorg tests that the given BitcoindClient correctly responds to a chain
// re-org.
func testReorg(t *testing.T, miner1 *rpctest.Harness, client *BitcoindClient) {
	t.Helper()

	miner2 := setupReorgMiner(t, miner1)

	require := require.New(t)

	miner1Hash, commonHeight, err := miner1.Client.GetBestBlock()
	require.NoError(err)

	miner2Hash, miner2Height, err := miner2.Client.GetBestBlock()
	require.NoError(err)

	require.Equal(commonHeight, miner2Height)
	require.Equal(miner1Hash, miner2Hash)

	require.NoError(client.NotifyBlocks())
	ntfns := client.Notifications()

	// We expect to get a ClientConnected notification.
	select {
	case ntfn := <-ntfns:
		_, ok := ntfn.(ClientConnected)
		require.Truef(ok, "Expected type ClientConnected, got %T", ntfn)

	case <-time.After(defaultTestTimeout):
		require.Fail("timed out for ClientConnected notification")
	}

	// Now disconnect the two miners.
	err = miner1.Client.AddNode(miner2.P2PAddress(), rpcclient.ANRemove)
	require.NoError(err)

	// Generate 5 blocks on miner2.
	_, err = miner2.Client.Generate(5)
	require.NoError(err)

	// Since the miners have been disconnected, we expect not to get any
	// notifications from our client since our client is connected to
	// miner1.
	select {
	case ntfn := <-ntfns:
		t.Fatalf("received a notification of type %T but expected, "+
			"none", ntfn)

	case <-time.After(time.Millisecond * 500):
	}

	// Now generate 3 blocks on miner1. Note that to force our client to
	// experience a re-org, miner1 must generate fewer blocks here than
	// miner2 so that when they reconnect, miner1 does a re-org to switch
	// to the longer chain.
	_, err = miner1.Client.Generate(3)
	require.NoError(err)

	// Read the notifications for the new blocks
	for i := 0; i < 3; i++ {
		_ = waitForBlockNtfn(t, ntfns, commonHeight+int32(i+1), true)
	}

	// Ensure that the two miners have different ideas of what the best
	// block is.
	hash1, height1, err := miner1.Client.GetBestBlock()
	require.NoError(err)
	require.Equal(commonHeight+3, height1)

	hash2, height2, err := miner2.Client.GetBestBlock()
	require.NoError(err)
	require.Equal(commonHeight+5, height2)

	require.False(hash1.IsEqual(hash2))

	// Reconnect the miners. This should result in miner1 reorging to match
	// miner2. Since our client is connected to a node connected to miner1,
	// we should get the expected disconnected and connected notifications.
	err = rpctest.ConnectNode(miner1, miner2)
	require.NoError(err)

	err = rpctest.JoinNodes(
		[]*rpctest.Harness{miner1, miner2}, rpctest.Blocks,
	)
	require.NoError(err)

	// Check that the miners are now on the same page.
	hash1, height1, err = miner1.Client.GetBestBlock()
	require.NoError(err)

	hash2, height2, err = miner2.Client.GetBestBlock()
	require.NoError(err)

	require.Equal(commonHeight+5, height2)
	require.Equal(commonHeight+5, height1)
	require.True(hash1.IsEqual(hash2))

	// We expect our client to get 3 BlockDisconnected notifications first
	// signaling the unwinding of its top 3 blocks.
	for i := 0; i < 3; i++ {
		_ = waitForBlockNtfn(t, ntfns, commonHeight+int32(3-i), false)
	}

	// Now we expect 5 BlockConnected notifications.
	for i := 0; i < 5; i++ {
		_ = waitForBlockNtfn(t, ntfns, commonHeight+int32(i+1), true)
	}
}

// waitForBlockNtfn waits on the passed channel for a BlockConnected or
// BlockDisconnected notification for a block of the expectedHeight. It returns
// hash of the notification if received. If the expected notification is not
// received within 2 seconds, the test is failed. Use the `connected` parameter
// to set whether a Connected or Disconnected notification is expected.
func waitForBlockNtfn(t *testing.T, ntfns <-chan interface{},
	expectedHeight int32, connected bool) chainhash.Hash {

	timer := time.NewTimer(defaultTestTimeout)
	for {
		select {
		case nftn := <-ntfns:
			switch ntfnType := nftn.(type) {
			case BlockConnected:
				if !connected {
					continue
				}

				if ntfnType.Height < expectedHeight {
					continue
				} else if ntfnType.Height != expectedHeight {
					t.Fatalf("expected notification for "+
						"height %d, got height %d",
						expectedHeight, ntfnType.Height)
				}

				return ntfnType.Hash

			case BlockDisconnected:
				if connected {
					continue
				}

				if ntfnType.Height > expectedHeight {
					continue
				} else if ntfnType.Height != expectedHeight {
					t.Fatalf("expected notification for "+
						"height %d, got height %d",
						expectedHeight, ntfnType.Height)
				}

				return ntfnType.Hash

			default:
			}

		case <-timer.C:
			t.Fatalf("timed out waiting for block notification")
		}
	}
}

// setUpMiner sets up a single miner.
func setupMiner(t *testing.T) *rpctest.Harness {
	t.Helper()

	args := []string{
		fmt.Sprintf("--trickleinterval=%v", 10*time.Millisecond),
		// TODO(yy): We should uncomment the following to allow setting
		// up ports here in the test. However, this cannot work without
		// modifying the rpcclient in the `btcd` first, as the ports
		// are overwritten there.
		//
		// fmt.Sprintf("--listen=%v", port.NextAvailablePort()),
		// fmt.Sprintf("--rpclisten=%v", port.NextAvailablePort()),
	}

	miner, err := rpctest.New(&chaincfg.RegressionNetParams, nil, args, "")
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, miner.TearDown())
	})

	require.NoError(t, miner.SetUp(true, 101))

	return miner
}

// setupReorgMiner sets up a second miner that can be used for a re-org test.
func setupReorgMiner(t *testing.T, miner1 *rpctest.Harness) *rpctest.Harness {
	t.Helper()

	args := []string{
		fmt.Sprintf("--trickleinterval=%v", 10*time.Millisecond),
		// TODO(yy): We should uncomment the following to allow setting
		// up ports here in the test. However, this cannot work without
		// modifying the rpcclient in the `btcd` first, as the ports
		// are overwritten there.
		//
		// fmt.Sprintf("--listen=%v", port.NextAvailablePort()),
		// fmt.Sprintf("--rpclisten=%v", port.NextAvailablePort()),
	}

	miner2, err := rpctest.New(
		&chaincfg.RegressionNetParams, nil, args, "",
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		miner2.TearDown()
	})

	require.NoError(t, miner2.SetUp(false, 0))

	// Connect the miners.
	require.NoError(t, rpctest.ConnectNode(miner1, miner2))

	err = rpctest.JoinNodes(
		[]*rpctest.Harness{miner1, miner2}, rpctest.Blocks,
	)
	require.NoError(t, err)

	return miner2
}

// setupBitcoind starts up a bitcoind node with either a zmq connection or
// rpc polling connection and returns a client wrapper of this connection.
func setupBitcoind(t *testing.T, minerAddr string,
	rpcPolling bool) *BitcoindClient {

	// Start a bitcoind instance and connect it to miner1.
	tempBitcoindDir := t.TempDir()

	zmqBlockPort := port.NextAvailablePort()
	zmqTxPort := port.NextAvailablePort()

	zmqBlockHost := fmt.Sprintf("tcp://127.0.0.1:%d", zmqBlockPort)
	zmqTxHost := fmt.Sprintf("tcp://127.0.0.1:%d", zmqTxPort)

	rpcPort := port.NextAvailablePort()
	p2pPort := port.NextAvailablePort()
	bitcoind := exec.Command(
		"bitcoind",
		"-datadir="+tempBitcoindDir,
		"-regtest",
		"-connect="+minerAddr,
		"-txindex",
		"-rpcauth=weks:469e9bb14ab2360f8e226efed5ca6f"+
			"d$507c670e800a95284294edb5773b05544b"+
			"220110063096c221be9933c82d38e1",
		fmt.Sprintf("-rpcport=%d", rpcPort),
		fmt.Sprintf("-port=%d", p2pPort),
		"-disablewallet",
		"-zmqpubrawblock="+zmqBlockHost,
		"-zmqpubrawtx="+zmqTxHost,
		"-blockfilterindex=1",
	)
	require.NoError(t, bitcoind.Start())

	t.Cleanup(func() {
		bitcoind.Process.Kill()
		bitcoind.Wait()
	})

	// Wait for the bitcoind instance to start up.
	time.Sleep(time.Second)

	host := fmt.Sprintf("127.0.0.1:%d", rpcPort)
	cfg := &BitcoindConfig{
		ChainParams: &chaincfg.RegressionNetParams,
		Host:        host,
		User:        "weks",
		Pass:        "weks",
		// Fields only required for pruned nodes, not
		// needed for these tests.
		Dialer:             nil,
		PrunedModeMaxPeers: 0,
	}

	if rpcPolling {
		cfg.PollingConfig = &PollingConfig{
			BlockPollingInterval: time.Millisecond * 100,
			TxPollingInterval:    time.Millisecond * 100,
		}
	} else {
		cfg.ZMQConfig = &ZMQConfig{
			ZMQBlockHost:           zmqBlockHost,
			ZMQTxHost:              zmqTxHost,
			ZMQReadDeadline:        5 * time.Second,
			MempoolPollingInterval: time.Millisecond * 100,
		}
	}

	chainConn, err := NewBitcoindConn(cfg)
	require.NoError(t, err)
	require.NoError(t, chainConn.Start())

	t.Cleanup(func() {
		chainConn.Stop()
	})

	// Create a bitcoind client.
	btcClient, err := chainConn.NewBitcoindClient()
	require.NoError(t, err)
	require.NoError(t, btcClient.Start(t.Context()))

	t.Cleanup(func() {
		btcClient.Stop()
	})

	// Wait for bitcoind to sync with the miner.
	require.Eventually(t, func() bool {
		_, height, err := btcClient.GetBestBlock()
		return err == nil && height >= 101
	}, defaultTestTimeout, 100*time.Millisecond)

	return btcClient
}

// randPubKeyHashScript generates a P2PKH script that pays to the public key of
// a randomly-generated private key.
func randPubKeyHashScript() ([]byte, *btcec.PrivateKey, error) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	pubKeyHash := address.Hash160(privKey.PubKey().SerializeCompressed())

	addrScript, err := address.NewAddressPubKeyHash(
		pubKeyHash, &chaincfg.RegressionNetParams,
	)
	if err != nil {
		return nil, nil, err
	}

	pkScript, err := txscript.PayToAddrScript(addrScript)
	if err != nil {
		return nil, nil, err
	}

	return pkScript, privKey, nil
}

// testBitcoindClientGetCFilter verifies the BitcoindClient's GetCFilter
// implementation by interacting with a live bitcoind node.
func testBitcoindClientGetCFilter(t *testing.T, miner *rpctest.Harness,
	client *BitcoindClient) {

	t.Helper()

	require := require.New(t)

	// Generate a block to have something to query a filter for.
	hashes, err := miner.Client.Generate(1)
	require.NoError(err)

	blockHash := hashes[0]

	// Get the CFilter using the BitcoindClient. This might take a few
	// attempts as the filter index might not be immediately available.
	var gcsFilter *gcs.Filter
	require.Eventually(func() bool {
		gcsFilter, err = client.GetCFilter(
			blockHash, wire.GCSFilterRegular,
		)

		return err == nil
	}, defaultTestTimeout, 100*time.Millisecond,
		"GetCFilter should succeed")
	require.NotNil(gcsFilter, "GCS filter should not be nil")
	require.IsType(&gcs.Filter{}, gcsFilter)

	// Verify the filter matches the block data.
	block, err := client.GetBlock(blockHash)
	require.NoError(err)

	// Use the first transaction's first output script.
	script := block.Transactions[0].TxOut[0].PkScript

	// Derive the filter key.
	key := builder.DeriveKey(blockHash)

	// Check match.
	matched, err := gcsFilter.Match(key, script)
	require.NoError(err)
	require.True(matched, "Filter should match script from block")

	// Test with an unsupported filter type.
	_, err = client.GetCFilter(blockHash, wire.FilterType(99))
	require.ErrorContains(err, "only basic filters are supported",
		"Unsupported filter type should return an error")

	// Test GetCFilter for a non-existent block.
	dummyHash := &chainhash.Hash{0x01, 0x02, 0x03}
	_, err = client.GetCFilter(dummyHash, wire.GCSFilterRegular)
	require.ErrorContains(err, "Block not found",
		"Non-existent block should return an error")
}

// waitForClientConnected waits for a ClientConnected notification on the passed
// channel. Any other notifications received while waiting are ignored.
func waitForClientConnected(t *testing.T, ntfns <-chan any) {
	t.Helper()

	timer := time.NewTimer(defaultTestTimeout)
	defer timer.Stop()

	for {
		select {
		case ntfn := <-ntfns:
			if _, ok := ntfn.(ClientConnected); ok {
				return
			}

		case <-timer.C:
			require.FailNow(t, "timed out for ClientConnected "+
				"notification")
		}
	}
}

// waitForRelevantTx waits for a RelevantTx notification for the passed tx
// hash on the passed channel. Any other notifications received while waiting
// are ignored.
func waitForRelevantTx(t *testing.T, ntfns <-chan any, hash *chainhash.Hash) {
	t.Helper()

	timer := time.NewTimer(defaultTestTimeout)
	defer timer.Stop()

	for {
		select {
		case ntfn := <-ntfns:
			if tx, ok := ntfn.(RelevantTx); ok {
				if tx.TxRecord.Hash.IsEqual(hash) {
					return
				}
			}

		case <-timer.C:
			require.FailNow(t, "timed out waiting for RelevantTx "+
				"notification")
		}
	}
}
