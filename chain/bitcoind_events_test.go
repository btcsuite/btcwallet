package chain

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

// TestBitcoindEvents ensures that the BitcoindClient correctly delivers tx and
// block notifications for both the case where a ZMQ subscription is used and
// for the case where RPC polling is used.
func TestBitcoindEvents(t *testing.T) {
	tests := []struct {
		name       string
		rpcPolling bool
	}{
		{
			name:       "Events via ZMQ subscriptions",
			rpcPolling: false,
		},
		{
			name:       "Events via RPC Polling",
			rpcPolling: true,
		},
	}

	for _, test := range tests {
		test := test

		// Set up 2 btcd miners.
		miner1, miner2 := setupMiners(t)
		addr := miner1.P2PAddress()

		t.Run(test.name, func(t *testing.T) {
			// Set up a bitcoind node and connect it to miner 1.
			btcClient := setupBitcoind(t, addr, test.rpcPolling)

			// Test that the correct block `Connect` and
			// `Disconnect` notifications are received during a
			// re-org.
			testReorg(t, miner1, miner2, btcClient)

			// Test that the expected block notifications are
			// received.
			btcClient = setupBitcoind(t, addr, test.rpcPolling)
			testNotifyBlocks(t, miner1, btcClient)

			// Test that the expected tx notifications are
			// received.
			btcClient = setupBitcoind(t, addr, test.rpcPolling)
			testNotifyTx(t, miner1, btcClient)

			// Test notifications for inputs already found in
			// mempool.
			btcClient = setupBitcoind(t, addr, test.rpcPolling)
			testNotifySpentMempool(t, miner1, btcClient)

			// Test looking up mempool for input spent.
			testLookupInputMempoolSpend(t, miner1, btcClient)
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

	_, err = client.SendRawTransaction(tx, true)
	require.NoError(err)

	ntfns := client.Notifications()

	// We expect to get a ClientConnected notification.
	select {
	case ntfn := <-ntfns:
		_, ok := ntfn.(ClientConnected)
		require.Truef(ok, "Expected type ClientConnected, got %T", ntfn)

	case <-time.After(time.Second):
		require.Fail("timed out for ClientConnected notification")
	}

	// We expect to get a RelevantTx notification.
	select {
	case ntfn := <-ntfns:
		tx, ok := ntfn.(RelevantTx)
		require.Truef(ok, "Expected type RelevantTx, got %T", ntfn)
		require.True(tx.TxRecord.Hash.IsEqual(&hash))

	case <-time.After(time.Second):
		require.Fail("timed out waiting for RelevantTx notification")
	}
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
	select {
	case ntfn := <-ntfns:
		_, ok := ntfn.(ClientConnected)
		require.Truef(ok, "Expected type ClientConnected, got %T", ntfn)

	case <-time.After(time.Second):
		require.Fail("timed out for ClientConnected notification")
	}

	// We expect to get a FilteredBlockConnected notification.
	select {
	case ntfn := <-ntfns:
		_, ok := ntfn.(FilteredBlockConnected)
		require.Truef(ok, "Expected type FilteredBlockConnected, "+
			"got %T", ntfn)

	case <-time.After(time.Second):
		require.Fail("timed out for FilteredBlockConnected " +
			"notification")
	}

	// We expect to get a BlockConnected notification.
	select {
	case ntfn := <-ntfns:
		_, ok := ntfn.(BlockConnected)
		require.Truef(ok, "Expected type BlockConnected, got %T", ntfn)

	case <-time.After(time.Second):
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
	select {
	case ntfn := <-ntfns:
		_, ok := ntfn.(ClientConnected)
		require.Truef(ok, "Expected type ClientConnected, got %T", ntfn)

	case <-time.After(time.Second):
		require.Fail("timed out for ClientConnected notification")
	}

	// We expect to get a RelevantTx notification.
	select {
	case ntfn := <-ntfns:
		tx, ok := ntfn.(RelevantTx)
		require.Truef(ok, "Expected type RelevantTx, got %T", ntfn)
		require.True(tx.TxRecord.Hash.IsEqual(&txid))

	case <-time.After(time.Second):
		require.Fail("timed out waiting for RelevantTx notification")
	}
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
	}, 5*time.Second, 100*time.Millisecond)

	// Check the expected txid is returned.
	rt.Equal(tx.TxHash(), txid)
}

// testReorg tests that the given BitcoindClient correctly responds to a chain
// re-org.
func testReorg(t *testing.T, miner1, miner2 *rpctest.Harness,
	client *BitcoindClient) {

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

	case <-time.After(time.Second):
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

	timer := time.NewTimer(2 * time.Second)
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

// setUpMiners sets up two miners that can be used for a re-org test.
func setupMiners(t *testing.T) (*rpctest.Harness, *rpctest.Harness) {
	trickle := fmt.Sprintf("--trickleinterval=%v", 10*time.Millisecond)
	args := []string{trickle}

	miner1, err := rpctest.New(
		&chaincfg.RegressionNetParams, nil, args, "",
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		miner1.TearDown()
	})

	require.NoError(t, miner1.SetUp(true, 1))

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

	return miner1, miner2
}

// setupBitcoind starts up a bitcoind node with either a zmq connection or
// rpc polling connection and returns a client wrapper of this connection.
func setupBitcoind(t *testing.T, minerAddr string,
	rpcPolling bool) *BitcoindClient {

	// Start a bitcoind instance and connect it to miner1.
	tempBitcoindDir, err := os.MkdirTemp("", "bitcoind")
	require.NoError(t, err)

	zmqBlockHost := "ipc:///" + tempBitcoindDir + "/blocks.socket"
	zmqTxHost := "ipc:///" + tempBitcoindDir + "/tx.socket"
	t.Cleanup(func() {
		os.RemoveAll(tempBitcoindDir)
	})

	rpcPort := rand.Int()%(65536-1024) + 1024
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
		"-disablewallet",
		"-zmqpubrawblock="+zmqBlockHost,
		"-zmqpubrawtx="+zmqTxHost,
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
	btcClient := chainConn.NewBitcoindClient()
	require.NoError(t, btcClient.Start())

	t.Cleanup(func() {
		btcClient.Stop()
	})

	return btcClient
}

// randPubKeyHashScript generates a P2PKH script that pays to the public key of
// a randomly-generated private key.
func randPubKeyHashScript() ([]byte, *btcec.PrivateKey, error) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	pubKeyHash := btcutil.Hash160(privKey.PubKey().SerializeCompressed())
	addrScript, err := btcutil.NewAddressPubKeyHash(
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
