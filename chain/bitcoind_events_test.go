package chain

import (
	"fmt"
	"io/ioutil"
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

	// Set up 2 btcd miners.
	miner1, miner2 := setupMiners(t)

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Set up a bitcoind node and connect it to miner 1.
			btcClient := setupBitcoind(
				t, miner1.P2PAddress(), test.rpcPolling,
			)

			// Test that the correct block `Connect` and
			// `Disconnect` notifications are received during a
			// re-org.
			testReorg(t, miner1, miner2, btcClient)

			// Test that the expected block and transaction
			// notifications are received.
			testNotifications(t, miner1, btcClient)
		})
	}
}

// TestMempool tests that each method of the mempool struct works as expected.
func TestMempool(t *testing.T) {
	m := newMempool()

	// Create a transaction.
	tx1 := &wire.MsgTx{LockTime: 1}

	// Check that mempool doesn't have the tx yet.
	require.False(t, m.contains(tx1.TxHash()))

	// Now add the tx.
	m.add(tx1.TxHash())

	// Mempool should now contain the tx.
	require.True(t, m.contains(tx1.TxHash()))

	// Add another tx to the mempool.
	tx2 := &wire.MsgTx{LockTime: 2}
	m.add(tx2.TxHash())
	require.True(t, m.contains(tx2.TxHash()))

	// Clean the mempool of tx1 (this simulates a block being confirmed
	// with tx1 in the block).
	m.clean([]*wire.MsgTx{tx1})

	// Ensure that tx1 is no longer in the mempool but that tx2 still is.
	require.False(t, m.contains(tx1.TxHash()))
	require.True(t, m.contains(tx2.TxHash()))

	// Lastly, we test that only marked transactions are deleted from the
	// mempool.

	// Let's first re-add tx1 so that we have more txs to work with.
	m.add(tx1.TxHash())

	// Now, we unmark all the transactions.
	m.unmarkAll()

	// Add tx3. This should automatically mark tx3.
	tx3 := &wire.MsgTx{LockTime: 3}
	m.add(tx3.TxHash())

	// Let us now manually mark tx2.
	m.mark(tx2.TxHash())

	// Now we delete all unmarked txs. This should leave only tx2 and tx3
	// in the mempool.
	m.deleteUnmarked()

	require.False(t, m.contains(tx1.TxHash()))
	require.True(t, m.contains(tx2.TxHash()))
	require.True(t, m.contains(tx3.TxHash()))
}

// testNotifications tests that the correct notifications are received for
// blocks and transactions in the simple non-reorg case.
func testNotifications(t *testing.T, miner *rpctest.Harness,
	client *BitcoindClient) {

	script, _, err := randPubKeyHashScript()
	require.NoError(t, err)

	tx, err := miner.CreateTransaction(
		[]*wire.TxOut{{Value: 1000, PkScript: script}}, 5, false,
	)
	require.NoError(t, err)

	hash := tx.TxHash()

	err = client.NotifyTx([]chainhash.Hash{hash})
	require.NoError(t, err)

	_, err = client.SendRawTransaction(tx, true)
	require.NoError(t, err)

	ntfns := client.Notifications()

	miner.Client.Generate(1)

	// First, we expect to get a RelevantTx notification.
	select {
	case ntfn := <-ntfns:
		tx, ok := ntfn.(RelevantTx)
		if !ok {
			t.Fatalf("Expected a notification of type "+
				"RelevantTx, got %T", ntfn)
		}

		require.True(t, tx.TxRecord.Hash.IsEqual(&hash))

	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for RelevantTx notification")
	}

	// Then, we expect to get a FilteredBlockConnected notification.
	select {
	case ntfn := <-ntfns:
		_, ok := ntfn.(FilteredBlockConnected)
		if !ok {
			t.Fatalf("Expected a notification of type "+
				"FilteredBlockConnected, got %T", ntfn)
		}

	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for FilteredBlockConnected " +
			"notification")
	}

	// Lastly, we expect to get a BlockConnected notification.
	select {
	case ntfn := <-ntfns:
		_, ok := ntfn.(BlockConnected)
		if !ok {
			t.Fatalf("Expected a notification of type "+
				"BlockConnected, got %T", ntfn)
		}

	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for BlockConnected notification")
	}
}

// testReorg tests that the given BitcoindClient correctly responds to a chain
// re-org.
func testReorg(t *testing.T, miner1, miner2 *rpctest.Harness,
	client *BitcoindClient) {

	miner1Hash, commonHeight, err := miner1.Client.GetBestBlock()
	require.NoError(t, err)

	miner2Hash, miner2Height, err := miner2.Client.GetBestBlock()
	require.NoError(t, err)

	require.Equal(t, commonHeight, miner2Height)
	require.Equal(t, miner1Hash, miner2Hash)

	// Let miner2 generate a few blocks and ensure that our bitcoind client
	// is notified of this block.
	hashes, err := miner2.Client.Generate(5)
	require.NoError(t, err)
	require.Len(t, hashes, 5)

	ntfns := client.Notifications()

	for i := 0; i < 5; i++ {
		commonHeight++
		ntfnHash := waitForBlockNtfn(t, ntfns, commonHeight, true)
		require.True(t, ntfnHash.IsEqual(hashes[i]))
	}

	// Now disconnect the two miners.
	err = miner1.Client.AddNode(miner2.P2PAddress(), rpcclient.ANRemove)
	require.NoError(t, err)

	// Generate 5 blocks on miner2.
	_, err = miner2.Client.Generate(5)
	require.NoError(t, err)

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
	require.NoError(t, err)

	// Read the notifications for the new blocks
	for i := 0; i < 3; i++ {
		_ = waitForBlockNtfn(t, ntfns, commonHeight+int32(i+1), true)
	}

	// Ensure that the two miners have different ideas of what the best
	// block is.
	hash1, height1, err := miner1.Client.GetBestBlock()
	require.NoError(t, err)
	require.Equal(t, commonHeight+3, height1)

	hash2, height2, err := miner2.Client.GetBestBlock()
	require.NoError(t, err)
	require.Equal(t, commonHeight+5, height2)

	require.False(t, hash1.IsEqual(hash2))

	// Reconnect the miners. This should result in miner1 reorging to match
	// miner2. Since our client is connected to a node connected to miner1,
	// we should get the expected disconnected and connected notifications.
	err = rpctest.ConnectNode(miner1, miner2)
	require.NoError(t, err)

	err = rpctest.JoinNodes(
		[]*rpctest.Harness{miner1, miner2}, rpctest.Blocks,
	)
	require.NoError(t, err)

	// Check that the miners are now on the same page.
	hash1, height1, err = miner1.Client.GetBestBlock()
	require.NoError(t, err)

	hash2, height2, err = miner2.Client.GetBestBlock()
	require.NoError(t, err)

	require.Equal(t, commonHeight+5, height2)
	require.Equal(t, commonHeight+5, height1)
	require.True(t, hash1.IsEqual(hash2))

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
					fmt.Println("???")
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
	tempBitcoindDir, err := ioutil.TempDir("", "bitcoind")
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
			ZMQBlockHost:    zmqBlockHost,
			ZMQTxHost:       zmqTxHost,
			ZMQReadDeadline: 5 * time.Second,
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

	require.NoError(t, btcClient.NotifyBlocks())

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
