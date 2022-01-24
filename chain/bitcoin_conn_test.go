package chain

import (
        "testing"
        "time"

        "github.com/btcsuite/btcd/chaincfg"
        "github.com/btcsuite/btcd/chaincfg/chainhash"
        "github.com/btcsuite/btcd/integration/rpctest"
        "github.com/btcsuite/btcd/txscript"
        "github.com/btcsuite/btcd/wire"
)

// setUpTestBackend sets up an rpc test harness and a bitcoind connection to it.
func setUpTestBackend(t *testing.T) (*rpctest.Harness, *BitcoindConn) {
        regtestParams := &chaincfg.RegressionNetParams

        rpcHarness, err := rpctest.New(regtestParams, nil, nil, "", true)
        if err != nil {
                t.Fatalf("unable to create primary harness: %v", err)
        }
        if err := rpcHarness.SetUp(true, 125); err != nil {
                t.Fatalf("unable to setup test chain: %v", err)
        }

        rpcCfg := rpcHarness.RPCConfig()

        // Establish the connection to bitcoind and create the clients
        // required for our relevant subsystems.
        bitcoindConn, err := NewBitcoindConn(&BitcoindConfig{
                ChainParams: regtestParams,
                Host:        rpcCfg.Host,
                User:        rpcCfg.User,
                Pass:        rpcCfg.Pass,
                RPCPolling:  true,
                // Set the below timers to a lower number for testing purposes.
                PollBlockTimer: time.Second,
                PollTxTimer:    time.Second,
        })
        if err != nil {
                t.Fatalf("failed to create bitcoind conn: %v", err)
        }

        return rpcHarness, bitcoindConn
}

// TestBlockEventHandlerRPC tests that when we choose to poll for the latest
// bitcoind blocks, the latest blocks are successfully sent to the client.
func TestBlockEventHandlerRPC(t *testing.T) {
        rpcHarness, bitcoindConn := setUpTestBackend(t)
        defer rpcHarness.TearDown()

        _, err := rpcHarness.GenerateAndSubmitBlock(nil, 4, time.Time{})
        if err != nil {
                t.Fatalf("failed to generated block: %v", err)
        }

        bitcoindConn.wg.Add(1)
        go bitcoindConn.blockEventHandlerRPC()

        bitcoindClient := bitcoindConn.NewBitcoindClient()

        err = bitcoindClient.Start()
        if err != nil {
                t.Fatalf("failed to start bitcoind client: %v", err)
        }

        bitcoindClient.NotifyBlocks()

        // Before we do anything else, check the current block height to
        // compare with at the end.
        bitcoindConn.rescanClientsMtx.Lock()
        initialBestBlock, err := bitcoindConn.rescanClients[1].BlockStamp()
        if err != nil {
                t.Fatalf("Unable to get most recent block: %v", err)
        }
        bitcoindConn.rescanClientsMtx.Unlock()

        _, err = rpcHarness.GenerateAndSubmitBlock(nil, 4, time.Time{})
        if err != nil {
                t.Fatalf("failed to generated block: %v", err)
        }

        // Sleep shortly so we can wait for block to go through.
        time.Sleep(time.Second * 2)

	// Check the block height of one of the clients to see
        // if we're up to date or not.
        bestBlock, err := bitcoindConn.rescanClients[1].BlockStamp()
        if err != nil {
                t.Fatalf("Unable to get most recent block: %v", err)
        }

        if bestBlock.Height != (initialBestBlock.Height + int32(1)) {
                t.Fatal("client did not successfully process block")
        }
}

// TestTxEventHandlerRPC tests that when we choose to poll for the latest
// bitcoind transactions, the latest mempool transactions are successfully sent
// to the client.
func TestTxEventHandlerRPC(t *testing.T) {
        rpcHarness, bitcoindConn := setUpTestBackend(t)
        defer rpcHarness.TearDown()

        _, err := rpcHarness.GenerateAndSubmitBlock(nil, 4, time.Time{})
        if err != nil {
                t.Fatalf("failed to generated block: %v", err)
        }

        bitcoindClient := bitcoindConn.NewBitcoindClient()

        err = bitcoindClient.Start()
        if err != nil {
                t.Fatalf("failed to start bitcoind client: %v", err)
        }

        bitcoindClient.NotifyBlocks()

	// Start polling for new transactions
        bitcoindConn.wg.Add(1)
        go bitcoindConn.txEventHandlerRPC()

        // We need to send a transaction to make sure that our polling detects
        // when a new transaction is sent.
        addr, err := rpcHarness.NewAddress()
        addrScript, err := txscript.PayToAddrScript(addr)
        if err != nil {
                t.Fatalf("unable to generate pkscript to addr: %v", err)
        }

        // Btcd's mempool first sees this transaction. And now, because
        // we're pooling to look for new transactions from the mempool, the
        // client should now know of it too.
        // We'll check the client to make sure this is the case.
        client := bitcoindConn.rescanClients[1]

        client.watchMtx.Lock()
        client.watchedAddresses[addr.String()] = struct{}{}
        client.watchMtx.Unlock()

        // Sleep to give time for client to get set up.
        time.Sleep(time.Second)

        output := wire.NewTxOut(5e8, addrScript)
        testTx, err := rpcHarness.CreateTransaction([]*wire.TxOut{output}, 10, true)
        if err != nil {
                t.Fatalf("coinbase spend failed: %v", err)
        }
        txHash, err := rpcHarness.Client.SendRawTransaction(testTx, true)
        if err != nil {
                t.Fatalf("send transaction failed: %v", err)
        }

        // Sleep to wait for new tx to be processed.
        time.Sleep(time.Second * 2)

        if _, ok := bitcoindConn.mempool[*txHash]; !ok {
                t.Fatal("new transaction wasn't put in local mempool map as " +
                        "it should have been")
        }

        if _, ok := client.mempool[*txHash]; !ok {
                t.Fatal("client did not process new transaction " +
                        "correctly")
        }
}

// TestCheckForUnconfTxs checks that checkForUnconfTxs susccessfully deletes
// transactions that have been in our mempool map for longer than some time
// frame.
func TestCheckForUnconfTxs(t *testing.T) {
        bitcoindConn := BitcoindConn{}
        bitcoindConn.mempool = make(map[chainhash.Hash]time.Time)

        txHash := []string{
                "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9",
                "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c1",
                "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c2",
                "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c3",
                "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c4",
        }

        txTimes := []time.Time{
                time.Now().AddDate(-1, 0, 0),
                time.Now().AddDate(0, -1, 0),
                time.Now().AddDate(0, 0, -1),
                time.Now().Add(time.Duration(-10) * time.Minute),
                time.Now().Add(time.Duration(-5) * time.Hour),
        }

        for idx, time := range txTimes {
                hash, err := chainhash.NewHashFromStr(txHash[idx])
                if err != nil {
                        t.Fatalf("failed to create hash: %v", err)
                }

                bitcoindConn.mempool[*hash] = time
        }

        bitcoindConn.checkForUnconfTxs()

        if len(bitcoindConn.mempool) != 2 {
                t.Fatal("mempool transactions older than a day should have " +
                        "been deleted")
        }
}
