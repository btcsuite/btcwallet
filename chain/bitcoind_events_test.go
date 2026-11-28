package chain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/gcs"
	"github.com/btcsuite/btcd/btcutil/v2/gcs/builder"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain/port"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	// defaultTestTimeout is the default timeout used for tests in this
	// file. It is set to 30 seconds to allow for slow test environments.
	defaultTestTimeout = 30 * time.Second
)

// newBitcoindStartupTestClient gives the real client a local RPC endpoint
// whose tip request can fail before the notification queue is published.
func newBitcoindStartupTestClient(t *testing.T,
	tipError func() *btcjson.RPCError) *BitcoindClient {

	t.Helper()

	// Serve startup RPCs without a node or its notification transport.
	serve := func(w http.ResponseWriter, r *http.Request) {
		var req btcjson.Request

		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			t.Error(err)
			return
		}

		response := btcjson.Response{Jsonrpc: req.Jsonrpc, ID: &req.ID}
		switch req.Method {
		case "getblockchaininfo":
			// Inject a warmup error only in tests that need it.
			if tipError != nil {
				response.Error = tipError()
			}

			if response.Error == nil {
				response.Result = json.RawMessage(
					`{"bestblockhash":"01"}`,
				)
			}

		case "getinfo":
			// Bitcoind exposes its version via getnetworkinfo.
			response.Error = btcjson.ErrRPCMethodNotFound

		case "getnetworkinfo":
			version := `{"subversion":"/Satoshi:32.0.0/"}`
			response.Result = json.RawMessage(version)

		case "getblockheader":
			response.Result = json.RawMessage(`{"time":1}`)

		default:
			t.Errorf("unexpected startup RPC %q", req.Method)
			return
		}

		err = json.NewEncoder(w).Encode(response)
		if err != nil {
			t.Error(err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(serve))
	t.Cleanup(server.Close)

	// Supply explicit credentials so rpcclient targets this test server
	// without looking for a local bitcoind cookie.
	cfg := rpcclient.ConnConfig{
		Host:         strings.TrimPrefix(server.URL, "http://"),
		User:         "test",
		Pass:         "test",
		HTTPPostMode: true,
		DisableTLS:   true,
	}
	rpc, err := rpcclient.New(&cfg, nil)
	require.NoError(t, err)

	t.Cleanup(rpc.WaitForShutdown)
	t.Cleanup(rpc.Shutdown)

	conn := &BitcoindConn{
		cfg: BitcoindConfig{
			Host: cfg.Host,
			User: cfg.User,
			Pass: cfg.Pass,
		},
		client: rpc,
	}
	client, err := conn.NewBitcoindClient()
	require.NoError(t, err)

	t.Cleanup(client.WaitForShutdown)
	t.Cleanup(client.Stop)

	return client
}

// TestBitcoindSubscriptionLiveDelivery checks that native history is excluded
// and that overflow at a slow reader leaves the fast reader unaffected.
func TestBitcoindSubscriptionLiveDelivery(t *testing.T) {
	t.Parallel()

	// Arrange a started client and drain the legacy startup marker so
	// the next legacy read can check the same marker as a live reader.
	client := newBitcoindStartupTestClient(t, nil)
	require.NoError(t, client.Start(t.Context()))
	atomic.StoreUint32(&client.notifyBlocks, 1)

	hash := chainhash.Hash{1}
	legacy := client.Notifications()
	waitForClientConnected(t, legacy)

	fast := client.SubscribeChainEvents(t.Context())
	slow := client.SubscribeChainEvents(t.Context())

	// Bound each read and return the first event so a later matching
	// marker cannot hide replay or a gap.
	receiveEvent := func(events <-chan Event) Event {
		t.Helper()

		select {
		case event := <-events:
			return event
		case <-time.After(defaultTestTimeout):
			require.FailNow(t, "reader missed an Event")
		}

		return Event{}
	}
	receiveLegacy := func(events <-chan any) any {
		t.Helper()

		select {
		case event := <-events:
			return event
		case <-time.After(defaultTestTimeout):
			require.FailNow(t, "legacy reader missed event")
		}

		return nil
	}

	// Act by filling the slow reader's buffer while draining the fast
	// reader to keep its subscription active.
	capacity := cap(slow.BlockEvents())
	require.Equal(t, 100, capacity)

	height := int32(2)

	for range capacity {
		client.onBlockDisconnected(&hash, height, time.Time{})

		ev := receiveEvent(fast.BlockEvents())
		require.Equal(t, EventBlockDisconnected, ev.Type)
		require.Equal(t, hash, ev.Block.Hash)
		require.Equal(t, height, ev.Block.Height)
		height++
	}

	// Assert coexistence on the first legacy marker. Drain through the
	// last marker because legacy enqueue follows all live offers.
	require.Equal(
		t, BlockDisconnected{
			Block: wtxmgr.Block{Hash: hash, Height: 2},
		}, receiveLegacy(legacy),
	)

	for range capacity - 1 {
		receiveLegacy(legacy)
	}

	// All slots are occupied. Closure requires a failed offer.
	select {
	case <-slow.Done():
		require.FailNow(t, "filling the buffer retired subscription")
	default:
	}

	// The next marker cannot fit for the slow reader. It still fits for
	// the fast reader and exposes the slow reader's terminal result.
	client.onBlockDisconnected(&hash, height, time.Time{})

	ev := receiveEvent(fast.BlockEvents())
	require.Equal(t, EventBlockDisconnected, ev.Type)
	require.Equal(t, height, ev.Block.Height)
	height++

	waitSubDone(t, slow)
	require.ErrorIs(t, slow.Err(), ErrEventSubscriptionBufferFull)

	late := client.SubscribeChainEvents(t.Context()).BlockEvents()

	// The closed slow reader retains exactly the accepted prefix.
	retained := int32(2)

	for range capacity {
		ev := receiveEvent(slow.BlockEvents())
		require.Equal(t, EventBlockDisconnected, ev.Type)
		require.Equal(t, hash, ev.Block.Hash)
		require.Equal(t, retained, ev.Block.Height)
		retained++
	}

	_, open := <-slow.BlockEvents()
	require.False(t, open)

	_, open = <-slow.MempoolTxns()
	require.False(t, open)

	// Check late enrollment and continued fast delivery after overflow.
	client.onBlockDisconnected(&hash, height, time.Time{})
	want := Event{
		Type: EventBlockDisconnected,
		Block: &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Hash: hash, Height: height},
		},
	}
	require.Equal(t, want, receiveEvent(late))
	require.Equal(t, want, receiveEvent(fast.BlockEvents()))
}

// TestBitcoindSubscriptionPreCanceled checks that an already-canceled
// context returns a retired subscription.
func TestBitcoindSubscriptionPreCanceled(t *testing.T) {
	t.Parallel()

	// Arrange a running source with a context canceled before enrollment.
	client := newBitcoindStartupTestClient(t, nil)
	require.NoError(t, client.Start(t.Context()))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Act by subscribing with the context that already finished.
	sub := client.SubscribeChainEvents(ctx)

	// Assert all channels are closed when the rejected call returns,
	// with the source still running.
	select {
	case <-sub.Done():
	default:
		require.FailNow(t, "refused subscription stayed active")
	}

	require.ErrorIs(t, sub.Err(), context.Canceled)

	select {
	case _, ok := <-sub.BlockEvents():
		require.False(t, ok)
	default:
		require.FailNow(t, "refused subscription left BlockEvents open")
	}

	select {
	case _, ok := <-sub.MempoolTxns():
		require.False(t, ok)
	default:
		require.FailNow(t, "refused subscription left MempoolTxns open")
	}
}

// TestBitcoindSubscriptionCancellation checks that an unread subscriber can
// retire and events published during the resulting gap are ineligible.
func TestBitcoindSubscriptionCancellation(t *testing.T) {
	t.Parallel()

	// Arrange one live subscriber with a pending event and no drain.
	client := newBitcoindStartupTestClient(t, nil)
	require.NoError(t, client.Start(t.Context()))
	atomic.StoreUint32(&client.notifyBlocks, 1)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	first := client.SubscribeChainEvents(ctx)
	hash := chainhash.Hash{3}
	client.onBlockDisconnected(&hash, 1, time.Time{})

	// Act by retiring the only subscriber, then publish while there is
	// no reader. Leave the old reader's BlockEvents channel unread.
	cancel()
	waitSubDone(t, first)
	require.ErrorIs(t, first.Err(), context.Canceled)

	client.onBlockDisconnected(&hash, 2, time.Time{})

	// The owner must finish publishing height 2 before it can accept
	// height 3. Publication of height 3 itself may race registration.
	client.onBlockDisconnected(&hash, 3, time.Time{})

	next := client.SubscribeChainEvents(t.Context())
	client.onBlockDisconnected(&hash, 4, time.Time{})

	// Assert the reader can receive the racing height 3 and must receive
	// height 4. Height 2 was published before enrollment and fails either
	// expectation.
	deadline := time.After(defaultTestTimeout)

	for {
		select {
		case event := <-next.BlockEvents():
			require.Equal(
				t, EventBlockDisconnected, event.Type,
			)

			if event.Block.Height == 3 {
				require.Equal(t, hash, event.Block.Hash)
				continue
			}

			require.Equal(t, hash, event.Block.Hash)
			require.Equal(t, int32(4), event.Block.Height)

			return

		case <-deadline:
			require.FailNow(t, "new reader missed live delivery")
		}
	}
}

// TestBitcoindSubscriptionClientShutdown checks client Stop independently of
// connection shutdown, including a live reader with an unread event.
func TestBitcoindSubscriptionClientShutdown(t *testing.T) {
	t.Parallel()

	// Arrange a started client and leave an eligible event unread.
	client := newBitcoindStartupTestClient(t, nil)
	require.NoError(t, client.Start(t.Context()))
	atomic.StoreUint32(&client.notifyBlocks, 1)

	sub := client.SubscribeChainEvents(t.Context())
	hash := chainhash.Hash{4}
	client.onBlockDisconnected(&hash, 1, time.Time{})

	// Act by stopping the client while its subscription context is live.
	client.Stop()

	// Assert retirement does not require first draining the event. The
	// existing buffered event remains readable on the closed channel.
	waitSubDone(t, sub)
	require.NoError(t, sub.Err())

	ev := <-sub.BlockEvents()
	require.Equal(t, EventBlockDisconnected, ev.Type)
	require.Equal(t, hash, ev.Block.Hash)
	require.Equal(t, int32(1), ev.Block.Height)

	_, ok := <-sub.BlockEvents()
	require.False(t, ok)

	_, ok = <-sub.MempoolTxns()
	require.False(t, ok)

	// A call after retirement must return already-closed channels.
	late := client.SubscribeChainEvents(t.Context())
	select {
	case <-late.Done():
	default:
		require.FailNow(t, "a stopped client accepted a new subscriber")
	}

	select {
	case _, open := <-late.BlockEvents():
		require.False(t, open)
	default:
		require.FailNow(t, "a stopped client left BlockEvents open")
	}

	select {
	case _, open := <-late.MempoolTxns():
		require.False(t, open)
	default:
		require.FailNow(t, "a stopped client left MempoolTxns open")
	}
}

// TestBitcoindSubscriptionAfterStartRetry verifies a failed Start leaves the
// client retryable and a successful retry makes live subscriptions usable.
func TestBitcoindSubscriptionAfterStartRetry(t *testing.T) {
	t.Parallel()

	// Arrange a node in warmup. The same RPC fixture can return its tip
	// when the test clears the error.
	var tipError atomic.Pointer[btcjson.RPCError]
	tipError.Store(btcjson.NewRPCError(
		btcjson.ErrRPCInWarmup, "Loading block index",
	))
	client := newBitcoindStartupTestClient(t, tipError.Load)

	// Act by starting once while the node is in warmup, then retry on
	// the same client after its tip RPC becomes available.
	firstErr := client.Start(t.Context())

	tipError.Store(nil)

	retryErr := client.Start(t.Context())

	// Assert the first call returns the actual RPC error. Verify the
	// retry initialized the stream by receiving a live native marker.
	var rpcErr *btcjson.RPCError
	require.ErrorAs(t, firstErr, &rpcErr)
	require.Equal(t, btcjson.ErrRPCInWarmup, rpcErr.Code)
	require.NoError(t, retryErr)

	atomic.StoreUint32(&client.notifyBlocks, 1)
	sub := client.SubscribeChainEvents(t.Context())
	hash := chainhash.Hash{1}
	client.onBlockDisconnected(&hash, 1, time.Time{})

	select {
	case event := <-sub.BlockEvents():
		require.Equal(t, EventBlockDisconnected, event.Type)
		require.Equal(t, hash, event.Block.Hash)
		require.Equal(t, int32(1), event.Block.Height)
	case <-time.After(defaultTestTimeout):
		require.FailNow(t, "retry did not enable live delivery")
	}
}

// TestBitcoindConcurrentStart verifies overlapping Start calls produce one
// startup notification for the client.
func TestBitcoindConcurrentStart(t *testing.T) {
	t.Parallel()

	// Arrange a real client with a healthy tip endpoint. A shared release
	// lets two callers enter Start while the first tip lookup is in flight.
	client := newBitcoindStartupTestClient(t, nil)
	start := make(chan struct{})
	results := make(chan error, 2)

	// Act by releasing both callers and collecting their results before
	// reading any startup notifications.
	for range cap(results) {
		go func() {
			<-start

			results <- client.Start(t.Context())
		}()
	}

	close(start)

	firstErr, secondErr := <-results, <-results

	// Assert both callers succeeded and together seeded exactly one
	// startup marker in the public notification channel.
	require.NoError(t, firstErr)
	require.NoError(t, secondErr)

	notifications := client.Notifications()
	require.Len(t, notifications, 1)
	require.Equal(t, ClientConnected{}, <-notifications)
}

// TestBitcoindStartRetryAfterStop verifies a failed start cannot be retried
// once Stop has retired the notification queue.
func TestBitcoindStartRetryAfterStop(t *testing.T) {
	t.Parallel()

	// Arrange an initial warmup failure before retiring the client.
	var tipError atomic.Pointer[btcjson.RPCError]
	tipError.Store(btcjson.NewRPCError(
		btcjson.ErrRPCInWarmup, "Loading block index",
	))
	client := newBitcoindStartupTestClient(t, tipError.Load)

	var rpcErr *btcjson.RPCError
	require.ErrorAs(t, client.Start(t.Context()), &rpcErr)
	require.Equal(t, btcjson.ErrRPCInWarmup, rpcErr.Code)
	client.Stop()
	tipError.Store(nil)

	// Act after the node has recovered while the old client stays stopped.
	err := client.Start(t.Context())

	// Assert startup rejects the retry on the retired queue.
	require.ErrorIs(t, err, ErrBitcoindClientShuttingDown)
}

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

	t.Run("SubscriptionSourceShutdown", func(t *testing.T) {
		// Arrange a live subscription before the client registers any
		// watches, so closure depends on observing the backing quit.
		client := setupBitcoind(t, setupMiner(t), true)
		sub := client.SubscribeChainEvents(t.Context())

		// Act on the backing connection. The subscription precedes
		// watch registration, so connection stop cannot find the
		// client in the registered set to stop it directly.
		client.chainConn.Stop()

		// Assert the connection's terminal signal reaches the client
		// even without a native watch on that connection.
		select {
		case <-sub.Done():
		case <-time.After(defaultTestTimeout):
			t.Fatal("subscription outlived its backing connection")
		}
	})
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
		{
			name: "Batch RPCs",
			testFn: func(t *testing.T, h *rpctest.Harness,
				bc *BitcoindClient) {

				t.Helper()
				testInterfaceBatchMethods(t, h, bc)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Initialize a fresh miner for the test case.
			miner1 := setupMiner(t)

			// Initialize a fresh bitcoind client for EVERY test
			// case.
			btcClient := setupBitcoind(t, miner1, rpcPolling)

			test.testFn(t, miner1, btcClient)
		})
	}
}

// TestBitcoindEventsWatchAddrsFromTip applies the live-tip contract.
//
//nolint:paralleltest // Btcd's rpctest ports can collide across subtests.
func TestBitcoindEventsWatchAddrsFromTip(t *testing.T) {
	backends := []struct {
		name       string
		rpcPolling bool
	}{
		{
			name:       "ZMQ",
			rpcPolling: false,
		},
		{
			name:       "RPC",
			rpcPolling: true,
		},
	}

	for _, backend := range backends {
		t.Run(backend.name, func(t *testing.T) {
			// Arrange: mine history before bitcoind starts and select its
			// transport from data, excluding stale ZMQ transaction events.
			miner := setupMiner(t)
			addr := mineHistoricalWatchAddr(t, miner)
			client := setupBitcoind(t, miner, backend.rpcPolling)

			// Act: prove no hidden rescan with an isolated client, then run
			// the production contract on the selected transport.
			assertWatchAddrsFromTipDoesNotRescan(t, client, addr)
			testWatchAddrsFromTipConformance(
				t, miner, client, addr,
			)

			// Assert: one future notification drains through a later block.
		})
	}
}

// assertWatchAddrsFromTipDoesNotRescan uses a handler-free test client.
func assertWatchAddrsFromTipDoesNotRescan(t *testing.T,
	client *BitcoindClient, addr address.Address) {

	t.Helper()

	// Arrange: start only the sibling queue so registration owns the wait
	// group and every tracked goroutine belongs to the operation under test.
	probe, err := client.chainConn.NewBitcoindClient()
	require.NoError(t, err)
	probe.notificationQueue.Start()

	atomic.StoreUint32(&probe.notifyBlocks, 1)
	defer probe.Stop()

	// Act: wait for registration work, then enqueue its FIFO marker.
	err = probe.WatchAddrsFromTip(t.Context(), []address.Address{addr})
	require.NoError(t, err)
	probe.WaitForShutdown()

	probe.notificationQueue.ChanIn() <- ClientConnected{}

	// Assert: reach the marker without a historical rescan completion.
	for ntfn := range probe.Notifications() {
		if _, ok := ntfn.(ClientConnected); ok {
			return
		}

		_, rescanned := ntfn.(*RescanFinished)
		require.False(t, rescanned)
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

	// Mine one block after the subscription is active. Both connected
	// notifications below must identify this block.
	blocks, err := miner.Client.Generate(1)
	require.NoError(err)
	require.Len(blocks, 1)
	blockHash := *blocks[0]

	// We expect to get a ClientConnected notification.
	waitForClientConnected(t, ntfns)

	// We expect to get a FilteredBlockConnected notification.
	select {
	case ntfn := <-ntfns:
		block, ok := ntfn.(FilteredBlockConnected)
		require.Truef(ok, "Expected type FilteredBlockConnected, "+
			"got %T", ntfn)
		require.Equal(blockHash, block.Block.Hash)

	case <-time.After(defaultTestTimeout):
		require.Fail("timed out for FilteredBlockConnected " +
			"notification")
	}

	// We expect to get a BlockConnected notification.
	select {
	case ntfn := <-ntfns:
		block, ok := ntfn.(BlockConnected)
		require.Truef(ok, "Expected type BlockConnected, got %T", ntfn)
		require.Equal(blockHash, block.Hash)

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

	// Arrange disconnected miners so the shorter branch becomes orphaned.
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
	oldHashes, err := miner1.Client.Generate(3)
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

	// Act by reconnecting the miners so miner1 reorganizes to miner2.
	// Its connected client must report the old and replacement identities.
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

	// Assert each disconnected identity as well as height: a grandparent
	// hash would prevent history recovery even though heights descend.
	for i := 0; i < 3; i++ {
		hash := waitForBlockNtfn(
			t, ntfns, commonHeight+int32(3-i), false,
		)
		require.Equal(*oldHashes[2-i], hash)
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
func setupBitcoind(t *testing.T, miner *rpctest.Harness,
	rpcPolling bool) *BitcoindClient {
	t.Helper()

	minerHash, minerHeight, err := miner.Client.GetBestBlock()
	require.NoError(t, err)

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
		"-connect="+miner.P2PAddress(),
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
	syncClient, err := rpcclient.New(&rpcclient.ConnConfig{
		Host:         host,
		User:         "weks",
		Pass:         "weks",
		DisableTLS:   true,
		HTTPPostMode: true,
	}, nil)
	require.NoError(t, err)

	defer syncClient.Shutdown()

	// Wait for bitcoind to reach the miner's exact tip before constructing
	// the event source. This prevents either the RPC poller or ZMQ subscriber
	// from observing synchronization blocks as post-start events.
	require.Eventually(t, func() bool {
		chainInfo, err := syncClient.GetBlockChainInfo()
		if err != nil {
			return false
		}

		return chainInfo.Blocks == minerHeight &&
			chainInfo.BestBlockHash == minerHash.String()
	}, defaultTestTimeout, 100*time.Millisecond)

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

// waitForExclusiveRelevantTx rejects every unexpected transaction.
func waitForExclusiveRelevantTx(t *testing.T, ntfns <-chan any,
	hash *chainhash.Hash) {

	t.Helper()

	timer := time.NewTimer(defaultTestTimeout)
	defer timer.Stop()

	for {
		select {
		case ntfn := <-ntfns:
			switch value := ntfn.(type) {
			case RelevantTx:
				require.True(
					t, value.TxRecord.Hash.IsEqual(hash),
					"received unexpected relevant transaction %v",
					value.TxRecord.Hash,
				)

				return

			case FilteredBlockConnected:
				// Bitcoind groups confirmed matches in block notifications,
				// so inspect every record to expose a historical replay.
				var found bool
				for _, tx := range value.RelevantTxs {
					require.True(
						t, tx.Hash.IsEqual(hash),
						"received unexpected relevant transaction %v",
						tx.Hash,
					)
					require.False(
						t, found,
						"received duplicate relevant transaction %v",
						tx.Hash,
					)
					found = true
				}

				if found {
					return
				}
			}

		case <-timer.C:
			require.FailNow(t, "timed out waiting for RelevantTx "+
				"notification")
		}
	}
}

// waitForNoRelevantTxUntilBlock drains notifications through an exact later
// block, failing if a duplicate or delayed historical transaction appears.
func waitForNoRelevantTxUntilBlock(t *testing.T, ntfns <-chan any,
	hash *chainhash.Hash) {

	t.Helper()

	timer := time.NewTimer(defaultTestTimeout)
	defer timer.Stop()

	for {
		select {
		case ntfn := <-ntfns:
			switch value := ntfn.(type) {
			case RelevantTx:
				require.FailNowf(
					t, "unexpected relevant transaction",
					"received transaction %v after the expected "+
						"future delivery", value.TxRecord.Hash,
				)

			case FilteredBlockConnected:
				// Every confirmed match after the expected delivery is a
				// duplicate or delayed historical notification.
				for _, tx := range value.RelevantTxs {
					require.FailNowf(
						t, "unexpected relevant transaction",
						"received transaction %v after the "+
							"expected future delivery", tx.Hash,
					)
				}

			case BlockConnected:
				if value.Hash.IsEqual(hash) {
					return
				}
			}

		case <-timer.C:
			require.FailNow(t, "timed out waiting for post-delivery "+
				"BlockConnected notification")
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

// waitSubDone waits until sub.Done() closes or fails the test on timeout.
func waitSubDone(t *testing.T, sub EventSubscription) {
	t.Helper()

	select {
	case <-sub.Done():
	case <-time.After(defaultTestTimeout):
		require.FailNow(t, "timed out waiting for subscription done")
	}
}

// TestChainEventSubscriptionUnindexOnCancel verifies that canceling one
// listener unindexes its exclusive watches, leaves shared watches intact for
// remaining listeners, and releases the retired listener's own watch maps.
func TestChainEventSubscriptionUnindexOnCancel(t *testing.T) {
	t.Parallel()

	// Set up a stream with two active listeners that share one script and
	// one outpoint while the first listener also owns exclusive keys.
	stream := newChainEventStream(&chaincfg.RegressionNetParams, nil)
	ctxA, cancelA := context.WithCancel(t.Context())
	subA := stream.subscribe(ctxA)
	subB := stream.subscribe(t.Context())

	sharedScript, onlyAScript := "shared-script", "only-a-script"
	sharedOP := wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}
	onlyAOP := wire.OutPoint{Hash: chainhash.Hash{2}, Index: 1}

	_, err := registerWatchKeys(
		ctxA, stream, subA.listener, ctxA.Done(),
		&stream.scriptListeners, &subA.listener.scripts,
		[]string{sharedScript, onlyAScript},
	)
	require.NoError(t, err)
	_, err = registerWatchKeys(
		ctxA, stream, subA.listener, ctxA.Done(),
		&stream.outpointListeners, &subA.listener.outpoints,
		[]wire.OutPoint{sharedOP, onlyAOP},
	)
	require.NoError(t, err)
	_, err = registerWatchKeys(
		t.Context(), stream, subB.listener, t.Context().Done(),
		&stream.scriptListeners, &subB.listener.scripts,
		[]string{sharedScript},
	)
	require.NoError(t, err)
	_, err = registerWatchKeys(
		t.Context(), stream, subB.listener, t.Context().Done(),
		&stream.outpointListeners, &subB.listener.outpoints,
		[]wire.OutPoint{sharedOP},
	)
	require.NoError(t, err)

	// Cancel the first subscription and wait for retirement to complete.
	cancelA()
	waitSubDone(t, subA)

	// Verify subA's exclusive keys were removed, shared keys still map to
	// subB, and subA's listener watch maps were cleared for GC.
	stream.mu.Lock()
	defer stream.mu.Unlock()

	require.ErrorIs(t, subA.Err(), context.Canceled)
	require.Nil(t, subA.listener.scripts)
	require.Nil(t, subA.listener.outpoints)
	require.NotContains(t, stream.scriptListeners, onlyAScript)
	require.NotContains(t, stream.outpointListeners, onlyAOP)
	require.Contains(t, stream.scriptListeners[sharedScript], subB.listener)
	require.NotContains(
		t, stream.scriptListeners[sharedScript], subA.listener,
	)
	require.Contains(t, stream.outpointListeners[sharedOP], subB.listener)
	require.NotContains(
		t, stream.outpointListeners[sharedOP], subA.listener,
	)
}

// TestChainEventSubscriptionOverflowUnindexesWatches verifies that overflowing
// a slow listener retires it with ErrEventSubscriptionBufferFull, unindexes
// its watches immediately, and leaves subsequent publications panic-free.
func TestChainEventSubscriptionOverflowUnindexesWatches(t *testing.T) {
	t.Parallel()

	// Enroll a slow listener with watches and an active fast sibling.
	stream := newChainEventStream(&chaincfg.RegressionNetParams, nil)
	slow := stream.subscribe(t.Context())
	fast := stream.subscribe(t.Context())

	op := wire.OutPoint{Hash: chainhash.Hash{5}, Index: 0}

	_, err := registerWatchKeys(
		t.Context(), stream, slow.listener, t.Context().Done(),
		&stream.scriptListeners, &slow.listener.scripts,
		[]string{"overflow-script"},
	)
	require.NoError(t, err)
	_, err = registerWatchKeys(
		t.Context(), stream, slow.listener, t.Context().Done(),
		&stream.outpointListeners, &slow.listener.outpoints,
		[]wire.OutPoint{op},
	)
	require.NoError(t, err)

	// Overflow slow's block buffer while draining fast, then publish once
	// more.
	for i := range chainEventSubscriberBufferSize + 1 {
		blk := BlockDisconnected{
			Block: wtxmgr.Block{Height: int32(i)},
		}
		stream.publish(blk)

		ev := <-fast.BlockEvents()
		require.Equal(t, EventBlockDisconnected, ev.Type)
		require.Equal(t, int32(i), ev.Block.Height)
	}

	stream.publish(BlockDisconnected{Block: wtxmgr.Block{Height: 999}})

	ev := <-fast.BlockEvents()
	require.Equal(t, int32(999), ev.Block.Height)

	// Assert slow retired with ErrEventSubscriptionBufferFull and released
	// all reverse-index entries and local maps.
	waitSubDone(t, slow)
	require.ErrorIs(t, slow.Err(), ErrEventSubscriptionBufferFull)
	_, err = registerWatchKeys(
		t.Context(), stream, slow.listener, t.Context().Done(),
		&stream.scriptListeners, &slow.listener.scripts,
		[]string{"late-script"},
	)
	require.ErrorIs(t, err, ErrEventSubscriptionBufferFull)

	stream.mu.Lock()
	defer stream.mu.Unlock()

	require.Nil(t, slow.listener.scripts)
	require.Nil(t, slow.listener.outpoints)
	require.Empty(t, stream.scriptListeners)
	require.Empty(t, stream.outpointListeners)
}

// TestChainEventSubscriptionMatchTx verifies single-pass transaction matching:
// empty-index fast path, bare multisig vs P2PKH distinction, received-output
// auto-indexing followed by cross-subscriber spend matching, and unknown-
// outpoint input matching via ComputePkScript.
func TestChainEventSubscriptionMatchTx(t *testing.T) {
	t.Parallel()

	params := &chaincfg.RegressionNetParams

	// Generate two distinct key pairs and build P2PK, P2PKH, P2WPKH, and
	// 1-of-2 bare multisig scripts for testing script matching rules.
	privA, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	privB, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKeyAddrA, err := address.NewAddressPubKey(
		privA.PubKey().SerializeCompressed(), params,
	)
	require.NoError(t, err)
	pubKeyAddrB, err := address.NewAddressPubKey(
		privB.PubKey().SerializeCompressed(), params,
	)
	require.NoError(t, err)

	p2pkhAddrA := pubKeyAddrA.AddressPubKeyHash()
	wpkhAddrA, err := address.NewAddressWitnessPubKeyHash(
		p2pkhAddrA.ScriptAddress(), params,
	)
	require.NoError(t, err)

	p2pkScriptA, err := txscript.PayToAddrScript(pubKeyAddrA)
	require.NoError(t, err)
	p2pkhScriptA, err := txscript.PayToAddrScript(p2pkhAddrA)
	require.NoError(t, err)
	wpkhScriptA, err := txscript.PayToAddrScript(wpkhAddrA)
	require.NoError(t, err)
	multisigScript, err := txscript.MultiSigScript(
		[]*address.AddressPubKey{pubKeyAddrA, pubKeyAddrB}, 1,
	)
	require.NoError(t, err)

	// Verify the empty-index fast path returns nil without errors.
	stream := newChainEventStream(params, nil)
	emptyTx := wire.NewMsgTx(wire.TxVersion)
	emptyTx.AddTxOut(wire.NewTxOut(1000, p2pkhScriptA))
	emptyRec, err := wtxmgr.NewTxRecordFromMsgTx(emptyTx, time.Now())
	require.NoError(t, err)

	stream.mu.Lock()
	require.Nil(t, stream.matchTx(emptyRec))
	stream.mu.Unlock()

	// Enroll three listeners: subP2PK watches P2PK(A), subP2PKH watches
	// P2PKH(A), and subWPKH watches P2WPKH(A).
	subP2PK := stream.subscribe(t.Context())
	subP2PKH := stream.subscribe(t.Context())
	subWPKH := stream.subscribe(t.Context())
	_, err = registerWatchKeys(
		t.Context(), stream, subP2PK.listener, t.Context().Done(),
		&stream.scriptListeners, &subP2PK.listener.scripts,
		[]string{string(p2pkScriptA)},
	)
	require.NoError(t, err)
	_, err = registerWatchKeys(
		t.Context(), stream, subP2PKH.listener, t.Context().Done(),
		&stream.scriptListeners, &subP2PKH.listener.scripts,
		[]string{string(p2pkhScriptA)},
	)
	require.NoError(t, err)
	_, err = registerWatchKeys(
		t.Context(), stream, subWPKH.listener, t.Context().Done(),
		&stream.scriptListeners, &subWPKH.listener.scripts,
		[]string{string(wpkhScriptA)},
	)
	require.NoError(t, err)

	// Match a bare multisig output: only subP2PK matches (not subP2PKH),
	// and the received output outpoint is auto-indexed for subP2PK.
	msTx := wire.NewMsgTx(wire.TxVersion)
	msTx.AddTxOut(wire.NewTxOut(2000, multisigScript))
	msRec, err := wtxmgr.NewTxRecordFromMsgTx(msTx, time.Now())
	require.NoError(t, err)

	stream.mu.Lock()
	msMatched := stream.matchTx(msRec)
	stream.mu.Unlock()
	require.Len(t, msMatched, 1)
	require.Contains(t, msMatched, subP2PK.listener)
	require.NotContains(t, msMatched, subP2PKH.listener)

	// Match a subsequent spend of the auto-indexed multisig outpoint that
	// pays to subP2PKH: both subP2PK (via outpoint) and subP2PKH (via
	// output) match in one pass.
	spendTx := wire.NewMsgTx(wire.TxVersion)
	spendTx.AddTxIn(wire.NewTxIn(
		wire.NewOutPoint(&msRec.Hash, 0), nil, nil,
	))
	spendTx.AddTxOut(wire.NewTxOut(1500, p2pkhScriptA))
	spendRec, err := wtxmgr.NewTxRecordFromMsgTx(spendTx, time.Now())
	require.NoError(t, err)

	stream.mu.Lock()
	spendMatched := stream.matchTx(spendRec)
	stream.mu.Unlock()
	require.Len(t, spendMatched, 2)
	require.Contains(t, spendMatched, subP2PK.listener)
	require.Contains(t, spendMatched, subP2PKH.listener)

	// Match an unknown-outpoint spend whose P2WPKH witness derives
	// wpkhScriptA via ComputePkScript without prior outpoint indexing.
	unknownSpend := wire.NewMsgTx(wire.TxVersion)
	unknownSpend.AddTxIn(wire.NewTxIn(
		wire.NewOutPoint(&chainhash.Hash{9}, 0),
		nil,
		wire.TxWitness{
			[]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01},
			privA.PubKey().SerializeCompressed(),
		},
	))
	unknownRec, err := wtxmgr.NewTxRecordFromMsgTx(unknownSpend, time.Now())
	require.NoError(t, err)

	stream.mu.Lock()
	wpkhMatched := stream.matchTx(unknownRec)
	stream.mu.Unlock()
	require.Len(t, wpkhMatched, 1)
	require.Contains(t, wpkhMatched, subWPKH.listener)
}

// randTestP2PKHAddr generates a random regtest P2PKH address and its pkScript.
func randTestP2PKHAddr(t *testing.T) (address.Address, []byte) {
	t.Helper()

	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pubAddr, err := address.NewAddressPubKey(
		priv.PubKey().SerializeCompressed(),
		&chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	addr := pubAddr.AddressPubKeyHash()
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	return addr, pkScript
}

// TestChainEventSubscriptionWatchRegistration verifies live WatchOutputs
// delegation with synchronous mempool spend delivery, unwatched sibling
// isolation, and post-cancel rejection.
func TestChainEventSubscriptionWatchRegistration(t *testing.T) {
	t.Parallel()

	// Set up an outpoint, a live subscription whose NotifySpent
	// synchronously publishes a spend tx, and an unwatched sibling
	// subscription.
	op := &wire.OutPoint{Hash: chainhash.Hash{11}, Index: 0}
	spendTx := wire.NewMsgTx(wire.TxVersion)
	spendTx.AddTxIn(wire.NewTxIn(op, nil, nil))
	spendRec, err := wtxmgr.NewTxRecordFromMsgTx(spendTx, time.Now())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	stream, mc, watched := newMockWatchSub(ctx)
	unwatched := stream.subscribe(t.Context())

	mc.On("NotifySpent", []*wire.OutPoint{op}).Run(
		func(mock.Arguments) {
			stream.publish(RelevantTx{TxRecord: spendRec})
		},
	).Return(nil).Once()

	// Register on the live handle, publish a barrier for the unwatched
	// sibling, cancel watched, and verify post-cancel rejection.
	liveOutErr := watched.WatchOutputs(ctx, []*wire.OutPoint{op})

	stream.publish(BlockDisconnected{Block: wtxmgr.Block{Height: 9}})

	// WatchOutputs delivers the synchronous spend only to watched.
	require.NoError(t, liveOutErr)

	rec := <-watched.MempoolTxns()
	require.Equal(t, spendRec, rec)
	require.Equal(
		t, EventBlockDisconnected, (<-unwatched.BlockEvents()).Type,
	)

	select {
	case extra := <-unwatched.MempoolTxns():
		require.FailNowf(
			t, "unexpected mempool tx",
			"unwatched received %v", extra.Hash,
		)
	default:
	}

	cancel()
	waitSubDone(t, watched)
	require.ErrorIs(
		t, watched.WatchOutputs(t.Context(), []*wire.OutPoint{op}),
		context.Canceled,
	)
	mc.AssertExpectations(t)
}

// newMockWatchSub creates a regtest stream, mock client, and handle.
func newMockWatchSub(
	ctx context.Context) (*chainEventStream, *mockChainClient,
	EventSubscription) {

	mc := &mockChainClient{}
	stream := newChainEventStream(&chaincfg.RegressionNetParams, mc)
	sub := stream.subscribe(ctx)

	return stream, mc, sub
}

// newExpiredWatchSub creates an already-expired deadline context, mock client,
// and handle.
func newExpiredWatchSub(
	t *testing.T) (context.Context, *mockChainClient, EventSubscription) {

	t.Helper()

	expiredCtx, cancel := context.WithDeadline(
		t.Context(), time.Now().Add(-time.Second),
	)
	t.Cleanup(cancel)

	_, mc, sub := newMockWatchSub(expiredCtx)

	return expiredCtx, mc, sub
}

// TestChainEventSubscriptionWatchAddrsError verifies WatchAddrs rejects nil
// addresses and expired deadline contexts without invoking the backend client.
func TestChainEventSubscriptionWatchAddrsError(t *testing.T) {
	t.Parallel()

	// Set up an active subscription for invalid-input checks and an
	// already-expired deadline subscription for deadline preservation.
	_, mcLive, liveSub := newMockWatchSub(t.Context())
	expiredCtx, mcExpired, expiredSub := newExpiredWatchSub(t)

	// Attempt both invalid WatchAddrs registrations.
	nilErr := liveSub.WatchAddrs(t.Context(), []address.Address{nil})
	deadlineErr := expiredSub.WatchAddrs(expiredCtx, nil)

	// Confirm expected errors are returned without any backend calls.
	require.ErrorIs(t, nilErr, ErrInvalidParam)
	require.ErrorIs(t, deadlineErr, context.DeadlineExceeded)
	mcLive.AssertExpectations(t)
	mcExpired.AssertExpectations(t)
}

// TestChainEventSubscriptionWatchOutputsError verifies WatchOutputs rejects
// nil outpoints and expired deadline contexts without invoking the backend.
func TestChainEventSubscriptionWatchOutputsError(t *testing.T) {
	t.Parallel()

	// Set up an active subscription for nil-outpoint validation and an
	// already-expired deadline subscription for deadline preservation.
	_, mcLive, liveSub := newMockWatchSub(t.Context())
	expiredCtx, mcExpired, expiredSub := newExpiredWatchSub(t)

	// Attempt both invalid WatchOutputs registrations.
	nilErr := liveSub.WatchOutputs(t.Context(), []*wire.OutPoint{nil})
	deadlineErr := expiredSub.WatchOutputs(expiredCtx, nil)

	// Confirm expected errors are returned without invoking NotifySpent.
	require.ErrorIs(t, nilErr, ErrInvalidParam)
	require.ErrorIs(t, deadlineErr, context.DeadlineExceeded)
	mcLive.AssertExpectations(t)
	mcExpired.AssertExpectations(t)
}

// TestChainEventSubscriptionWatchRollbackError verifies that a failed
// WatchAddrs or WatchOutputs withdraws only the failed registration's newly
// added keys while preserving pre-existing watches and sibling delivery.
func TestChainEventSubscriptionWatchRollbackError(t *testing.T) {
	t.Parallel()

	// Enroll subFail with pre-existing watches (keepAddr, keepOP) and an
	// independent sibling subOK that will succeed for failAddr and failOP.
	keepAddr, keepScript := randTestP2PKHAddr(t)
	failAddr, failScript := randTestP2PKHAddr(t)
	keepOP := &wire.OutPoint{Hash: chainhash.Hash{41}, Index: 0}
	failOP := &wire.OutPoint{Hash: chainhash.Hash{42}, Index: 1}
	regErr := errors.New("backend registration failed")

	stream, mc, subFail := newMockWatchSub(t.Context())
	subOK := stream.subscribe(t.Context())

	mc.On("WatchAddrsFromTip",
		mock.Anything, []address.Address{keepAddr},
	).Return(nil).Once()
	mc.On("NotifySpent", []*wire.OutPoint{keepOP}).Return(nil).Once()
	mc.On("WatchAddrsFromTip",
		mock.Anything, []address.Address{keepAddr, failAddr},
	).Return(regErr).Once()
	mc.On("NotifySpent",
		[]*wire.OutPoint{keepOP, failOP},
	).Return(regErr).Once()
	mc.On("WatchAddrsFromTip",
		mock.Anything, []address.Address{failAddr},
	).Return(nil).Once()
	mc.On("NotifySpent", []*wire.OutPoint{failOP}).Return(nil).Once()

	require.NoError(
		t, subFail.WatchAddrs(t.Context(), []address.Address{keepAddr}),
	)
	require.NoError(
		t, subFail.WatchOutputs(t.Context(), []*wire.OutPoint{keepOP}),
	)

	makeTx := func(txOut *wire.TxOut, txIn *wire.TxIn) *wtxmgr.TxRecord {
		tx := wire.NewMsgTx(wire.TxVersion)
		if txIn != nil {
			tx.AddTxIn(txIn)
		}

		if txOut != nil {
			tx.AddTxOut(txOut)
		}

		rec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
		require.NoError(t, err)

		return rec
	}
	failAddrRec := makeTx(wire.NewTxOut(1100, failScript), nil)
	failOPRec := makeTx(nil, wire.NewTxIn(failOP, nil, nil))
	keepAddrRec := makeTx(wire.NewTxOut(1200, keepScript), nil)
	keepOPRec := makeTx(nil, wire.NewTxIn(keepOP, nil, nil))

	// Fail overlapping registrations on subFail while succeeding on subOK,
	// then publish matching txns followed by a disconnect barrier.
	addrErr := subFail.WatchAddrs(
		t.Context(), []address.Address{keepAddr, failAddr},
	)
	outErr := subFail.WatchOutputs(
		t.Context(), []*wire.OutPoint{keepOP, failOP},
	)
	require.NoError(
		t, subOK.WatchAddrs(t.Context(), []address.Address{failAddr}),
	)
	require.NoError(
		t, subOK.WatchOutputs(t.Context(), []*wire.OutPoint{failOP}),
	)

	stream.publish(RelevantTx{TxRecord: failAddrRec})
	stream.publish(RelevantTx{TxRecord: failOPRec})
	stream.publish(RelevantTx{TxRecord: keepAddrRec})
	stream.publish(RelevantTx{TxRecord: keepOPRec})
	stream.publish(BlockDisconnected{Block: wtxmgr.Block{Height: 8}})

	// Confirm the failed calls surfaced regErr, subOK received only failAddr
	// and failOP txns, and subFail kept receiving keepAddr and keepOP txns.
	require.ErrorIs(t, addrErr, regErr)
	require.ErrorIs(t, outErr, regErr)

	require.Equal(t, failAddrRec, waitMempoolTx(t, subOK.MempoolTxns()))
	require.Equal(t, failOPRec, waitMempoolTx(t, subOK.MempoolTxns()))
	require.Empty(t, subOK.MempoolTxns())

	okBarrier := waitChainEvent(t, subOK.BlockEvents())
	require.Equal(t, EventBlockDisconnected, okBarrier.Type)

	require.Equal(t, keepAddrRec, waitMempoolTx(t, subFail.MempoolTxns()))
	require.Equal(t, keepOPRec, waitMempoolTx(t, subFail.MempoolTxns()))
	require.Empty(t, subFail.MempoolTxns())

	failBarrier := waitChainEvent(t, subFail.BlockEvents())
	require.Equal(t, EventBlockDisconnected, failBarrier.Type)
	mc.AssertExpectations(t)
}

// TestChainEventSubscriptionAutoWatchRollbackError verifies that a received
// output auto-indexed during a failing WatchOutputs call retains its own
// watch reference after rollback so subsequent spends still deliver.
func TestChainEventSubscriptionAutoWatchRollbackError(t *testing.T) {
	t.Parallel()

	// Set up a Taproot watched address whose key-path spends carry only a
	// 64-byte witness, plus a funding outpoint whose NotifySpent fails after
	// synchronously delivering the funding tx.
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	tapAddr, err := address.NewAddressTaproot(
		priv.PubKey().SerializeCompressed()[1:],
		&chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)
	tapScript, err := txscript.PayToAddrScript(tapAddr)
	require.NoError(t, err)

	stream, mc, watched := newMockWatchSub(t.Context())
	mc.On("WatchAddrsFromTip",
		mock.Anything, []address.Address{tapAddr},
	).Return(nil).Once()
	require.NoError(
		t, watched.WatchAddrs(t.Context(), []address.Address{tapAddr}),
	)

	fundTx := wire.NewMsgTx(wire.TxVersion)
	fundTx.AddTxOut(wire.NewTxOut(5000, tapScript))
	fundRec, err := wtxmgr.NewTxRecordFromMsgTx(fundTx, time.Now())
	require.NoError(t, err)

	fundOP := wire.OutPoint{Hash: fundRec.Hash, Index: 0}

	spendTx := wire.NewMsgTx(wire.TxVersion)
	spendTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: fundOP,
		Witness:          wire.TxWitness{make([]byte, 64)},
	})
	spendRec, err := wtxmgr.NewTxRecordFromMsgTx(spendTx, time.Now())
	require.NoError(t, err)

	regErr := errors.New("backend NotifySpent failed")
	mc.On("NotifySpent", []*wire.OutPoint{&fundOP}).Run(
		func(mock.Arguments) {
			stream.publish(RelevantTx{TxRecord: fundRec})
		},
	).Return(regErr).Once()

	// Fail WatchOutputs on fundOP, then publish the Taproot key-path spend
	// and a disconnect barrier.
	watchErr := watched.WatchOutputs(t.Context(), []*wire.OutPoint{&fundOP})

	stream.publish(RelevantTx{TxRecord: spendRec})
	stream.publish(BlockDisconnected{Block: wtxmgr.Block{Height: 11}})

	// Confirm the failed call returned regErr while the auto-indexed
	// outpoint survived rollback and delivered the subsequent spend.
	require.ErrorIs(t, watchErr, regErr)

	require.Equal(t, fundRec, waitMempoolTx(t, watched.MempoolTxns()))
	require.Equal(t, spendRec, waitMempoolTx(t, watched.MempoolTxns()))

	barrierEv := waitChainEvent(t, watched.BlockEvents())
	require.Equal(t, EventBlockDisconnected, barrierEv.Type)
	mc.AssertExpectations(t)
}

// TestChainEventSubscriptionWatchConcurrentClose verifies concurrent
// WatchAddrs, WatchOutputs, and stream close calls do not race on index fields
// during registration or rollback.
func TestChainEventSubscriptionWatchConcurrentClose(t *testing.T) {
	t.Parallel()

	// Set up a live subscription whose backend rejects watch calls so both
	// registration and rollback paths overlap stream.close().
	addr, _ := randTestP2PKHAddr(t)
	op := &wire.OutPoint{Hash: chainhash.Hash{51}, Index: 0}
	regErr := errors.New("backend closed")

	stream, mc, sub := newMockWatchSub(t.Context())
	mc.On(
		"WatchAddrsFromTip", mock.Anything, []address.Address{addr},
	).Return(regErr).Maybe()
	mc.On("NotifySpent", []*wire.OutPoint{op}).Return(regErr).Maybe()

	start := make(chan struct{})
	errs := make(chan error, 2)
	closed := make(chan struct{})

	// Release WatchAddrs, WatchOutputs, and stream.close() simultaneously.
	go func() {
		<-start

		errs <- sub.WatchAddrs(t.Context(), []address.Address{addr})
	}()
	go func() {
		<-start

		errs <- sub.WatchOutputs(t.Context(), []*wire.OutPoint{op})
	}()
	go func() {
		<-start
		stream.close()
		close(closed)
	}()

	close(start)
	<-closed

	// Confirm both watch calls terminated with Canceled or regErr cleanly.
	for range 2 {
		err := <-errs
		require.True(
			t, errors.Is(err, context.Canceled) ||
				errors.Is(err, regErr),
		)
	}
}

// TestChainEventSubscriptionMempoolTx verifies unconfirmed RelevantTx delivers
// on MempoolTxns only to matched listeners while confirmed RelevantTx is
// ignored on EventSubscription.
func TestChainEventSubscriptionMempoolTx(t *testing.T) {
	t.Parallel()

	// Set up a watched subscription, an unwatched sibling, and two
	// distinct txns paying to the watched address so a leaked confirmed tx
	// cannot masquerade as the unconfirmed mempool tx.
	addrA, scriptA := randTestP2PKHAddr(t)
	stream, mc, watched := newMockWatchSub(t.Context())
	mc.On(
		"WatchAddrsFromTip", mock.Anything, []address.Address{addrA},
	).Return(nil).Once()

	unwatched := stream.subscribe(t.Context())
	require.NoError(
		t, watched.WatchAddrs(t.Context(), []address.Address{addrA}),
	)

	confirmedTx := wire.NewMsgTx(wire.TxVersion)
	confirmedTx.AddTxOut(wire.NewTxOut(1000, scriptA))
	confirmedRec, err := wtxmgr.NewTxRecordFromMsgTx(
		confirmedTx, time.Now(),
	)
	require.NoError(t, err)

	mempoolTx := wire.NewMsgTx(wire.TxVersion)
	mempoolTx.AddTxOut(wire.NewTxOut(2000, scriptA))
	mempoolRec, err := wtxmgr.NewTxRecordFromMsgTx(mempoolTx, time.Now())
	require.NoError(t, err)

	// Publish the confirmed RelevantTx, the unconfirmed RelevantTx, and a
	// block-disconnect barrier.
	stream.publish(RelevantTx{
		TxRecord: confirmedRec,
		Block:    &wtxmgr.BlockMeta{Block: wtxmgr.Block{Height: 1}},
	})
	stream.publish(RelevantTx{TxRecord: mempoolRec, Block: nil})
	stream.publish(BlockDisconnected{Block: wtxmgr.Block{Height: 2}})

	// Confirm watched receives only the unconfirmed mempool tx on
	// MempoolTxns and the disconnect barrier on BlockEvents, while
	// unwatched receives nothing on MempoolTxns.
	require.Equal(t, mempoolRec, <-watched.MempoolTxns())
	require.Empty(t, watched.MempoolTxns())
	require.Empty(t, unwatched.MempoolTxns())

	barrier := <-watched.BlockEvents()
	require.Equal(t, EventBlockDisconnected, barrier.Type)
	require.Equal(t, int32(2), barrier.Block.Height)
	require.Equal(
		t, EventBlockDisconnected, (<-unwatched.BlockEvents()).Type,
	)
	mc.AssertExpectations(t)
}

// TestChainEventSubscriptionBlockEvents verifies FilteredBlockConnected
// scoping (including same-block parent-to-child spends without mutating the
// input slice), BlockDisconnected delivery, and suppression of legacy markers.
func TestChainEventSubscriptionBlockEvents(t *testing.T) {
	t.Parallel()

	// Enroll watched and unwatched subscriptions and build a block
	// containing a watched parent, an unrelated tx, and a child spending
	// the parent's output.
	addrA, scriptA := randTestP2PKHAddr(t)
	_, scriptOther := randTestP2PKHAddr(t)
	stream, mc, watched := newMockWatchSub(t.Context())
	mc.On(
		"WatchAddrsFromTip", mock.Anything, []address.Address{addrA},
	).Return(nil).Once()

	unwatched := stream.subscribe(t.Context())
	require.NoError(
		t, watched.WatchAddrs(t.Context(), []address.Address{addrA}),
	)

	makeRec := func(tx *wire.MsgTx) *wtxmgr.TxRecord {
		rec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
		require.NoError(t, err)

		return rec
	}
	parent := wire.NewMsgTx(wire.TxVersion)
	parent.AddTxOut(wire.NewTxOut(5000, scriptA))
	parentRec := makeRec(parent)

	unrelated := wire.NewMsgTx(wire.TxVersion)
	unrelated.AddTxOut(wire.NewTxOut(1000, scriptOther))
	unrelatedRec := makeRec(unrelated)

	child := wire.NewMsgTx(wire.TxVersion)
	child.AddTxIn(wire.NewTxIn(
		wire.NewOutPoint(&parentRec.Hash, 0), nil, nil,
	))
	child.AddTxOut(wire.NewTxOut(4000, scriptOther))
	childRec := makeRec(child)

	origSlice := []*wtxmgr.TxRecord{parentRec, unrelatedRec, childRec}
	blk := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Hash: chainhash.Hash{22}, Height: 5},
	}

	// Publish suppressed legacy markers, the filtered block, and a block
	// disconnect.
	stream.publish(ClientConnected{})
	stream.publish(BlockConnected(*blk))
	stream.publish(&RescanProgress{Hash: blk.Hash, Height: blk.Height})
	stream.publish(FilteredBlockConnected{
		Block: blk, RelevantTxs: origSlice,
	})
	stream.publish(BlockDisconnected(*blk))

	// Confirm watched receives only parent and child in block order without
	// mutating origSlice, unwatched receives an empty block, the
	// disconnect follows, and MempoolTxns stays empty.
	wBlk := <-watched.BlockEvents()
	require.Equal(t, EventBlockConnected, wBlk.Type)
	require.Equal(t, blk, wBlk.Block)
	require.Equal(
		t, []*wtxmgr.TxRecord{parentRec, childRec}, wBlk.RelevantTxs,
	)
	require.Equal(
		t, []*wtxmgr.TxRecord{parentRec, unrelatedRec, childRec},
		origSlice,
	)

	uBlk := <-unwatched.BlockEvents()
	require.Equal(t, EventBlockConnected, uBlk.Type)
	require.Nil(t, uBlk.RelevantTxs)

	wDisc := <-watched.BlockEvents()
	require.Equal(t, EventBlockDisconnected, wDisc.Type)
	require.Equal(t, blk.Hash, wDisc.Block.Hash)
	require.Empty(t, watched.MempoolTxns())
	require.Empty(t, unwatched.MempoolTxns())
	require.Equal(t, EventUnknown, Event{}.Type)
	mc.AssertExpectations(t)
}

// TestBitcoindScopedWatch verifies BitcoindClient scopes mempool RelevantTx
// and FilteredBlockConnected delivery to watched subscriptions and keeps
// unwatched siblings isolated.
func TestBitcoindScopedWatch(t *testing.T) {
	t.Parallel()

	// Start a BitcoindClient fixture configured for regtest with block
	// notifications enabled and enroll watched and unwatched subscriptions.
	client := newBitcoindStartupTestClient(t, nil)
	client.chainConn.cfg.ChainParams = &chaincfg.RegressionNetParams
	client.chainConn.events = &bitcoindRPCPollingEvents{
		mempool: newMempool(&mempoolConfig{}),
	}
	require.NoError(t, client.Start(t.Context()))
	atomic.StoreUint32(&client.notifyBlocks, 1)

	addr, pkScript := randTestP2PKHAddr(t)
	scopedOP := &wire.OutPoint{Hash: chainhash.Hash{77}, Index: 0}
	watched := client.SubscribeChainEvents(t.Context())
	unwatched := client.SubscribeChainEvents(t.Context())
	require.NoError(
		t, watched.WatchAddrs(t.Context(), []address.Address{addr}),
	)
	require.NoError(
		t, watched.WatchOutputs(t.Context(), []*wire.OutPoint{scopedOP}),
	)

	// Drive a mempool tx through filterTx followed by a block containing a
	// fresh scoped address tx and a scoped outpoint spend.
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxOut(wire.NewTxOut(2500, pkScript))
	_, rec, err := client.filterTx(btcutil.NewTx(tx), nil, true)
	require.NoError(t, err)

	blockTx := wire.NewMsgTx(wire.TxVersion)
	blockTx.AddTxOut(wire.NewTxOut(3500, pkScript))
	spendTx := wire.NewMsgTx(wire.TxVersion)
	spendTx.AddTxIn(wire.NewTxIn(scopedOP, nil, nil))
	block := &wire.MsgBlock{
		Header: wire.BlockHeader{Timestamp: time.Now()},
		Transactions: []*wire.MsgTx{
			blockTx,
			spendTx,
		},
	}
	client.filterBlock(block, 10, true)

	// Watched receives the mempool tx on MempoolTxns and the connected
	// block with blockTx and spendTx on BlockEvents; unwatched receives
	// only the empty connected block and no mempool txns.
	memRec := waitMempoolTx(t, watched.MempoolTxns())
	require.Equal(t, rec.Hash, memRec.Hash)

	wBlk := waitChainEvent(t, watched.BlockEvents())
	require.Equal(t, EventBlockConnected, wBlk.Type)
	require.Equal(t, int32(10), wBlk.Block.Height)
	require.Len(t, wBlk.RelevantTxs, 2)
	require.Equal(t, blockTx.TxHash(), wBlk.RelevantTxs[0].Hash)
	require.Equal(t, spendTx.TxHash(), wBlk.RelevantTxs[1].Hash)

	uBlk := waitChainEvent(t, unwatched.BlockEvents())
	require.Equal(t, EventBlockConnected, uBlk.Type)
	require.Equal(t, int32(10), uBlk.Block.Height)
	require.Empty(t, uBlk.RelevantTxs)
	require.Empty(t, unwatched.MempoolTxns())
}

// waitLegacyNotification reads the next legacy notification or fails on
// timeout.
func waitLegacyNotification(t *testing.T, ch <-chan any) any {
	t.Helper()

	select {
	case n, ok := <-ch:
		require.True(t, ok, "unexpected closed legacy channel")
		return n
	case <-time.After(defaultTestTimeout):
		require.FailNow(t, "timed out waiting for legacy notification")
		return nil
	}
}

// TestBitcoindClientLegacyQueueBoundedUntilNotifications verifies that
// BitcoindClient caps unread legacy notifications at legacyPreActivationCap
// while delivering SubscribeChainEvents past the cap, and activates unbounded
// FIFO overflow once Notifications() is called.
func TestBitcoindClientLegacyQueueBoundedUntilNotifications(t *testing.T) {
	t.Parallel()

	// Arrange: start a BitcoindClient with block notifications enabled and
	// enroll a scoped subscriber without calling Notifications().
	client := newBitcoindStartupTestClient(t, nil)
	require.NoError(t, client.Start(t.Context()))
	atomic.StoreUint32(&client.notifyBlocks, 1)

	sub := client.SubscribeChainEvents(t.Context())
	burst := legacyPreActivationCap + 5

	// Act: emit a burst exceeding legacyPreActivationCap while unactivated,
	// send one distinct fence marker on unbuffered intake so the queue
	// finishes the burst before activation, then open Notifications() and
	// emit a sentinel plus a post-activation burst.
	for i := int32(1); i <= int32(burst); i++ {
		hash := chainhash.Hash{byte(i)}
		client.onBlockDisconnected(&hash, i, time.Time{})

		ev := waitChainEvent(t, sub.BlockEvents())
		require.Equal(t, EventBlockDisconnected, ev.Type)
		require.Equal(t, i, ev.Block.Height)
	}

	const fenceHeight int32 = -1

	var fence BlockConnected

	fence.Height = fenceHeight
	client.enqueueNotification(fence)

	legacy := client.Notifications()

	const sentinelHeight int32 = 100

	sentinelHash := chainhash.Hash{byte(sentinelHeight)}
	client.onBlockDisconnected(&sentinelHash, sentinelHeight, time.Time{})
	waitChainEvent(t, sub.BlockEvents())

	for i := int32(1); i <= int32(burst); i++ {
		h := sentinelHeight + i
		hash := chainhash.Hash{byte(h)}
		client.onBlockDisconnected(&hash, h, time.Time{})
		waitChainEvent(t, sub.BlockEvents())
	}

	// Assert: ClientConnected and 19 prefix items precede the sentinel
	// (ignoring the distinct fence marker if its own admission straddled
	// activation), followed by every post-activation event in FIFO order.
	require.IsType(t, ClientConnected{}, waitLegacyNotification(t, legacy))

	for i := int32(1); i < int32(legacyPreActivationCap); i++ {
		disc, ok := waitLegacyNotification(t, legacy).(BlockDisconnected)
		require.True(t, ok, "expected prefix BlockDisconnected")
		require.Equal(t, i, disc.Height)
	}

	nextNtfn := waitLegacyNotification(t, legacy)
	if blk, ok := nextNtfn.(BlockConnected); ok &&
		blk.Height == fenceHeight {

		nextNtfn = waitLegacyNotification(t, legacy)
	}

	sentinel, ok := nextNtfn.(BlockDisconnected)
	require.True(t, ok, "expected sentinel BlockDisconnected")
	require.Equal(t, sentinelHeight, sentinel.Height)

	for i := int32(1); i <= int32(burst); i++ {
		disc, ok := waitLegacyNotification(t, legacy).(BlockDisconnected)
		require.True(t, ok, "expected post-activation BlockDisconnected")
		require.Equal(t, sentinelHeight+i, disc.Height)
	}
}

// TestBitcoindClientRescanActivatesLegacyQueue verifies that calling
// BitcoindClient.Rescan before Notifications() activates lossless legacy
// delivery so RescanFinished survives a full pre-activation startup prefix.
func TestBitcoindClientRescanActivatesLegacyQueue(t *testing.T) {
	t.Parallel()

	// Arrange: start a BitcoindClient without opening Notifications(),
	// fill the 20-item startup prefix, and hand off a distinct fence
	// marker on unbuffered intake before activation.
	client := newBitcoindStartupTestClient(t, nil)
	require.NoError(t, client.Start(t.Context()))
	atomic.StoreUint32(&client.notifyBlocks, 1)

	sub := client.SubscribeChainEvents(t.Context())
	for i := int32(1); i <= int32(legacyPreActivationCap); i++ {
		hash := chainhash.Hash{byte(i)}
		client.onBlockDisconnected(&hash, i, time.Time{})
		waitChainEvent(t, sub.BlockEvents())
	}

	const fenceHeight int32 = -1

	var fence BlockConnected

	fence.Height = fenceHeight
	client.enqueueNotification(fence)

	tip, err := client.BlockStamp()
	require.NoError(t, err)

	// Act: invoke Rescan at the tip before opening Notifications(), check
	// the atomic activation flag immediately, then open Notifications().
	require.NoError(t, client.Rescan(&tip.Hash, nil, nil))
	require.True(t, client.legacyNotificationsActive.Load())

	legacy := client.Notifications()

	// Assert: the 20-item startup prefix (ignoring the distinct fence
	// marker if it straddled activation) is followed by RescanFinished.
	require.IsType(t, ClientConnected{}, waitLegacyNotification(t, legacy))

	for i := int32(1); i < int32(legacyPreActivationCap); i++ {
		disc, ok := waitLegacyNotification(t, legacy).(BlockDisconnected)
		require.True(t, ok, "expected prefix BlockDisconnected")
		require.Equal(t, i, disc.Height)
	}

	nextNtfn := waitLegacyNotification(t, legacy)
	if blk, ok := nextNtfn.(BlockConnected); ok &&
		blk.Height == fenceHeight {

		nextNtfn = waitLegacyNotification(t, legacy)
	}

	fin, ok := nextNtfn.(*RescanFinished)
	require.True(t, ok, "expected *RescanFinished")
	require.Equal(t, &tip.Hash, fin.Hash)
}

// TestChainEventSubscriptionMempoolDropOnFull verifies that filling a slow
// subscriber's MempoolTxns buffer drops excess mempool tx notifications
// without retiring the subscription, blocking BlockEvents, affecting a fast
// sibling, or skipping received-output auto-indexing.
func TestChainEventSubscriptionMempoolDropOnFull(t *testing.T) {
	t.Parallel()

	// Arrange: enroll slow and fast subscribers watching a Taproot address
	// whose key-path spends carry only a 64-byte witness so spend matching
	// relies exclusively on received-output auto-indexing.
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	tapAddr, err := address.NewAddressTaproot(
		priv.PubKey().SerializeCompressed()[1:],
		&chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)
	tapScript, err := txscript.PayToAddrScript(tapAddr)
	require.NoError(t, err)

	stream, mc, slow := newMockWatchSub(t.Context())
	fast := stream.subscribe(t.Context())

	mc.On(
		"WatchAddrsFromTip", mock.Anything, []address.Address{tapAddr},
	).Return(nil).Twice()

	require.NoError(
		t, slow.WatchAddrs(t.Context(), []address.Address{tapAddr}),
	)
	require.NoError(
		t, fast.WatchAddrs(t.Context(), []address.Address{tapAddr}),
	)

	capacity := cap(slow.MempoolTxns())
	require.Equal(t, chainMempoolSubscriberBufferSize, capacity)

	makeFundingTx := func(val int64) *wtxmgr.TxRecord {
		tx := wire.NewMsgTx(wire.TxVersion)
		tx.AddTxOut(wire.NewTxOut(val, tapScript))
		rec, recErr := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
		require.NoError(t, recErr)

		return rec
	}

	// Act: fill slow's MempoolTxns buffer while draining fast, then publish
	// an additional funding tx that overflows slow's MempoolTxns buffer,
	// followed by a block disconnect and a connected block spending the
	// dropped funding tx's output via a Taproot key-path input.
	accepted := make([]*wtxmgr.TxRecord, capacity)
	for i := range capacity {
		rec := makeFundingTx(int64(1000 + i))
		accepted[i] = rec
		stream.publish(RelevantTx{TxRecord: rec})
		require.Equal(t, rec, waitMempoolTx(t, fast.MempoolTxns()))
	}

	droppedFundRec := makeFundingTx(99999)
	stream.publish(RelevantTx{TxRecord: droppedFundRec})
	require.Equal(t, droppedFundRec, waitMempoolTx(t, fast.MempoolTxns()))

	droppedOP := wire.OutPoint{Hash: droppedFundRec.Hash, Index: 0}
	spendTx := wire.NewMsgTx(wire.TxVersion)
	spendTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: droppedOP,
		Witness:          wire.TxWitness{make([]byte, 64)},
	})
	spendRec, err := wtxmgr.NewTxRecordFromMsgTx(spendTx, time.Now())
	require.NoError(t, err)

	blk := &wtxmgr.BlockMeta{Hash: chainhash.Hash{88}, Height: 12}
	stream.publish(BlockDisconnected{Height: 11})
	stream.publish(FilteredBlockConnected{
		Block:       blk,
		RelevantTxs: []*wtxmgr.TxRecord{spendRec},
	})

	// Assert: slow stayed active with no error and received both block
	// events including the spend of the dropped funding tx's output.
	select {
	case <-slow.Done():
		require.FailNow(t, "full MempoolTxns retired subscription")
	default:
	}

	require.NoError(t, slow.Err())

	discEv := waitChainEvent(t, slow.BlockEvents())
	require.Equal(t, EventBlockDisconnected, discEv.Type)
	require.Equal(t, int32(11), discEv.Block.Height)

	connEv := waitChainEvent(t, slow.BlockEvents())
	require.Equal(t, EventBlockConnected, connEv.Type)
	require.Equal(t, blk, connEv.Block)
	require.Equal(t, []*wtxmgr.TxRecord{spendRec}, connEv.RelevantTxs)

	// Drain slow's MempoolTxns to verify strictly the initial accepted
	// prefix was retained (without droppedFundRec), then publish a new
	// mempool tx to verify delivery resumes once space frees up.
	for _, want := range accepted {
		require.Equal(t, want, waitMempoolTx(t, slow.MempoolTxns()))
	}

	require.Empty(t, slow.MempoolTxns())

	afterDrainRec := makeFundingTx(77777)
	stream.publish(RelevantTx{TxRecord: afterDrainRec})
	require.Equal(t, afterDrainRec, waitMempoolTx(t, slow.MempoolTxns()))
	require.Equal(t, afterDrainRec, waitMempoolTx(t, fast.MempoolTxns()))
	mc.AssertExpectations(t)
}

// drainClosedChan non-blockingly drains all buffered items from ch and
// verifies ch was already closed before the caller observed Done.
func drainClosedChan[T any](t *testing.T, ch <-chan T, name string) []T {
	t.Helper()

	var items []T

	for {
		select {
		case item, ok := <-ch:
			if !ok {
				return items
			}

			items = append(items, item)
		default:
			require.FailNowf(
				t, "channel not closed",
				"%s was not closed before Done", name,
			)
		}
	}
}

// TestChainEventSubscriptionCancel verifies direct EventSubscription.Cancel
// semantics: immediate synchronous channel closure, idempotent concurrent use,
// context.AfterFunc unregistration, watch unregistration, post-cancel watch
// rejection, and Err distinguishing cancellation from source shutdown and
// block overflow.
func TestChainEventSubscriptionCancel(t *testing.T) {
	t.Parallel()

	t.Run("direct cancel and watch cleanup", func(t *testing.T) {
		t.Parallel()

		// Arrange: enroll a live subscription with address and outpoint
		// watches while leaving parentCtx live, and buffer one mempool
		// tx plus one block disconnect before canceling.
		parentCtx, parentCancel := context.WithCancel(t.Context())
		defer parentCancel()

		addr, pkScript := randTestP2PKHAddr(t)
		op := wire.OutPoint{Hash: chainhash.Hash{0x62}, Index: 1}

		mc := &mockChainClient{}
		stream := newChainEventStream(
			&chaincfg.RegressionNetParams, mc,
		)
		sub := stream.subscribe(parentCtx)

		stream.mu.Lock()
		stopAfterFunc := stream.members[sub.listener]
		stream.mu.Unlock()
		require.NotNil(t, stopAfterFunc)

		mc.On(
			"WatchAddrsFromTip", mock.Anything,
			[]address.Address{addr},
		).Return(nil).Once()
		mc.On("NotifySpent", []*wire.OutPoint{&op}).Return(nil).Once()

		require.NoError(
			t, sub.WatchAddrs(t.Context(), []address.Address{addr}),
		)
		require.NoError(
			t, sub.WatchOutputs(t.Context(), []*wire.OutPoint{&op}),
		)

		tx := wire.NewMsgTx(wire.TxVersion)
		tx.AddTxOut(wire.NewTxOut(2500, pkScript))
		rec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
		require.NoError(t, err)

		stream.publish(RelevantTx{TxRecord: rec})
		stream.publish(BlockDisconnected{Height: 7})

		// Act: invoke Cancel concurrently from multiple goroutines and
		// again sequentially to prove concurrency safety and
		// idempotency while parentCtx remains uncanceled.
		const callers = 8

		start := make(chan struct{})

		var wg sync.WaitGroup

		for range callers {
			wg.Go(func() {
				<-start
				sub.Cancel()
			})
		}

		close(start)
		wg.Wait()
		sub.Cancel()

		// Assert: Done, BlockEvents, and MempoolTxns are immediately
		// closed, buffered items remain readable, Err reports
		// context.Canceled, and context.AfterFunc is unregistered.
		select {
		case <-sub.Done():
		default:
			require.FailNow(t, "Cancel did not close Done")
		}

		require.ErrorIs(t, sub.Err(), context.Canceled)
		require.NoError(t, parentCtx.Err())
		require.False(t, stopAfterFunc())

		blocks := drainClosedChan(t, sub.BlockEvents(), "BlockEvents")
		require.Len(t, blocks, 1)
		mempool := drainClosedChan(t, sub.MempoolTxns(), "MempoolTxns")
		require.Equal(t, []*wtxmgr.TxRecord{rec}, mempool)

		// Verify watch indices and membership were cleared on Cancel.
		stream.mu.Lock()
		require.Empty(t, stream.members)
		require.Empty(t, stream.scriptListeners)
		require.Empty(t, stream.outpointListeners)
		stream.mu.Unlock()

		// Verify post-cancel WatchAddrs and WatchOutputs fail with
		// context.Canceled without invoking backend client mocks.
		err = sub.WatchAddrs(t.Context(), []address.Address{addr})
		require.ErrorIs(t, err, context.Canceled)
		err = sub.WatchOutputs(t.Context(), []*wire.OutPoint{&op})
		require.ErrorIs(t, err, context.Canceled)

		// Canceling parentCtx and closing the stream afterward must
		// keep sub.Err() at context.Canceled.
		parentCancel()
		stream.close()
		require.ErrorIs(t, sub.Err(), context.Canceled)
		mc.AssertExpectations(t)
	})

	t.Run("cancel preserves prior terminal result", func(t *testing.T) {
		t.Parallel()

		// Arrange: terminate three subscriptions via source shutdown,
		// BlockEvents overflow, and parent deadline expiry before
		// calling Cancel.
		shutdownStream := newChainEventStream(
			&chaincfg.RegressionNetParams, &mockChainClient{},
		)
		shutdownSub := shutdownStream.subscribe(t.Context())
		shutdownStream.close()
		waitSubDone(t, shutdownSub)

		overflowStream := newChainEventStream(
			&chaincfg.RegressionNetParams, &mockChainClient{},
		)
		overflowSub := overflowStream.subscribe(t.Context())

		overflowCount := int32(chainEventSubscriberBufferSize) + 1
		for i := int32(1); i <= overflowCount; i++ {
			overflowStream.publish(BlockDisconnected{Height: i})
		}

		waitSubDone(t, overflowSub)

		deadlineCtx, cancelDeadline := context.WithDeadline(
			t.Context(), time.Now().Add(-time.Second),
		)
		defer cancelDeadline()

		deadlineStream := newChainEventStream(
			&chaincfg.RegressionNetParams, &mockChainClient{},
		)
		deadlineSub := deadlineStream.subscribe(deadlineCtx)
		waitSubDone(t, deadlineSub)

		// Act: invoke Cancel on every already-terminated subscription.
		shutdownSub.Cancel()
		overflowSub.Cancel()
		deadlineSub.Cancel()

		// Assert: each subscription preserves its original terminal
		// result so callers distinguish shutdown, overflow, and cancel.
		require.NoError(t, shutdownSub.Err())
		require.ErrorIs(
			t, overflowSub.Err(), ErrEventSubscriptionBufferFull,
		)
		require.ErrorIs(t, deadlineSub.Err(), context.DeadlineExceeded)
	})
}
