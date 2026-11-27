package chain

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
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

// TestRPCClientSubscriptionLifecycle checks live delivery, cancellation, and
// shutdown through btcd's native filtered notification handler.
func TestRPCClientSubscriptionLifecycle(t *testing.T) {
	t.Parallel()

	// Arrange a live client opted into block notifications and a
	// cancellable subscription.
	miner, client := setupBtcd(t)
	require.NoError(t, client.NotifyBlocks())

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	sub := client.SubscribeChainEvents(ctx)
	_, startHeight, err := miner.Client.GetBestBlock()
	require.NoError(t, err)

	wantHeight := startHeight + 1

	// Act by mining a block after enrollment and reading it from both the
	// filtered subscription and legacy Notifications().
	hashes, err := miner.Client.Generate(1)
	require.NoError(t, err)
	require.Len(t, hashes, 1)

	select {
	case ev := <-sub.Events():
		require.Equal(t, EventBlockConnected, ev.Type)
		require.NotNil(t, ev.Block)
		require.Equal(t, *hashes[0], ev.Block.Hash)
		require.Equal(t, wantHeight, ev.Block.Height)
	case <-time.After(defaultTestTimeout):
		require.FailNow(t, "missed EventBlockConnected")
	}

	legacyHash := waitForBlockNtfn(
		t, client.Notifications(), wantHeight, true,
	)
	require.Equal(t, *hashes[0], legacyHash)
	cancel()

	// Assert cancellation retires this reader while the owner is still
	// running. A different live context then exercises handler shutdown.
	waitSubDone(t, sub)
	require.NoError(t, sub.Err())

	live := client.SubscribeChainEvents(t.Context())
	client.Stop()
	waitSubDone(t, live)
	require.NoError(t, live.Err())
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

// TestRPCClientNotifySpentNilOutpoint verifies NotifySpent rejects nil
// outpoints with ErrInvalidParam before invoking btcd RPCs.
func TestRPCClientNotifySpentNilOutpoint(t *testing.T) {
	t.Parallel()

	// Create an uninitialized client so any RPC call would panic.
	client := &RPCClient{}

	// Call NotifySpent with a slice containing a nil outpoint.
	err := client.NotifySpent([]*wire.OutPoint{nil})

	// Confirm ErrInvalidParam is returned before touching the RPC client.
	require.ErrorIs(t, err, ErrInvalidParam)
}

// testWPKHKey holds a regtest key pair, its P2WPKH address, and its pkScript.
type testWPKHKey struct {
	// priv is the signing key for the P2WPKH output.
	priv *btcec.PrivateKey

	// addr is the regtest P2WPKH address derived from priv.
	addr address.Address

	// pkScript is the PayToAddrScript for addr.
	pkScript []byte
}

// newTestWPKHKey generates a regtest P2WPKH key bundle.
func newTestWPKHKey(t *testing.T) testWPKHKey {
	t.Helper()

	params := &chaincfg.RegressionNetParams
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pubAddr, err := address.NewAddressPubKey(
		priv.PubKey().SerializeCompressed(), params,
	)
	require.NoError(t, err)
	addr, err := address.NewAddressWitnessPubKeyHash(
		pubAddr.AddressPubKeyHash().ScriptAddress(), params,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	return testWPKHKey{priv: priv, addr: addr, pkScript: pkScript}
}

// fundConfirmedWPKH funds k with 10000 satoshis in a mined block on miner and
// returns the funded outpoint.
func fundConfirmedWPKH(t *testing.T, miner *rpctest.Harness,
	k testWPKHKey) wire.OutPoint {

	t.Helper()

	tx, err := miner.CreateTransaction(
		[]*wire.TxOut{{Value: 10000, PkScript: k.pkScript}}, 5, false,
	)
	require.NoError(t, err)
	_, err = miner.GenerateAndSubmitBlock(
		[]*btcutil.Tx{btcutil.NewTx(tx)}, -1, time.Time{},
	)
	require.NoError(t, err)

	for i, out := range tx.TxOut {
		if string(out.PkScript) == string(k.pkScript) {
			return wire.OutPoint{
				Hash:  tx.TxHash(),
				Index: uint32(i),
			}
		}
	}

	require.FailNow(t, "funded output not found")

	return wire.OutPoint{}
}

// signWPKHSpend constructs and signs a single-input SegWit tx spending input
// owned by key/inAmt to a single output.
func signWPKHSpend(t *testing.T, input wire.OutPoint, key testWPKHKey,
	inAmt int64, destScript []byte, sendAmt int64) *wire.MsgTx {

	t.Helper()

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(wire.NewTxIn(&input, nil, nil))
	tx.AddTxOut(wire.NewTxOut(sendAmt, destScript))

	fetcher := txscript.NewCannedPrevOutputFetcher(key.pkScript, inAmt)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	wit, err := txscript.WitnessSignature(
		tx, sigHashes, 0, inAmt, key.pkScript, txscript.SigHashAll,
		key.priv, true,
	)
	require.NoError(t, err)

	tx.TxIn[0].Witness = wit

	return tx
}

// TestRPCClientRelevantTxWitnessTxid verifies onRelevantTxAccepted decodes raw
// SegWit txns using their canonical txid rather than their witness hash.
func TestRPCClientRelevantTxWitnessTxid(t *testing.T) {
	t.Parallel()

	// Construct a signed SegWit spend whose txid differs from its witness
	// hash and serialize it with witness data as btcd sends on the wire.
	key := newTestWPKHKey(t)
	dest := newTestWPKHKey(t)
	tx := signWPKHSpend(
		t, wire.OutPoint{Hash: chainhash.Hash{1}, Index: 0}, key,
		10000, dest.pkScript, 9000,
	)
	require.NotEqual(t, tx.TxHash(), tx.WitnessHash())

	var raw bytes.Buffer
	require.NoError(t, tx.Serialize(&raw))

	stream := newChainEventStream(&chaincfg.RegressionNetParams, nil)
	sub := stream.subscribe(t.Context())
	_, err := registerWatchKeys(
		t.Context(), stream, sub.listener, t.Context().Done(),
		&stream.scriptListeners, &sub.listener.scripts,
		[]string{string(dest.pkScript)},
	)
	require.NoError(t, err)

	client := &RPCClient{eventStream: stream}

	// Feed the serialized witness tx into onRelevantTxAccepted.
	client.onRelevantTxAccepted(raw.Bytes())

	// Confirm an unconfirmed EventMempoolTx with canonical txid was
	// published on the subscription.
	ev := waitChainEvent(t, sub.Events())
	require.Equal(t, EventMempoolTx, ev.Type)
	require.Nil(t, ev.Block)
	require.Len(t, ev.RelevantTxs, 1)
	require.Equal(t, tx.TxHash(), ev.RelevantTxs[0].Hash)
}

// waitChainEvent reads the next Event from ch or fails on timeout.
func waitChainEvent(t *testing.T, ch <-chan Event) Event {
	t.Helper()

	select {
	case ev, ok := <-ch:
		require.True(t, ok, "unexpected closed Event channel")
		return ev
	case <-time.After(defaultTestTimeout):
		require.FailNow(t, "timed out waiting for Event")
		return Event{}
	}
}

// TestRPCClientScopedWatch verifies live btcd scoped mempool and confirmed
// same-block parent-to-child block delivery, unwatched sibling isolation, and
// legacy Notifications compatibility.
func TestRPCClientScopedWatch(t *testing.T) {
	t.Parallel()

	// Fund a confirmed output for keyA and subscribe with keyA's address
	// and fundOP watched on watched, an unwatched sibling, and legacy
	// Notifications.
	miner := setupBtcdMiner(t)
	keyA := newTestWPKHKey(t)
	keyOther := newTestWPKHKey(t)
	fundOP := fundConfirmedWPKH(t, miner, keyA)

	client := setupBtcdClient(t, miner)
	require.NoError(t, client.NotifyBlocks())
	legacy := client.Notifications()
	waitForClientConnected(t, legacy)

	watched := client.SubscribeChainEvents(t.Context())
	unwatched := client.SubscribeChainEvents(t.Context())
	require.NoError(
		t, watched.WatchAddrs(t.Context(), []address.Address{keyA.addr}),
	)
	require.NoError(
		t, watched.WatchOutputs(t.Context(), []*wire.OutPoint{&fundOP}),
	)

	// Broadcast the spend parent in mempool first so watched sees it via
	// EventMempoolTx before confirmation.
	parent := signWPKHSpend(
		t, fundOP, keyA, 10000, keyA.pkScript, 9000,
	)
	parentHash := parent.TxHash()
	_, err := client.SendRawTransaction(parent, true)
	require.NoError(t, err)

	memEv := waitChainEvent(t, watched.Events())
	require.Equal(t, EventMempoolTx, memEv.Type)
	require.Nil(t, memEv.Block)
	require.Len(t, memEv.RelevantTxs, 1)
	require.Equal(t, parentHash, memEv.RelevantTxs[0].Hash)

	// Build a same-block child spending parent's self-funded output and
	// mine both directly in one block.
	parentOP := wire.OutPoint{Hash: parentHash, Index: 0}
	child := signWPKHSpend(
		t, parentOP, keyA, 9000, keyOther.pkScript, 8000,
	)

	minedBlk, err := miner.GenerateAndSubmitBlock(
		[]*btcutil.Tx{btcutil.NewTx(parent), btcutil.NewTx(child)},
		-1, time.Time{},
	)
	require.NoError(t, err)

	// Verify watched receives parent then child inside one
	// EventBlockConnected, unwatched receives an empty block event, and
	// legacy Notifications receives parent.
	wBlk := waitChainEvent(t, watched.Events())
	require.Equal(t, EventBlockConnected, wBlk.Type)
	require.Equal(t, *minedBlk.Hash(), wBlk.Block.Hash)
	require.Len(t, wBlk.RelevantTxs, 2)
	require.Equal(t, parentHash, wBlk.RelevantTxs[0].Hash)
	require.Equal(t, child.TxHash(), wBlk.RelevantTxs[1].Hash)

	uBlk := waitChainEvent(t, unwatched.Events())
	require.Equal(t, EventBlockConnected, uBlk.Type)
	require.Equal(t, *minedBlk.Hash(), uBlk.Block.Hash)
	require.Empty(t, uBlk.RelevantTxs)

	waitForRelevantTx(t, legacy, &parentHash)
}

// TestRPCClientWatchWithoutNotifyBlocks verifies calling WatchAddrs without
// NotifyBlocks does not stealth-enable legacy BlockConnected notifications on
// Notifications() while still delivering watched EventMempoolTx events.
func TestRPCClientWatchWithoutNotifyBlocks(t *testing.T) {
	t.Parallel()

	// Start btcd without calling NotifyBlocks, drain the initial connect
	// marker, and register a scoped address watch.
	miner, client := setupBtcd(t)
	legacy := client.Notifications()
	waitForClientConnected(t, legacy)

	sub := client.SubscribeChainEvents(t.Context())
	dest := newTestWPKHKey(t)
	require.NoError(
		t, sub.WatchAddrs(t.Context(), []address.Address{dest.addr}),
	)

	// Mine an empty block first, then broadcast a watched mempool payment.
	_, err := miner.Client.Generate(1)
	require.NoError(t, err)

	tx, err := miner.CreateTransaction(
		[]*wire.TxOut{{Value: 3000, PkScript: dest.pkScript}}, 5, false,
	)
	require.NoError(t, err)

	txHash := tx.TxHash()
	_, err = client.SendRawTransaction(tx, true)
	require.NoError(t, err)

	// Verify sub receives the mempool tx and legacy Notifications() sees
	// no unrequested BlockConnected before the matching RelevantTx.
	memEv := waitChainEvent(t, sub.Events())
	require.Equal(t, EventMempoolTx, memEv.Type)
	require.Equal(t, txHash, memEv.RelevantTxs[0].Hash)

	deadline := time.After(defaultTestTimeout)
	for {
		select {
		case ntfn := <-legacy:
			_, isBlk := ntfn.(BlockConnected)
			require.False(
				t, isBlk, "WatchAddrs stealth-enabled "+
					"BlockConnected",
			)

			if rel, ok := ntfn.(RelevantTx); ok &&
				rel.TxRecord.Hash.IsEqual(&txHash) {

				return
			}
		case <-deadline:
			require.FailNow(t, "legacy Notifications missed tx")
		}
	}
}
