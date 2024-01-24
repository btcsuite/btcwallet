package chain

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/neutrino/query"
	"github.com/lightningnetwork/lnd/ticker"
	"github.com/stretchr/testify/require"
)

var (
	addrCounter int32 // Increased atomically.

	chainParams = chaincfg.RegressionNetParams
)

func nextAddr() string {
	port := atomic.AddInt32(&addrCounter, 1)
	return fmt.Sprintf("10.0.0.1:%d", port)
}

// prunedBlockDispatcherHarness is a harness used to facilitate the testing of the
// PrunedBlockDispatcher.
type prunedBlockDispatcherHarness struct {
	t *testing.T

	dispatcher *PrunedBlockDispatcher

	hashes []*chainhash.Hash
	blocks map[chainhash.Hash]*wire.MsgBlock

	peerMtx       sync.Mutex
	peers         map[string]*peer.Peer
	fallbackAddrs map[string]*peer.Peer
	localConns    map[string]net.Conn // Connections to peers.
	remoteConns   map[string]net.Conn // Connections from peers.

	dialedPeer    chan string
	queriedPeer   chan struct{}
	blocksQueried map[chainhash.Hash]int

	shouldReply uint32 // 0 == true, 1 == false, 2 == invalid reply
}

// newNetworkBlockTestHarness initializes a new PrunedBlockDispatcher test harness
// backed by a custom chain and peers.
func newNetworkBlockTestHarness(t *testing.T, numBlocks,
	numPeers, numWorkers uint32) *prunedBlockDispatcherHarness {

	h := &prunedBlockDispatcherHarness{
		t:             t,
		dispatcher:    &PrunedBlockDispatcher{},
		peers:         make(map[string]*peer.Peer, numPeers),
		fallbackAddrs: make(map[string]*peer.Peer, numPeers),
		localConns:    make(map[string]net.Conn, numPeers),
		remoteConns:   make(map[string]net.Conn, numPeers),
		dialedPeer:    make(chan string),
		queriedPeer:   make(chan struct{}),
		blocksQueried: make(map[chainhash.Hash]int),
		shouldReply:   0,
	}

	h.hashes, h.blocks = genBlockChain(numBlocks)
	for i := uint32(0); i < numPeers; i++ {
		h.addPeer(false)
	}

	dial := func(addr string) (net.Conn, error) {
		go func() {
			h.dialedPeer <- addr
		}()

		h.peerMtx.Lock()
		defer h.peerMtx.Unlock()

		localConn, ok := h.localConns[addr]
		if !ok {
			return nil, fmt.Errorf("local conn %v not found", addr)
		}
		remoteConn, ok := h.remoteConns[addr]
		if !ok {
			return nil, fmt.Errorf("remote conn %v not found", addr)
		}

		if p, ok := h.peers[addr]; ok {
			p.AssociateConnection(remoteConn)
		}
		if p, ok := h.fallbackAddrs[addr]; ok {
			p.AssociateConnection(remoteConn)
		}
		return localConn, nil
	}

	var err error
	h.dispatcher, err = NewPrunedBlockDispatcher(&PrunedBlockDispatcherConfig{
		ChainParams:    &chainParams,
		NumTargetPeers: int(numWorkers),
		Dial:           dial,
		GetPeers: func() ([]btcjson.GetPeerInfoResult, error) {
			h.peerMtx.Lock()
			defer h.peerMtx.Unlock()

			res := make([]btcjson.GetPeerInfoResult, 0, len(h.peers))
			for addr, peer := range h.peers {
				var rawServices [8]byte
				binary.BigEndian.PutUint64(
					rawServices[:], uint64(peer.Services()),
				)

				res = append(res, btcjson.GetPeerInfoResult{
					Addr:     addr,
					Services: hex.EncodeToString(rawServices[:]),
				})
			}

			return res, nil
		},
		GetNodeAddresses: func(*int32) ([]btcjson.GetNodeAddressesResult, error) {
			h.peerMtx.Lock()
			defer h.peerMtx.Unlock()

			res := make(
				[]btcjson.GetNodeAddressesResult, 0,
				len(h.fallbackAddrs),
			)
			for addr, peer := range h.fallbackAddrs {
				res = append(res, btcjson.GetNodeAddressesResult{
					Services: uint64(peer.Services()),
					Address:  addr,
				})
			}
			return res, nil
		},
		PeerReadyTimeout:   time.Hour,
		RefreshPeersTicker: ticker.NewForce(time.Hour),
		AllowSelfPeerConns: true,
		MaxRequestInvs:     wire.MaxInvPerMsg,
	})
	require.NoError(t, err)

	return h
}

// start starts the PrunedBlockDispatcher and asserts that connections are made
// to all available peers.
func (h *prunedBlockDispatcherHarness) start() {
	h.t.Helper()

	err := h.dispatcher.Start()
	require.NoError(h.t, err)

	h.peerMtx.Lock()
	numPeers := len(h.peers)
	h.peerMtx.Unlock()

	for i := 0; i < numPeers; i++ {
		h.assertPeerDialed()
	}
}

// stop stops the PrunedBlockDispatcher and asserts that all internal fields of
// the harness have been properly consumed.
func (h *prunedBlockDispatcherHarness) stop() {
	h.dispatcher.Stop()

	select {
	case <-h.dialedPeer:
		h.t.Fatal("did not consume all dialedPeer signals")
	default:
	}

	select {
	case <-h.queriedPeer:
		h.t.Fatal("did not consume all queriedPeer signals")
	default:
	}

	require.Empty(h.t, h.blocksQueried)
}

// addPeer adds a new random peer available for use by the
// PrunedBlockDispatcher.
func (h *prunedBlockDispatcherHarness) addPeer(fallback bool) string {
	addr := nextAddr()

	h.peerMtx.Lock()
	defer h.peerMtx.Unlock()

	h.resetPeer(addr, fallback)
	return addr
}

// resetPeer resets the internal peer connection state allowing the
// PrunedBlockDispatcher to establish a mock connection to it.
func (h *prunedBlockDispatcherHarness) resetPeer(addr string, fallback bool) {
	if fallback {
		h.fallbackAddrs[addr] = h.newPeer()
	} else {
		h.peers[addr] = h.newPeer()
	}

	inConn, outConn, err := setupConnPair()
	if err != nil {
		h.t.Fatalf("failed to setup conn pair: %v", err)
	}

	h.localConns[addr] = outConn
	h.remoteConns[addr] = inConn
}

// newPeer returns a new properly configured peer.Peer instance that will be
// used by the PrunedBlockDispatcher.
func (h *prunedBlockDispatcherHarness) newPeer() *peer.Peer {
	return peer.NewInboundPeer(&peer.Config{
		ChainParams:    &chainParams,
		DisableRelayTx: true,
		Listeners: peer.MessageListeners{
			OnGetData: func(p *peer.Peer, msg *wire.MsgGetData) {
				go func() {
					h.queriedPeer <- struct{}{}
				}()

				for _, inv := range msg.InvList {
					// Invs should always be for blocks.
					require.Equal(h.t, wire.InvTypeWitnessBlock, inv.Type)

					// Invs should always be for known blocks.
					block, ok := h.blocks[inv.Hash]
					require.True(h.t, ok)

					switch atomic.LoadUint32(&h.shouldReply) {
					// Don't reply if requested.
					case 1:
						continue
					// Make the block invalid and send it.
					case 2:
						block = produceInvalidBlock(block)
					}

					go p.QueueMessage(block, nil)
				}
			},
		},
		Services:       wire.SFNodeNetwork | wire.SFNodeWitness,
		AllowSelfConns: true,
	})
}

// query requests the given blocks from the PrunedBlockDispatcher.
func (h *prunedBlockDispatcherHarness) query(blocks []*chainhash.Hash,
	opts ...query.QueryOption) (
	<-chan *wire.MsgBlock, <-chan error, <-chan error) {

	h.t.Helper()

	// cancelChan will receive an error msg in case the dependant block
	// request fails. This is used for block requests already have a pending
	// request registered and this request fails.
	cancelChan := make(chan error, 1)

	blockChan, errChan := h.dispatcher.Query(blocks, cancelChan, opts...)
	select {
	case err := <-errChan:
		require.NoError(h.t, err)
	default:
	}

	for _, block := range blocks {
		h.blocksQueried[*block]++
	}

	return blockChan, errChan, cancelChan
}

// disablePeerReplies prevents the query peer from replying.
func (h *prunedBlockDispatcherHarness) disablePeerReplies() {
	atomic.StoreUint32(&h.shouldReply, 1)
}

// enablePeerReplies allows the query peer to reply.
func (h *prunedBlockDispatcherHarness) enablePeerReplies() {
	atomic.StoreUint32(&h.shouldReply, 0)
}

// enableInvalidPeerReplies
func (h *prunedBlockDispatcherHarness) enableInvalidPeerReplies() {
	atomic.StoreUint32(&h.shouldReply, 2)
}

// refreshPeers forces the RefreshPeersTicker to fire.
func (h *prunedBlockDispatcherHarness) refreshPeers() {
	h.t.Helper()

	h.dispatcher.cfg.RefreshPeersTicker.(*ticker.Force).Force <- time.Now()
}

// disconnectPeer simulates a peer disconnecting from the PrunedBlockDispatcher.
func (h *prunedBlockDispatcherHarness) disconnectPeer(addr string, fallback bool) {
	h.t.Helper()

	h.peerMtx.Lock()
	defer h.peerMtx.Unlock()

	require.Contains(h.t, h.peers, addr)

	// Obtain the current number of peers before disconnecting such that we
	// can block until the peer has been fully disconnected.
	h.dispatcher.peerMtx.Lock()
	numPeers := len(h.dispatcher.currentPeers)
	h.dispatcher.peerMtx.Unlock()

	h.peers[addr].Disconnect()

	require.Eventually(h.t, func() bool {
		h.dispatcher.peerMtx.Lock()
		defer h.dispatcher.peerMtx.Unlock()
		return len(h.dispatcher.currentPeers) == numPeers-1
	}, time.Second, 200*time.Millisecond)

	// Reset the peer connection state to allow connections to them again.
	h.resetPeer(addr, fallback)
}

// assertPeerDialed asserts that a connection was made to the given peer.
func (h *prunedBlockDispatcherHarness) assertPeerDialed() {
	h.t.Helper()

	select {
	case <-h.dialedPeer:
	case <-time.After(5 * time.Second):
		h.t.Fatalf("expected peer to be dialed")
	}
}

// assertPeerDialedWithAddr asserts that a connection was made to the given peer.
func (h *prunedBlockDispatcherHarness) assertPeerDialedWithAddr(addr string) {
	h.t.Helper()

	select {
	case dialedAddr := <-h.dialedPeer:
		require.Equal(h.t, addr, dialedAddr)
	case <-time.After(5 * time.Second):
		h.t.Fatalf("expected peer to be dialed")
	}
}

// assertPeerQueried asserts that query was sent to the given peer.
func (h *prunedBlockDispatcherHarness) assertPeerQueried() {
	h.t.Helper()

	select {
	case <-h.queriedPeer:
	case <-time.After(5 * time.Second):
		h.t.Fatalf("expected a peer to be queried")
	}
}

// assertPeerReplied asserts that the query peer replies with a block the
// PrunedBlockDispatcher queried for.
func (h *prunedBlockDispatcherHarness) assertPeerReplied(
	blockChan <-chan *wire.MsgBlock, errChan, cancelChan <-chan error,
	expectCompletionSignal bool) {

	h.t.Helper()

	select {
	case block := <-blockChan:
		blockHash := block.BlockHash()
		_, ok := h.blocksQueried[blockHash]
		require.True(h.t, ok)

		expBlock, ok := h.blocks[blockHash]
		require.True(h.t, ok)
		require.Equal(h.t, expBlock, block)

		// Decrement how many clients queried the same block. Once we
		// have none left, remove it from the map.
		h.blocksQueried[blockHash]--
		if h.blocksQueried[blockHash] == 0 {
			delete(h.blocksQueried, blockHash)
		}

	// We need to check the errChan after a timeout because when a request
	// was successful a nil error is signaled via the errChan and this
	// might happen even before the block is received.
	case <-time.After(5 * time.Second):
		select {
		case err := <-errChan:
			h.t.Fatalf("received unexpected error send: %v", err)

		case err := <-cancelChan:
			h.t.Fatalf("received unexpected cancel request with "+
				"error: %v", err)

		default:
		}
		h.t.Fatal("expected reply from peer")
	}

	// If we should expect a nil error to be sent by the internal
	// workManager to signal completion of the request, wait for it now.
	if expectCompletionSignal {
		select {
		case err := <-errChan:
			require.NoError(h.t, err)
		case <-time.After(5 * time.Second):
			h.t.Fatal("expected nil err to signal completion")
		}
	}
}

// assertPeerFailed asserts that the query request fails with an expected
// error.
func (h *prunedBlockDispatcherHarness) assertPeerFailed(
	blockChan <-chan *wire.MsgBlock, errChan, cancelChan <-chan error,
	expectedErr error) {

	h.t.Helper()

	select {
	case <-blockChan:
		h.t.Fatalf("expected no reply from peer")

	case err := <-errChan:
		require.ErrorIs(h.t, err, expectedErr)
		for _, hash := range h.hashes {
			h.dispatcher.CancelRequest(*hash, err)
			// The corresponding block is deleted from the request
			// queue in `CancelRequest` so we delete it from the
			// harness as well.
			delete(h.blocksQueried, *hash)
		}

	case err := <-cancelChan:
		require.ErrorIs(h.t, err, expectedErr)

	case <-time.After(5 * time.Second):
		h.t.Fatalf("expected the error for the block request: %v",
			expectedErr)
	}

}

// assertNoPeerDialed asserts that the PrunedBlockDispatcher hasn't established
// a new peer connection.
func (h *prunedBlockDispatcherHarness) assertNoPeerDialed() {
	h.t.Helper()

	select {
	case peer := <-h.dialedPeer:
		h.t.Fatalf("unexpected connection established with peer %v", peer)
	case <-time.After(2 * time.Second):
	}
}

// assertNoReply asserts that the peer hasn't replied to a query.
func (h *prunedBlockDispatcherHarness) assertNoReply(
	blockChan <-chan *wire.MsgBlock, errChan, cancelChan <-chan error) {

	h.t.Helper()

	select {
	case block := <-blockChan:
		h.t.Fatalf("received unexpected block %v", block.BlockHash())

	case err := <-errChan:
		h.t.Fatalf("received unexpected error send: %v", err)

	case err := <-cancelChan:
		h.t.Fatalf("received unexpected cancel request with error: %v",
			err)

	case <-time.After(2 * time.Second):
	}
}

// TestPrunedBlockDispatcherQuerySameBlock tests that client requests for the
// same block result in only fetching the block once while pending.
func TestPrunedBlockDispatcherQuerySameBlock(t *testing.T) {
	t.Parallel()

	const numBlocks = 1
	const numPeers = 5
	const numRequests = numBlocks * numPeers

	h := newNetworkBlockTestHarness(t, numBlocks, numPeers, numPeers)
	h.start()
	defer h.stop()

	// Queue all the block requests one by one.
	blockChans := make([]<-chan *wire.MsgBlock, 0, numRequests)
	errChans := make([]<-chan error, 0, numRequests)
	cancelChans := make([]<-chan error, 0, numRequests)

	for i := 0; i < numRequests; i++ {
		blockChan, errChan, cancelChan := h.query(h.hashes)
		blockChans = append(blockChans, blockChan)
		errChans = append(errChans, errChan)
		cancelChans = append(cancelChans, cancelChan)

	}

	// We should only see one query.
	h.assertPeerQueried()
	for i := 0; i < numRequests; i++ {
		h.assertPeerReplied(blockChans[i], errChans[i], cancelChans[i],
			i == 0)
	}
}

// TestPrunedBlockDispatcherQuerySameBlock tests that client requests for the
// same block result in only fetching the block once while pending.
func TestPrunedBlockDispatcherQueryFailSameBlock(t *testing.T) {
	t.Parallel()

	const numBlocks = 1
	const numPeers = 5
	const numRequests = numBlocks * numPeers

	h := newNetworkBlockTestHarness(t, numBlocks, numPeers, numPeers)
	h.start()
	defer h.stop()

	// Queue all the block requests one by one.
	blockChans := make([]<-chan *wire.MsgBlock, 0, numRequests)
	errChans := make([]<-chan error, 0, numRequests)
	cancelChans := make([]<-chan error, 0, numRequests)

	// We want to force a timeout.
	h.disablePeerReplies()

	for i := 0; i < numRequests; i++ {
		// The default retry number is 2 and is defined in the neutrino
		// package. We want to fail the request therefore we use 1.
		// Moreover the default timeout of a single request is 2 seconds
		// and currently not configurable so we have to make sure when
		// asserting not not timeout before.
		blockChan, errChan, cancelChan := h.query(
			h.hashes, query.NumRetries(1),
		)
		blockChans = append(blockChans, blockChan)
		errChans = append(errChans, errChan)
		cancelChans = append(cancelChans, cancelChan)
	}

	// We should only see one query.
	h.assertPeerQueried()
	for i := 0; i < numRequests; i++ {
		h.assertPeerFailed(blockChans[i], errChans[i], cancelChans[i],
			query.ErrQueryTimeout)
	}
}

// TestPrunedBlockDispatcherMultipleGetData tests that a client requesting blocks
// that span across multiple queries works as intended.
func TestPrunedBlockDispatcherMultipleGetData(t *testing.T) {
	t.Parallel()

	const maxRequestInvs = 5
	const numBlocks = (maxRequestInvs * 5) + 1

	h := newNetworkBlockTestHarness(t, numBlocks, 1, 1)
	h.dispatcher.cfg.MaxRequestInvs = maxRequestInvs
	h.start()
	defer h.stop()

	// Request all blocks.
	blockChan, errChan, cancelChan := h.query(h.hashes)

	// Since we have more blocks than can fit in a single GetData message,
	// we should expect multiple queries. For each query, we should expect
	// wire.MaxInvPerMsg replies until we've received all of them.
	blocksRecvd := 0
	numMsgs := (numBlocks / maxRequestInvs)
	if numBlocks%wire.MaxInvPerMsg > 0 {
		numMsgs++
	}
	for i := 0; i < numMsgs; i++ {
		h.assertPeerQueried()
		for j := 0; j < maxRequestInvs; j++ {
			expectCompletionSignal := blocksRecvd == numBlocks-1
			h.assertPeerReplied(
				blockChan, errChan, cancelChan,
				expectCompletionSignal,
			)

			blocksRecvd++
			if blocksRecvd == numBlocks {
				break
			}
		}
	}
}

// TestPrunedBlockDispatcherMultipleQueryPeers tests that client requests are
// distributed across multiple query peers.
func TestPrunedBlockDispatcherMultipleQueryPeers(t *testing.T) {
	t.Parallel()

	const numBlocks = 10
	const numPeers = numBlocks / 2

	h := newNetworkBlockTestHarness(t, numBlocks, numPeers, numPeers)
	h.start()
	defer h.stop()

	// Queue all the block requests one by one.
	blockChans := make([]<-chan *wire.MsgBlock, 0, numBlocks)
	errChans := make([]<-chan error, 0, numBlocks)
	cancelChans := make([]<-chan error, 0, numBlocks)

	for i := 0; i < numBlocks; i++ {
		blockChan, errChan, cancelChan := h.query(h.hashes[i : i+1])
		blockChans = append(blockChans, blockChan)
		errChans = append(errChans, errChan)
		cancelChans = append(cancelChans, cancelChan)

	}

	// We should see one query per block.
	for i := 0; i < numBlocks; i++ {
		h.assertPeerQueried()
		h.assertPeerReplied(blockChans[i], errChans[i], cancelChans[i],
			true)
	}
}

// TestPrunedBlockDispatcherPeerPoller ensures that the peer poller can detect
// when more connections are required to satisfy a request.
func TestPrunedBlockDispatcherPeerPoller(t *testing.T) {
	t.Parallel()

	// Initialize our harness as usual, but don't create any peers yet.
	h := newNetworkBlockTestHarness(t, 1, 0, 2)
	h.start()
	defer h.stop()

	// We shouldn't see any peers dialed since we don't have any.
	h.assertNoPeerDialed()

	// We'll then query for a block.
	blockChan, errChan, cancelChan := h.query(h.hashes)

	// Refresh our peers. This would dial some peers, but we don't have any
	// yet.
	h.refreshPeers()
	h.assertNoPeerDialed()

	// Add a new peer and force a refresh. We should see the peer be dialed.
	// We'll disable replies for now, as we'll want to test the disconnect
	// case.
	h.disablePeerReplies()
	peer := h.addPeer(false)
	h.refreshPeers()
	h.assertPeerDialedWithAddr(peer)
	h.assertPeerQueried()

	// Disconnect our peer and re-enable replies.
	h.disconnectPeer(peer, false)
	h.enablePeerReplies()
	h.assertNoReply(blockChan, errChan, cancelChan)

	// Force a refresh once again. Since the peer has disconnected, a new
	// connection should be made and the peer should be queried again.
	h.refreshPeers()
	h.assertPeerDialed()
	h.assertPeerQueried()

	// Add a fallback addresses and force refresh our peers again. We can
	// afford to have one more query peer, so a connection should be made.
	fallbackPeer := h.addPeer(true)
	h.refreshPeers()
	h.assertPeerDialedWithAddr(fallbackPeer)

	// Now that we know we've connected to the peer, we should be able to
	// receive their response.
	h.assertPeerReplied(blockChan, errChan, cancelChan, true)
}

// TestPrunedBlockDispatcherInvalidBlock ensures that validation is performed on
// blocks received from peers, and that any peers which have sent an invalid
// block are banned and not connected to.
func TestPrunedBlockDispatcherInvalidBlock(t *testing.T) {
	t.Parallel()

	h := newNetworkBlockTestHarness(t, 1, 1, 1)
	h.start()
	defer h.stop()

	// We'll start the test by signaling our peer to send an invalid block.
	h.enableInvalidPeerReplies()

	// We'll then query for a block. We shouldn't see a response as the
	// block should have failed validation.
	blockChan, errChan, cancelChan := h.query(h.hashes)
	h.assertPeerQueried()
	h.assertNoReply(blockChan, errChan, cancelChan)

	// Since the peer sent us an invalid block, they should have been
	// disconnected and banned. Refreshing our peers shouldn't result in a
	// new connection attempt because we don't have any other peers
	// available.
	h.refreshPeers()
	h.assertNoPeerDialed()

	// Signal to our peers to send valid replies and add a new peer.
	h.enablePeerReplies()
	_ = h.addPeer(false)

	// Force a refresh, which should cause our new peer to be dialed and
	// queried. We expect them to send a valid block and fulfill our
	// request.
	h.refreshPeers()
	h.assertPeerDialed()
	h.assertPeerQueried()
	h.assertPeerReplied(blockChan, errChan, cancelChan, true)
}

func TestSatisfiesRequiredServices(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		services wire.ServiceFlag
		ok       bool
	}{
		{
			name:     "full node, segwit",
			services: wire.SFNodeWitness | wire.SFNodeNetwork,
			ok:       true,
		},
		{
			name:     "full node segwit, signals limited",
			services: wire.SFNodeWitness | wire.SFNodeNetwork | prunedNodeService,
			ok:       true,
		},
		{
			name:     "full node, no segwit",
			services: wire.SFNodeNetwork,
			ok:       false,
		},
		{
			name:     "segwit, pure pruned",
			services: wire.SFNodeWitness | prunedNodeService,
			ok:       false,
		},
	}
	for _, testCase := range testCases {
		ok := satisfiesRequiredServices(testCase.services)
		require.Equal(
			t, testCase.ok, ok, fmt.Sprintf("test case: %v", testCase.name),
		)
	}
}
