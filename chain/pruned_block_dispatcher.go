package chain

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/peer"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/neutrino/query"
	"github.com/lightningnetwork/lnd/ticker"
)

const (
	// defaultRefreshPeersInterval represents the default polling interval
	// at which we attempt to refresh the set of known peers.
	defaultRefreshPeersInterval = 30 * time.Second

	// defaultPeerReadyTimeout is the default amount of time we'll wait for
	// a query peer to be ready to receive incoming block requests. Peers
	// cannot respond to requests until the version exchange is completed
	// upon connection establishment.
	defaultPeerReadyTimeout = 15 * time.Second

	// requiredServices are the requires services we require any candidate
	// peers to signal such that we can retrieve pruned blocks from them.
	requiredServices = wire.SFNodeNetwork | wire.SFNodeWitness

	// prunedNodeService is the service bit signaled by pruned nodes on the
	// network. Note that this service bit can also be signaled by full
	// nodes, except that they also signal wire.SFNodeNetwork, where as
	// pruned nodes don't.
	prunedNodeService wire.ServiceFlag = 1 << 10
)

// queryPeer represents a Bitcoin network peer that we'll query for blocks.
// The ready channel serves as a signal for us to know when we can be sending
// queries to the peer. Any messages received from the peer are sent through the
// msgsRecvd channel.
type queryPeer struct {
	*peer.Peer
	ready     chan struct{}
	msgsRecvd chan wire.Message
	quit      chan struct{}
}

// signalUponDisconnect closes the peer's quit chan to signal it has
// disconnected.
func (p *queryPeer) signalUponDisconnect(f func()) {
	go func() {
		p.WaitForDisconnect()
		close(p.quit)
		f()
	}()
}

// SubscribeRecvMsg adds a OnRead subscription to the peer. All bitcoin messages
// received from this peer will be sent on the returned channel. A closure is
// also returned, that should be called to cancel the subscription.
//
// NOTE: This method exists to satisfy the query.Peer interface.
func (p *queryPeer) SubscribeRecvMsg() (<-chan wire.Message, func()) {
	return p.msgsRecvd, func() {}
}

// OnDisconnect returns a channel that will be closed once the peer disconnects.
//
// NOTE: This method exists to satisfy the query.Peer interface.
func (p *queryPeer) OnDisconnect() <-chan struct{} {
	return p.quit
}

// PrunedBlockDispatcherConfig encompasses all of the dependencies required by
// the PrunedBlockDispatcher to carry out its duties.
type PrunedBlockDispatcherConfig struct {
	// ChainParams represents the parameters of the current active chain.
	ChainParams *chaincfg.Params

	// NumTargetPeer represents the target number of peers we should
	// maintain connections with. This exists to prevent establishing
	// connections to all of the bitcoind's peers, which would be
	// unnecessary and ineffecient.
	NumTargetPeers int

	// Dial establishes connections to Bitcoin peers. This must support
	// dialing peers running over Tor if the backend also supports it.
	Dial func(string) (net.Conn, error)

	// GetPeers retrieves the active set of peers known to the backend node.
	GetPeers func() ([]btcjson.GetPeerInfoResult, error)

	// GetNodeAddresses returns random reachable addresses known to the
	// backend node. An optional number of addresses to return can be
	// provided, otherwise 8 are returned by default.
	GetNodeAddresses func(*int32) ([]btcjson.GetNodeAddressesResult, error)

	// PeerReadyTimeout is the amount of time we'll wait for a query peer to
	// be ready to receive incoming block requests. Peers cannot respond to
	// requests until the version exchange is completed upon connection
	// establishment.
	PeerReadyTimeout time.Duration

	// RefreshPeersTicker is the polling ticker that signals us when we
	// should attempt to refresh the set of known peers.
	RefreshPeersTicker ticker.Ticker

	// AllowSelfPeerConns is only used to allow the tests to bypass the peer
	// self connection detecting and disconnect logic since they
	// intentionally do so for testing purposes.
	AllowSelfPeerConns bool

	// MaxRequestInvs dictates how many invs we should fit in a single
	// getdata request to a peer. This only exists to facilitate the testing
	// of a request spanning multiple getdata messages.
	MaxRequestInvs int
}

// PrunedBlockDispatcher enables a chain client to request blocks that the
// server has already pruned. This is done by connecting to the server's full
// node peers and querying them directly. Ideally, this is a capability
// supported by the server, though this is not yet possible with bitcoind.
type PrunedBlockDispatcher struct {
	cfg PrunedBlockDispatcherConfig

	// workManager handles satisfying all of our incoming pruned block
	// requests.
	workManager query.WorkManager

	// blocksQueried represents the set of pruned blocks we've been
	// requested to query. Each block maps to a list of clients waiting to
	// be notified once the block is received.
	//
	// NOTE: The blockMtx lock must always be held when accessing this
	// field.
	blocksQueried map[chainhash.Hash][]chan *wire.MsgBlock

	// blockQueryCancel signals the cancellation of a `GetBlock` request.
	//
	// NOTE: The blockMtx lock must always be held when accessing this
	// field.
	blockQueryCancel map[chainhash.Hash][]chan<- error

	blockMtx sync.Mutex

	// currentPeers represents the set of peers we're currently connected
	// to. Each peer found here will have a worker spawned within the
	// workManager to handle our queries.
	//
	// NOTE: The peerMtx lock must always be held when accessing this
	// field.
	currentPeers map[string]*peer.Peer

	// bannedPeers represents the set of peers who have sent us an invalid
	// reply corresponding to a query. Peers within this set should not be
	// dialed.
	//
	// NOTE: The peerMtx lock must always be held when accessing this
	// field.
	bannedPeers map[string]struct{}
	peerMtx     sync.Mutex

	// peersConnected is the channel through which we'll send new peers
	// we've established connections to.
	peersConnected chan query.Peer

	// timeSource provides a mechanism to add several time samples which are
	// used to determine a median time which is then used as an offset to
	// the local clock when validating blocks received from peers.
	timeSource blockchain.MedianTimeSource

	quit chan struct{}
	wg   sync.WaitGroup
}

// NewPrunedBlockDispatcher initializes a new PrunedBlockDispatcher instance
// backed by the given config.
func NewPrunedBlockDispatcher(cfg *PrunedBlockDispatcherConfig) (
	*PrunedBlockDispatcher, error) {

	if cfg.NumTargetPeers < 1 {
		return nil, errors.New("config option NumTargetPeer must be >= 1")
	}
	if cfg.MaxRequestInvs > wire.MaxInvPerMsg {
		return nil, fmt.Errorf("config option MaxRequestInvs must be "+
			"<= %v", wire.MaxInvPerMsg)
	}

	peersConnected := make(chan query.Peer)
	return &PrunedBlockDispatcher{
		cfg: *cfg,
		workManager: query.NewWorkManager(&query.Config{
			ConnectedPeers: func() (<-chan query.Peer, func(), error) {
				return peersConnected, func() {}, nil
			},
			NewWorker: query.NewWorker,
			Ranking:   query.NewPeerRanking(),
		}),
		blocksQueried:    make(map[chainhash.Hash][]chan *wire.MsgBlock),
		blockQueryCancel: make(map[chainhash.Hash][]chan<- error),
		currentPeers:     make(map[string]*peer.Peer),
		bannedPeers:      make(map[string]struct{}),
		peersConnected:   peersConnected,
		timeSource:       blockchain.NewMedianTime(),
		quit:             make(chan struct{}),
	}, nil
}

// Start allows the PrunedBlockDispatcher to begin handling incoming block
// requests.
func (d *PrunedBlockDispatcher) Start() error {
	log.Tracef("Starting pruned block dispatcher")

	if err := d.workManager.Start(); err != nil {
		return err
	}

	d.wg.Add(1)
	go d.pollPeers()

	return nil
}

// Stop stops the PrunedBlockDispatcher from accepting any more incoming block
// requests.
func (d *PrunedBlockDispatcher) Stop() {
	log.Tracef("Stopping pruned block dispatcher")

	close(d.quit)
	d.wg.Wait()

	_ = d.workManager.Stop()
}

// pollPeers continuously polls the backend node for new peers to establish
// connections to.
func (d *PrunedBlockDispatcher) pollPeers() {
	defer d.wg.Done()

	if err := d.connectToPeers(); err != nil {
		log.Warnf("Unable to establish peer connections: %v", err)
	}

	d.cfg.RefreshPeersTicker.Resume()
	defer d.cfg.RefreshPeersTicker.Stop()

	for {
		select {
		case <-d.cfg.RefreshPeersTicker.Ticks():
			// Quickly determine if we need any more peer
			// connections. If we don't, we'll wait for our next
			// tick.
			d.peerMtx.Lock()
			peersNeeded := d.cfg.NumTargetPeers - len(d.currentPeers)
			d.peerMtx.Unlock()
			if peersNeeded <= 0 {
				continue
			}

			// If we do, attempt to establish connections until
			// we've reached our target number.
			if err := d.connectToPeers(); err != nil {
				log.Warnf("Failed to establish peer "+
					"connections: %v", err)
				continue
			}

		case <-d.quit:
			return
		}
	}
}

// connectToPeers attempts to establish new peer connections until the target
// number is reached. Once a connection is successfully established, the peer is
// sent through the peersConnected channel to notify the internal workManager.
func (d *PrunedBlockDispatcher) connectToPeers() error {
	// Refresh the list of peers our backend is currently connected to, and
	// filter out any that do not meet our requirements.
	peers, err := d.cfg.GetPeers()
	if err != nil {
		return err
	}
	addrs, err := filterPeers(peers)
	if err != nil {
		return err
	}
	rand.Shuffle(len(addrs), func(i, j int) {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	})

	for _, addr := range addrs {
		needMore, err := d.connectToPeer(addr)
		if err != nil {
			log.Debugf("Failed connecting to peer %v: %v", addr, err)
			continue
		}
		if !needMore {
			return nil
		}
	}

	// We still need more addresses so we'll also invoke the
	// `getnodeaddresses` RPC to receive random reachable addresses. We'll
	// also filter out any that do not meet our requirements. The nil
	// argument will return a default number of addresses, which is
	// currently 8. We don't care how many addresses are returned as long as
	// 1 is returned, since this will be polled regularly if needed.
	nodeAddrs, err := d.cfg.GetNodeAddresses(nil)
	if err != nil {
		return err
	}
	addrs = filterNodeAddrs(nodeAddrs)
	for _, addr := range addrs {
		if _, err := d.connectToPeer(addr); err != nil {
			log.Debugf("Failed connecting to peer %v: %v", addr, err)
		}
	}

	return nil
}

// connectToPeer attempts to establish a connection to the given peer and waits
// up to PeerReadyTimeout for the version exchange to complete so that we can
// begin sending it our queries.
func (d *PrunedBlockDispatcher) connectToPeer(addr string) (bool, error) {
	// Prevent connections to peers we've already connected to or we've
	// banned.
	d.peerMtx.Lock()
	_, isBanned := d.bannedPeers[addr]
	_, isConnected := d.currentPeers[addr]
	d.peerMtx.Unlock()
	if isBanned || isConnected {
		return true, nil
	}

	peer, err := d.newQueryPeer(addr)
	if err != nil {
		return true, fmt.Errorf("unable to configure query peer %v: "+
			"%w", addr, err)
	}

	// Establish the connection and wait for the protocol negotiation to
	// complete.
	conn, err := d.cfg.Dial(addr)
	if err != nil {
		return true, err
	}
	peer.AssociateConnection(conn)

	select {
	case <-peer.ready:
	case <-time.After(d.cfg.PeerReadyTimeout):
		peer.Disconnect()
		return true, errors.New("timed out waiting for protocol negotiation")
	case <-d.quit:
		return false, errors.New("shutting down")
	}

	// Remove the peer once it has disconnected.
	peer.signalUponDisconnect(func() {
		d.peerMtx.Lock()
		delete(d.currentPeers, peer.Addr())
		d.peerMtx.Unlock()
	})

	d.peerMtx.Lock()
	d.currentPeers[addr] = peer.Peer
	numPeers := len(d.currentPeers)
	d.peerMtx.Unlock()

	// Notify the new peer connection to our workManager.
	select {
	case d.peersConnected <- peer:
	case <-d.quit:
		return false, errors.New("shutting down")
	}

	// Request more peer connections if we haven't reached our target number
	// with the new peer.
	return numPeers < d.cfg.NumTargetPeers, nil
}

// filterPeers filters out any peers which cannot handle arbitrary witness block
// requests, i.e., any peer which is not considered a segwit-enabled
// "full-node".
func filterPeers(peers []btcjson.GetPeerInfoResult) ([]string, error) {
	var eligible []string // nolint:prealloc

	// First we sort the peers by the measured ping time, to choose the best
	// peers to fetch blocks from.
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].PingTime < peers[j].PingTime
	})

	for _, peer := range peers {
		// We cannot use the inbound peers here because the referenced
		// port in the `addr` field is not the listen port for the p2p
		// connection but a random outgoing port of the peer.
		if peer.Inbound {
			log.Debugf("Inbound peer %v not considering for "+
				"outbound connection to fetch pruned blocks",
				peer)

			continue
		}

		rawServices, err := hex.DecodeString(peer.Services)
		if err != nil {
			return nil, err
		}
		services := wire.ServiceFlag(binary.BigEndian.Uint64(rawServices))
		if !satisfiesRequiredServices(services) {
			continue
		}
		eligible = append(eligible, peer.Addr)
	}
	return eligible, nil
}

// filterNodeAddrs filters out any peers which cannot handle arbitrary witness
// block requests, i.e., any peer which is not considered a segwit-enabled
// "full-node".
func filterNodeAddrs(nodeAddrs []btcjson.GetNodeAddressesResult) []string {
	var eligible []string // nolint:prealloc
	for _, nodeAddr := range nodeAddrs {
		services := wire.ServiceFlag(nodeAddr.Services)
		if !satisfiesRequiredServices(services) {
			continue
		}
		eligible = append(eligible, nodeAddr.Address)
	}
	return eligible
}

// satisfiesRequiredServices determines whether the services signaled by a peer
// satisfy our requirements for retrieving pruned blocks from them. We need the
// full chain, and witness data as well. Note that we ignore the limited
// (pruned bit) as nodes can have the full data and set that as well. Pure
// pruned nodes won't set the network bit.
func satisfiesRequiredServices(services wire.ServiceFlag) bool {
	return services&requiredServices == requiredServices
}

// newQueryPeer creates a new peer instance configured to relay any received
// messages to the internal workManager.
func (d *PrunedBlockDispatcher) newQueryPeer(addr string) (*queryPeer, error) {
	ready := make(chan struct{})
	msgsRecvd := make(chan wire.Message)

	cfg := &peer.Config{
		ChainParams: d.cfg.ChainParams,
		// We're not interested in transactions, so disable their relay.
		DisableRelayTx: true,
		Listeners: peer.MessageListeners{
			// Add the remote peer time as a sample for creating an
			// offset against the local clock to keep the network
			// time in sync.
			OnVersion: func(p *peer.Peer, msg *wire.MsgVersion) *wire.MsgReject {
				d.timeSource.AddTimeSample(p.Addr(), msg.Timestamp)
				return nil
			},
			// Register a callback to signal us when we can start
			// querying the peer for blocks.
			OnVerAck: func(*peer.Peer, *wire.MsgVerAck) {
				close(ready)
			},
			// Register a callback to signal us whenever the peer
			// has sent us a block message.
			OnRead: func(p *peer.Peer, _ int, msg wire.Message, err error) {
				if err != nil {
					return
				}

				var block *wire.MsgBlock
				switch msg := msg.(type) {
				case *wire.MsgBlock:
					block = msg
				case *wire.MsgVersion, *wire.MsgVerAck,
					*wire.MsgPing, *wire.MsgPong:
					return
				default:
					log.Debugf("Received unexpected message "+
						"%T from peer %v", msg, p.Addr())
					return
				}

				select {
				case msgsRecvd <- block:
				case <-d.quit:
				}
			},
		},
		AllowSelfConns: true,
	}
	p, err := peer.NewOutboundPeer(cfg, addr)
	if err != nil {
		return nil, err
	}

	return &queryPeer{
		Peer:      p,
		ready:     ready,
		msgsRecvd: msgsRecvd,
		quit:      make(chan struct{}),
	}, nil
}

// banPeer bans a peer by disconnecting them and ensuring we don't reconnect.
func (d *PrunedBlockDispatcher) banPeer(peer string) {
	d.peerMtx.Lock()
	defer d.peerMtx.Unlock()

	d.bannedPeers[peer] = struct{}{}
	if p, ok := d.currentPeers[peer]; ok {
		p.Disconnect()
	}
}

// Query submits a request to query the information of the given blocks.
func (d *PrunedBlockDispatcher) Query(blocks []*chainhash.Hash,
	cancelChan chan<- error,
	opts ...query.QueryOption) (<-chan *wire.MsgBlock, <-chan error) {

	reqs, blockChan, err := d.newRequest(blocks, cancelChan)
	if err != nil {
		errChan := make(chan error, 1)
		errChan <- err
		return nil, errChan
	}

	var errChan chan error
	if len(reqs) > 0 {
		errChan = d.workManager.Query(reqs, opts...)
	}

	return blockChan, errChan
}

// newRequest construct a new query request for the given blocks to submit to
// the internal workManager. A channel is also returned through which the
// requested blocks are sent through.
//
// NOTE: The cancelChan must be buffered.
func (d *PrunedBlockDispatcher) newRequest(blocks []*chainhash.Hash,
	cancelChan chan<- error) ([]*query.Request, <-chan *wire.MsgBlock,
	error) {

	// Make sure the channel is buffered enough to handle all blocks.
	blockChan := make(chan *wire.MsgBlock, len(blocks))

	d.blockMtx.Lock()
	defer d.blockMtx.Unlock()

	// Each GetData message can only include up to MaxRequestInvs invs,
	// and each block consumes a single inv.
	var (
		reqs    []*query.Request
		getData *wire.MsgGetData
	)
	for i, block := range blocks {
		if getData == nil {
			getData = wire.NewMsgGetData()
		}

		if _, ok := d.blocksQueried[*block]; !ok {
			log.Debugf("Queuing new block %v for request", *block)
			inv := wire.NewInvVect(wire.InvTypeWitnessBlock, block)
			if err := getData.AddInvVect(inv); err != nil {
				return nil, nil, err
			}
		} else {
			log.Debugf("Received new request for pending query of "+
				"block %v", *block)

			d.blockQueryCancel[*block] = append(
				d.blockQueryCancel[*block], cancelChan,
			)
		}

		d.blocksQueried[*block] = append(
			d.blocksQueried[*block], blockChan,
		)

		// If we have any invs to request, or we've reached the maximum
		// allowed, queue the getdata message as is, and proceed to the
		// next if any.
		if (len(getData.InvList) > 0 && i == len(blocks)-1) ||
			len(getData.InvList) == d.cfg.MaxRequestInvs {

			reqs = append(reqs, &query.Request{
				Req:        getData,
				HandleResp: d.handleResp,
			})
			getData = nil
		}
	}

	return reqs, blockChan, nil
}

// handleResp is a response handler that will be called for every message
// received from the peer that the request was made to. It should validate the
// response against the request made, and return a Progress indicating whether
// the request was answered by this particular response.
//
// NOTE: Since the worker's job queue will be stalled while this method is
// running, it should not be doing any expensive operations. It should validate
// the response and immediately return the progress. The response should be
// handed off to another goroutine for processing.
func (d *PrunedBlockDispatcher) handleResp(req, resp wire.Message,
	peer string) query.Progress {

	// We only expect MsgBlock as replies.
	block, ok := resp.(*wire.MsgBlock)
	if !ok {
		return query.Progress{
			Progressed: false,
			Finished:   false,
		}
	}

	// We only serve MsgGetData requests.
	getData, ok := req.(*wire.MsgGetData)
	if !ok {
		return query.Progress{
			Progressed: false,
			Finished:   false,
		}
	}

	// Check that we've actually queried for this block and validate it.
	blockHash := block.BlockHash()
	d.blockMtx.Lock()
	blockChans, ok := d.blocksQueried[blockHash]
	if !ok {
		d.blockMtx.Unlock()
		return query.Progress{
			Progressed: false,
			Finished:   false,
		}
	}
	copyblockChans := make([]chan *wire.MsgBlock, len(blockChans))
	copy(copyblockChans, blockChans)

	err := blockchain.CheckBlockSanity(
		btcutil.NewBlock(block), d.cfg.ChainParams.PowLimit,
		d.timeSource,
	)
	if err != nil {
		d.blockMtx.Unlock()

		log.Warnf("Received invalid block %v from peer %v: %v",
			blockHash, peer, err)
		d.banPeer(peer)

		return query.Progress{
			Progressed: false,
			Finished:   false,
		}
	}

	err = blockchain.ValidateWitnessCommitment(btcutil.NewBlock(block))
	if err != nil {
		d.blockMtx.Unlock()

		log.Warnf("Received invalid block %v from peer %v: %v",
			blockHash, peer, err)
		d.banPeer(peer)

		return query.Progress{
			Progressed: false,
			Finished:   false,
		}
	}

	// Once validated, we can safely remove it.
	delete(d.blocksQueried, blockHash)

	// Check whether we have any other pending blocks we've yet to receive.
	// If we do, we'll mark the response as progressing our query, but not
	// completing it yet.
	progress := query.Progress{Progressed: true, Finished: true}
	for _, inv := range getData.InvList {
		if _, ok := d.blocksQueried[inv.Hash]; ok {
			progress.Finished = false
			break
		}
	}
	d.blockMtx.Unlock()

	// Launch a goroutine to notify all clients of the block as we don't
	// want to potentially block our workManager.
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()

		for _, blockChan := range copyblockChans {
			select {
			case blockChan <- block:
			case <-d.quit:
				return
			}
		}
	}()

	return progress
}

// CancelRequest removes all information regarding a failed block request.
// When for example the Peer disconnects or runs in a timeout we make sure
// that all related information is deleted and a new request for this block
// can be registered. Moreover will also cancel all depending goroutines.
func (d *PrunedBlockDispatcher) CancelRequest(blockHash chainhash.Hash,
	err error) {

	// failDependant is a helper function which fails all dependant
	// goroutines via their cancel channels.
	failDependant := func(cancelChans []chan<- error) {
		defer d.wg.Done()

		for _, cancel := range cancelChans {
			select {
			case cancel <- err:
			case <-d.quit:
				return
			}
		}
	}

	d.blockMtx.Lock()

	// Before removing the block hash we get the cancelChans which were
	// registered for block requests that had already an ongoing pending
	// request.
	cancelChans, ok := d.blockQueryCancel[blockHash]
	var copycancelChans []chan<- error
	if ok {
		copycancelChans = make([]chan<- error, len(cancelChans))
		copy(copycancelChans, cancelChans)
	}

	// Remove all data related to this block request to make sure the same
	// block can be registered again in the future.
	delete(d.blocksQueried, blockHash)
	delete(d.blockQueryCancel, blockHash)

	d.blockMtx.Unlock()

	// In case there are goroutines depending on this block request we
	// make sure we cancel them.
	// We do this in a goroutine to not block the initial request.
	if ok {
		d.wg.Add(1)
		go failDependant(copycancelChans)
	}
}
