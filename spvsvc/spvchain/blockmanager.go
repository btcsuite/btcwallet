package spvchain

import (
	"container/list"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

const (
	// minInFlightBlocks is the minimum number of blocks that should be
	// in the request queue for headers-first mode before requesting
	// more.
	minInFlightBlocks = 10

	// blockDbNamePrefix is the prefix for the block database name.  The
	// database type is appended to this value to form the full block
	// database name.
	blockDbNamePrefix = "blocks"

	// maxRequestedBlocks is the maximum number of requested block
	// hashes to store in memory.
	maxRequestedBlocks = wire.MaxInvPerMsg

	// maxTimeOffset is the maximum duration a block time is allowed to be
	// ahead of the curent time. This is currently 2 hours.
	maxTimeOffset = 2 * time.Hour
)

// TODO: Redo this using query API.
var (
	// WaitForMoreCFHeaders is a configurable time to wait for CFHeaders
	// messages from peers. It defaults to 3 seconds but can be increased
	// for higher security and decreased for faster synchronization.
	WaitForMoreCFHeaders = 3 * time.Second
)

// zeroHash is the zero value hash (all zeros).  It is defined as a convenience.
var zeroHash chainhash.Hash

// newPeerMsg signifies a newly connected peer to the block handler.
type newPeerMsg struct {
	peer *serverPeer
}

// blockMsg packages a bitcoin block message and the peer it came from together
// so the block handler has access to that information.
type blockMsg struct {
	block *btcutil.Block
	peer  *serverPeer
}

// invMsg packages a bitcoin inv message and the peer it came from together
// so the block handler has access to that information.
type invMsg struct {
	inv  *wire.MsgInv
	peer *serverPeer
}

// headersMsg packages a bitcoin headers message and the peer it came from
// together so the block handler has access to that information.
type headersMsg struct {
	headers *wire.MsgHeaders
	peer    *serverPeer
}

// cfheadersMsg packages a bitcoin cfheaders message and the peer it came from
// together so the block handler has access to that information.
type cfheadersMsg struct {
	cfheaders *wire.MsgCFHeaders
	peer      *serverPeer
}

// cfheadersProcessedMsg tells the block manager to try to see if there are
// enough samples of cfheaders messages to process the committed filter header
// chain. This is kind of a hack until these get soft-forked in, but we do
// verification to avoid getting bamboozled by malicious nodes.
type processCFHeadersMsg struct {
	earliestNode *headerNode
	stopHash     chainhash.Hash
	extended     bool
}

// donePeerMsg signifies a newly disconnected peer to the block handler.
type donePeerMsg struct {
	peer *serverPeer
}

// txMsg packages a bitcoin tx message and the peer it came from together
// so the block handler has access to that information.
type txMsg struct {
	tx   *btcutil.Tx
	peer *serverPeer
}

// getSyncPeerMsg is a message type to be sent across the message channel for
// retrieving the current sync peer.
type getSyncPeerMsg struct {
	reply chan *serverPeer
}

// processBlockResponse is a response sent to the reply channel of a
// processBlockMsg.
type processBlockResponse struct {
	isOrphan bool
	err      error
}

// processBlockMsg is a message type to be sent across the message channel
// for requested a block is processed.  Note this call differs from blockMsg
// above in that blockMsg is intended for blocks that came from peers and have
// extra handling whereas this message essentially is just a concurrent safe
// way to call ProcessBlock on the internal block chain instance.
type processBlockMsg struct {
	block *btcutil.Block
	flags blockchain.BehaviorFlags
	reply chan processBlockResponse
}

// isCurrentMsg is a message type to be sent across the message channel for
// requesting whether or not the block manager believes it is synced with
// the currently connected peers.
type isCurrentMsg struct {
	reply chan bool
}

// headerNode is used as a node in a list of headers that are linked together
// between checkpoints.
type headerNode struct {
	height int32
	header *wire.BlockHeader
}

// blockManager provides a concurrency safe block manager for handling all
// incoming blocks.
type blockManager struct {
	server          *ChainService
	started         int32
	shutdown        int32
	requestedBlocks map[chainhash.Hash]struct{}
	progressLogger  *blockProgressLogger
	syncPeer        *serverPeer
	// Channel for messages that come from peers
	peerChan chan interface{}
	// Channel for messages that come from internal commands
	intChan chan interface{}
	wg      sync.WaitGroup
	quit    chan struct{}

	headerList     *list.List
	reorgList      *list.List
	startHeader    *list.Element
	nextCheckpoint *chaincfg.Checkpoint
	lastRequested  chainhash.Hash

	basicHeaders            map[chainhash.Hash]map[chainhash.Hash][]*serverPeer
	lastBasicCFHeaderHeight int32
	numBasicCFHeadersMsgs   int32
	extendedHeaders         map[chainhash.Hash]map[chainhash.Hash][]*serverPeer
	lastExtCFHeaderHeight   int32
	numExtCFHeadersMsgs     int32
	mapMutex                sync.Mutex

	minRetargetTimespan int64 // target timespan / adjustment factor
	maxRetargetTimespan int64 // target timespan * adjustment factor
	blocksPerRetarget   int32 // target timespan / target time per block
}

// newBlockManager returns a new bitcoin block manager.
// Use Start to begin processing asynchronous block and inv updates.
func newBlockManager(s *ChainService) (*blockManager, error) {
	targetTimespan := int64(s.chainParams.TargetTimespan / time.Second)
	targetTimePerBlock := int64(s.chainParams.TargetTimePerBlock / time.Second)
	adjustmentFactor := s.chainParams.RetargetAdjustmentFactor

	bm := blockManager{
		server:              s,
		requestedBlocks:     make(map[chainhash.Hash]struct{}),
		progressLogger:      newBlockProgressLogger("Processed", log),
		peerChan:            make(chan interface{}, MaxPeers*3),
		intChan:             make(chan interface{}, 1),
		headerList:          list.New(),
		reorgList:           list.New(),
		quit:                make(chan struct{}),
		blocksPerRetarget:   int32(targetTimespan / targetTimePerBlock),
		minRetargetTimespan: targetTimespan / adjustmentFactor,
		maxRetargetTimespan: targetTimespan * adjustmentFactor,
		basicHeaders: make(
			map[chainhash.Hash]map[chainhash.Hash][]*serverPeer,
		),
		extendedHeaders: make(
			map[chainhash.Hash]map[chainhash.Hash][]*serverPeer,
		),
	}

	// Initialize the next checkpoint based on the current height.
	header, height, err := s.LatestBlock()
	if err != nil {
		return nil, err
	}
	bm.nextCheckpoint = bm.findNextHeaderCheckpoint(int32(height))
	bm.resetHeaderState(&header, int32(height))

	return &bm, nil
}

// Start begins the core block handler which processes block and inv messages.
func (b *blockManager) Start() {
	// Already started?
	if atomic.AddInt32(&b.started, 1) != 1 {
		return
	}

	log.Trace("Starting block manager")
	b.wg.Add(1)
	go b.blockHandler()
}

// Stop gracefully shuts down the block manager by stopping all asynchronous
// handlers and waiting for them to finish.
func (b *blockManager) Stop() error {
	if atomic.AddInt32(&b.shutdown, 1) != 1 {
		log.Warnf("Block manager is already in the process of " +
			"shutting down")
		return nil
	}

	log.Infof("Block manager shutting down")
	close(b.quit)
	b.wg.Wait()
	return nil
}

// NewPeer informs the block manager of a newly active peer.
func (b *blockManager) NewPeer(sp *serverPeer) {
	// Ignore if we are shutting down.
	if atomic.LoadInt32(&b.shutdown) != 0 {
		return
	}
	b.peerChan <- &newPeerMsg{peer: sp}
}

// handleNewPeerMsg deals with new peers that have signalled they may
// be considered as a sync peer (they have already successfully negotiated).  It
// also starts syncing if needed.  It is invoked from the syncHandler goroutine.
func (b *blockManager) handleNewPeerMsg(peers *list.List, sp *serverPeer) {
	// Ignore if in the process of shutting down.
	if atomic.LoadInt32(&b.shutdown) != 0 {
		return
	}

	log.Infof("New valid peer %s (%s)", sp, sp.UserAgent())

	// Ignore the peer if it's not a sync candidate.
	if !b.isSyncCandidate(sp) {
		return
	}

	// Add the peer as a candidate to sync from.
	peers.PushBack(sp)

	// Start syncing by choosing the best candidate if needed.
	b.startSync(peers)
}

// DonePeer informs the blockmanager that a peer has disconnected.
func (b *blockManager) DonePeer(sp *serverPeer) {
	// Ignore if we are shutting down.
	if atomic.LoadInt32(&b.shutdown) != 0 {
		return
	}

	b.peerChan <- &donePeerMsg{peer: sp}
}

// handleDonePeerMsg deals with peers that have signalled they are done.  It
// removes the peer as a candidate for syncing and in the case where it was
// the current sync peer, attempts to select a new best peer to sync from.  It
// is invoked from the syncHandler goroutine.
func (b *blockManager) handleDonePeerMsg(peers *list.List, sp *serverPeer) {
	// Remove the peer from the list of candidate peers.
	for e := peers.Front(); e != nil; e = e.Next() {
		if e.Value == sp {
			peers.Remove(e)
			break
		}
	}

	log.Infof("Lost peer %s", sp)

	// Attempt to find a new peer to sync from if the quitting peer is the
	// sync peer.  Also, reset the header state.
	if b.syncPeer != nil && b.syncPeer == sp {
		b.syncPeer = nil
		header, height, err := b.server.LatestBlock()
		if err != nil {
			return
		}
		b.resetHeaderState(&header, int32(height))
		b.startSync(peers)
	}
}

// blockHandler is the main handler for the block manager.  It must be run
// as a goroutine.  It processes block and inv messages in a separate goroutine
// from the peer handlers so the block (MsgBlock) messages are handled by a
// single thread without needing to lock memory data structures.  This is
// important because the block manager controls which blocks are needed and how
// the fetching should proceed.
func (b *blockManager) blockHandler() {
	candidatePeers := list.New()
out:
	for {
		// Check internal messages channel first and continue if there's
		// nothing to process.
		select {
		case m := <-b.intChan:
			switch msg := m.(type) {
			case *processCFHeadersMsg:
				b.handleProcessCFHeadersMsg(msg)

			default:
				log.Warnf("Invalid message type in block "+
					"handler: %T", msg)
			}
		default:
		}
		// Now check peer messages and quit channels.
		select {
		case m := <-b.peerChan:
			switch msg := m.(type) {
			case *newPeerMsg:
				b.handleNewPeerMsg(candidatePeers, msg.peer)

			/*case *blockMsg:
			b.handleBlockMsg(msg)
			msg.peer.blockProcessed <- struct{}{}*/

			case *invMsg:
				b.handleInvMsg(msg)

			case *headersMsg:
				b.handleHeadersMsg(msg)

			case *cfheadersMsg:
				b.handleCFHeadersMsg(msg)

			case *donePeerMsg:
				b.handleDonePeerMsg(candidatePeers, msg.peer)

			case getSyncPeerMsg:
				msg.reply <- b.syncPeer

			/*case processBlockMsg:
			_, isOrphan, err := b.chain.ProcessBlock(
				msg.block, msg.flags)
			if err != nil {
				msg.reply <- processBlockResponse{
					isOrphan: false,
					err:      err,
				}
			}

			msg.reply <- processBlockResponse{
				isOrphan: isOrphan,
				err:      nil,
			}*/

			case isCurrentMsg:
				msg.reply <- b.current()

			default:
				log.Warnf("Invalid message type in block "+
					"handler: %T", msg)
			}

		case <-b.quit:
			break out
		}
	}

	b.wg.Done()
	log.Trace("Block handler done")
}

// queueHandler reads the message channel and queues the message. This allows
// lookahead checks in

// isSyncCandidate returns whether or not the peer is a candidate to consider
// syncing from.
func (b *blockManager) isSyncCandidate(sp *serverPeer) bool {
	// The peer is not a candidate for sync if it's not a full node.
	return sp.Services()&wire.SFNodeNetwork == wire.SFNodeNetwork
}

// findNextHeaderCheckpoint returns the next checkpoint after the passed height.
// It returns nil when there is not one either because the height is already
// later than the final checkpoint or there are none for the current network.
func (b *blockManager) findNextHeaderCheckpoint(height int32) *chaincfg.Checkpoint {
	// There is no next checkpoint if there are none for this current
	// network.
	checkpoints := b.server.chainParams.Checkpoints
	if len(checkpoints) == 0 {
		return nil
	}

	// There is no next checkpoint if the height is already after the final
	// checkpoint.
	finalCheckpoint := &checkpoints[len(checkpoints)-1]
	if height >= finalCheckpoint.Height {
		return nil
	}

	// Find the next checkpoint.
	nextCheckpoint := finalCheckpoint
	for i := len(checkpoints) - 2; i >= 0; i-- {
		if height >= checkpoints[i].Height {
			break
		}
		nextCheckpoint = &checkpoints[i]
	}
	return nextCheckpoint
}

// findPreviousHeaderCheckpoint returns the last checkpoint before the passed
// height. It returns a checkpoint matching the genesis block when the height
// is earlier than the first checkpoint or there are no checkpoints for the
// current network. This is used for resettng state when a malicious peer sends
// us headers that don't lead up to a known checkpoint.
func (b *blockManager) findPreviousHeaderCheckpoint(height int32) *chaincfg.Checkpoint {
	// Start with the genesis block - earliest checkpoint to which our
	// code will want to reset
	prevCheckpoint := &chaincfg.Checkpoint{
		Height: 0,
		Hash:   b.server.chainParams.GenesisHash,
	}

	// Find the latest checkpoint lower than height or return genesis block
	// if there are none.
	checkpoints := b.server.chainParams.Checkpoints
	for i := 0; i < len(checkpoints); i++ {
		if height <= checkpoints[i].Height {
			break
		}
		prevCheckpoint = &checkpoints[i]
	}
	return prevCheckpoint
}

// resetHeaderState sets the headers-first mode state to values appropriate for
// syncing from a new peer.
func (b *blockManager) resetHeaderState(newestHeader *wire.BlockHeader,
	newestHeight int32) {
	b.headerList.Init()
	b.startHeader = nil
	b.mapMutex.Lock()
	b.basicHeaders = make(
		map[chainhash.Hash]map[chainhash.Hash][]*serverPeer,
	)
	b.extendedHeaders = make(
		map[chainhash.Hash]map[chainhash.Hash][]*serverPeer,
	)
	b.mapMutex.Unlock()

	// Add an entry for the latest known block into the header pool.
	// This allows the next downloaded header to prove it links to the chain
	// properly.
	node := headerNode{header: newestHeader, height: newestHeight}
	b.headerList.PushBack(&node)
	b.mapMutex.Lock()
	b.basicHeaders[newestHeader.BlockHash()] = make(
		map[chainhash.Hash][]*serverPeer,
	)
	b.extendedHeaders[newestHeader.BlockHash()] = make(
		map[chainhash.Hash][]*serverPeer,
	)
	b.mapMutex.Unlock()
}

// startSync will choose the best peer among the available candidate peers to
// download/sync the blockchain from.  When syncing is already running, it
// simply returns.  It also examines the candidates for any which are no longer
// candidates and removes them as needed.
func (b *blockManager) startSync(peers *list.List) {
	// Return now if we're already syncing.
	if b.syncPeer != nil {
		return
	}

	best, err := b.server.BestSnapshot()
	if err != nil {
		log.Errorf("Failed to get hash and height for the "+
			"latest block: %s", err)
		return
	}
	var bestPeer *serverPeer
	var enext *list.Element
	for e := peers.Front(); e != nil; e = enext {
		enext = e.Next()
		sp := e.Value.(*serverPeer)

		// Remove sync candidate peers that are no longer candidates due
		// to passing their latest known block.  NOTE: The < is
		// intentional as opposed to <=.  While techcnically the peer
		// doesn't have a later block when it's equal, it will likely
		// have one soon so it is a reasonable choice.  It also allows
		// the case where both are at 0 such as during regression test.
		if sp.LastBlock() < best.Height {
			peers.Remove(e)
			continue
		}

		// TODO: Use a better algorithm to choose the best peer.
		// For now, just pick the candidate with the highest last block.
		if bestPeer == nil || sp.LastBlock() > bestPeer.LastBlock() {
			bestPeer = sp
		}
	}

	// Start syncing from the best peer if one was selected.
	if bestPeer != nil {
		// Clear the requestedBlocks if the sync peer changes, otherwise
		// we may ignore blocks we need that the last sync peer failed
		// to send.
		b.requestedBlocks = make(map[chainhash.Hash]struct{})

		locator, err := b.server.LatestBlockLocator()
		if err != nil {
			log.Errorf("Failed to get block locator for the "+
				"latest block: %s", err)
			return
		}

		log.Infof("Syncing to block height %d from peer %s",
			bestPeer.LastBlock(), bestPeer.Addr())

		// When the current height is less than a known checkpoint we
		// can use block headers to learn about which blocks comprise
		// the chain up to the checkpoint and perform less validation
		// for them.  This is possible since each header contains the
		// hash of the previous header and a merkle root.  Therefore if
		// we validate all of the received headers link together
		// properly and the checkpoint hashes match, we can be sure the
		// hashes for the blocks in between are accurate.  Further, once
		// the full blocks are downloaded, the merkle root is computed
		// and compared against the value in the header which proves the
		// full block hasn't been tampered with.
		//
		// Once we have passed the final checkpoint, or checkpoints are
		// disabled, use standard inv messages learn about the blocks
		// and fully validate them.  Finally, regression test mode does
		// not support the headers-first approach so do normal block
		// downloads when in regression test mode.
		b.syncPeer = bestPeer
		if b.nextCheckpoint != nil &&
			best.Height < b.nextCheckpoint.Height {

			b.syncPeer.PushGetHeadersMsg(locator, b.nextCheckpoint.Hash)
			log.Infof("Downloading headers for blocks %d to "+
				"%d from peer %s", best.Height+1,
				b.nextCheckpoint.Height, bestPeer.Addr())
			// This will get adjusted when we process headers if
			// we request more headers than the peer is willing to
			// give us in one message.
		} else {
			b.syncPeer.PushGetBlocksMsg(locator, &zeroHash)
		}
	} else {
		log.Warnf("No sync peer candidates available")
	}
}

// current returns true if we believe we are synced with our peers, false if we
// still have blocks to check
func (b *blockManager) current() bool {
	// Figure out the latest block we know.
	header, height, err := b.server.LatestBlock()
	if err != nil {
		return false
	}

	// There is no last checkpoint if checkpoints are disabled or there are
	// none for this current network.
	checkpoints := b.server.chainParams.Checkpoints
	if len(checkpoints) != 0 {
		// We aren't current if the newest block we know of isn't ahead
		// of all checkpoints.
		if checkpoints[len(checkpoints)-1].Height >= int32(height) {
			return false
		}
	}

	// If we have a syncPeer and are below the block we are syncing to, we
	// are not current.
	if b.syncPeer != nil && int32(height) < b.syncPeer.LastBlock() {
		return false
	}

	// If our time source (median times of all the connected peers) is at
	// least 24 hours ahead of our best known block, we aren't current.
	minus24Hours := b.server.timeSource.AdjustedTime().Add(-24 * time.Hour)
	return !header.Timestamp.Before(minus24Hours)
}

// IsCurrent returns whether or not the block manager believes it is synced with
// the connected peers.
func (b *blockManager) IsCurrent() bool {
	reply := make(chan bool)
	b.peerChan <- isCurrentMsg{reply: reply}
	return <-reply
}

// QueueInv adds the passed inv message and peer to the block handling queue.
func (b *blockManager) QueueInv(inv *wire.MsgInv, sp *serverPeer) {
	// No channel handling here because peers do not need to block on inv
	// messages.
	if atomic.LoadInt32(&b.shutdown) != 0 {
		return
	}

	b.peerChan <- &invMsg{inv: inv, peer: sp}
}

// handleInvMsg handles inv messages from all peers.
// We examine the inventory advertised by the remote peer and act accordingly.
func (b *blockManager) handleInvMsg(imsg *invMsg) {
	// Attempt to find the final block in the inventory list.  There may
	// not be one.
	lastBlock := -1
	invVects := imsg.inv.InvList
	for i := len(invVects) - 1; i >= 0; i-- {
		if invVects[i].Type == wire.InvTypeBlock {
			lastBlock = i
			break
		}
	}

	// If this inv contains a block announcement, and this isn't coming from
	// our current sync peer or we're current, then update the last
	// announced block for this peer. We'll use this information later to
	// update the heights of peers based on blocks we've accepted that they
	// previously announced.
	if lastBlock != -1 && (imsg.peer != b.syncPeer || b.current()) {
		imsg.peer.UpdateLastAnnouncedBlock(&invVects[lastBlock].Hash)
	}

	// Ignore invs from peers that aren't the sync if we are not current.
	// Helps prevent dealing with orphans.
	if imsg.peer != b.syncPeer && !b.current() {
		return
	}

	// If our chain is current and a peer announces a block we already
	// know of, then update their current block height.
	if lastBlock != -1 && b.current() {
		_, blkHeight, err := b.server.GetBlockByHash(invVects[lastBlock].Hash)
		if err == nil {
			imsg.peer.UpdateLastBlockHeight(int32(blkHeight))
		}
	}

	// Add blocks to the cache of known inventory for the peer.
	for _, iv := range invVects {
		if iv.Type == wire.InvTypeBlock {
			imsg.peer.AddKnownInventory(iv)
		}
	}

	// If this is the sync peer or we're current, get the headers
	// for the announced blocks and update the last announced block.
	if lastBlock != -1 && (imsg.peer == b.syncPeer || b.current()) {
		lastEl := b.headerList.Back()
		var lastHash chainhash.Hash
		if lastEl != nil {
			lastHash = lastEl.Value.(*headerNode).header.BlockHash()
		}
		// Only send getheaders if we don't already know about the last
		// block hash being announced.
		if lastHash != invVects[lastBlock].Hash && lastEl != nil &&
			b.lastRequested != invVects[lastBlock].Hash {
			// Make a locator starting from the latest known header
			// we've processed.
			locator := make(blockchain.BlockLocator, 0,
				wire.MaxBlockLocatorsPerMsg)
			locator = append(locator, &lastHash)
			// Add locator from the database as backup.
			knownLocator, err := b.server.LatestBlockLocator()
			if err == nil {
				locator = append(locator, knownLocator...)
			}
			// Get headers based on locator.
			err = imsg.peer.PushGetHeadersMsg(locator,
				&invVects[lastBlock].Hash)
			if err != nil {
				log.Warnf("Failed to send getheaders message "+
					"to peer %s: %s", imsg.peer.Addr(), err)
				return
			}
			b.lastRequested = invVects[lastBlock].Hash
		}
	}
}

// QueueHeaders adds the passed headers message and peer to the block handling
// queue.
func (b *blockManager) QueueHeaders(headers *wire.MsgHeaders, sp *serverPeer) {
	// No channel handling here because peers do not need to block on
	// headers messages.
	if atomic.LoadInt32(&b.shutdown) != 0 {
		return
	}

	b.peerChan <- &headersMsg{headers: headers, peer: sp}
}

// handleHeadersMsg handles headers messages from all peers.
func (b *blockManager) handleHeadersMsg(hmsg *headersMsg) {
	msg := hmsg.headers
	numHeaders := len(msg.Headers)

	// Nothing to do for an empty headers message.
	if numHeaders == 0 {
		return
	}

	// For checking to make sure blocks aren't too far in the
	// future as of the time we receive the headers message.
	maxTimestamp := b.server.timeSource.AdjustedTime().
		Add(maxTimeOffset)

	// Process all of the received headers ensuring each one connects to the
	// previous and that checkpoints match.
	receivedCheckpoint := false
	var finalHash *chainhash.Hash
	var finalHeight int32
	for i, blockHeader := range msg.Headers {
		blockHash := blockHeader.BlockHash()
		finalHash = &blockHash

		// Ensure there is a previous header to compare against.
		prevNodeEl := b.headerList.Back()
		if prevNodeEl == nil {
			log.Warnf("Header list does not contain a previous" +
				"element as expected -- disconnecting peer")
			hmsg.peer.Disconnect()
			return
		}

		// Ensure the header properly connects to the previous one,
		// that the proof of work is good, and that the header's
		// timestamp isn't too far in the future, and add it to the
		// list of headers.
		node := headerNode{header: blockHeader}
		prevNode := prevNodeEl.Value.(*headerNode)
		prevHash := prevNode.header.BlockHash()
		if prevHash.IsEqual(&blockHeader.PrevBlock) {
			err := b.checkHeaderSanity(blockHeader, maxTimestamp,
				false)
			if err != nil {
				log.Warnf("Header doesn't pass sanity check: "+
					"%s -- disconnecting peer", err)
				hmsg.peer.Disconnect()
				return
			}
			node.height = prevNode.height + 1
			finalHeight = node.height
			err = b.server.putBlock(*blockHeader,
				uint32(node.height))
			if err != nil {
				log.Criticalf("Couldn't write block to "+
					"database: %s", err)
				// Should we panic here?
			}
			err = b.server.putMaxBlockHeight(uint32(node.height))
			if err != nil {
				log.Criticalf("Couldn't write max block height"+
					" to database: %s", err)
				// Should we panic here?
			}
			hmsg.peer.UpdateLastBlockHeight(node.height)
			e := b.headerList.PushBack(&node)
			b.mapMutex.Lock()
			b.basicHeaders[node.header.BlockHash()] = make(
				map[chainhash.Hash][]*serverPeer,
			)
			b.extendedHeaders[node.header.BlockHash()] = make(
				map[chainhash.Hash][]*serverPeer,
			)
			b.mapMutex.Unlock()
			if b.startHeader == nil {
				b.startHeader = e
			}
		} else {
			// The block doesn't connect to the last block we know.
			// We will need to do some additional checks to process
			// possible reorganizations or incorrect chain on either
			// our or the peer's side.
			// If we got these headers from a peer that's not our
			// sync peer, they might not be aligned correctly or
			// even on the right chain. Just ignore the rest of the
			// message. However, if we're current, this might be a
			// reorg, in which case we'll either change our sync
			// peer or disconnect the peer that sent us these
			// bad headers.
			if hmsg.peer != b.syncPeer && !b.current() {
				return
			}
			// Check if this is the last block we know of. This is
			// a shortcut for sendheaders so that each redundant
			// header doesn't cause a disk read.
			if blockHash == prevHash {
				continue
			}
			// Check if this block is known. If so, we continue to
			// the next one.
			_, _, err := b.server.GetBlockByHash(blockHash)
			if err == nil {
				continue
			}
			// Check if the previous block is known. If it is, this
			// is probably a reorg based on the estimated latest
			// block that matches between us and the peer as
			// derived from the block locator we sent to request
			// these headers. Otherwise, the headers don't connect
			// to anything we know and we should disconnect the
			// peer.
			backHead, backHeight, err := b.server.GetBlockByHash(
				blockHeader.PrevBlock)
			if err != nil {
				log.Warnf("Received block header that does not"+
					" properly connect to the chain from"+
					" peer %s (%s) -- disconnecting",
					hmsg.peer.Addr(), err)
				hmsg.peer.Disconnect()
				return
			}
			// We've found a branch we weren't aware of. If the
			// branch is earlier than the latest synchronized
			// checkpoint, it's invalid and we need to disconnect
			// the reporting peer.
			prevCheckpoint := b.findPreviousHeaderCheckpoint(
				prevNode.height)
			if backHeight < uint32(prevCheckpoint.Height) {
				log.Errorf("Attempt at a reorg earlier than a "+
					"checkpoint past which we've already "+
					"synchronized -- disconnecting peer "+
					"%s", hmsg.peer.Addr())
				hmsg.peer.Disconnect()
				return
			}
			// Check the sanity of the new branch. If any of the
			// blocks don't pass sanity checks, disconnect the peer.
			// We also keep track of the work represented by these
			// headers so we can compare it to the work in the known
			// good chain.
			b.reorgList.Init()
			b.reorgList.PushBack(&headerNode{
				header: &backHead,
				height: int32(backHeight),
			})
			totalWork := big.NewInt(0)
			for j, reorgHeader := range msg.Headers[i:] {
				err = b.checkHeaderSanity(reorgHeader,
					maxTimestamp, true)
				if err != nil {
					log.Warnf("Header doesn't pass sanity"+
						" check: %s -- disconnecting "+
						"peer", err)
					hmsg.peer.Disconnect()
					return
				}
				totalWork.Add(totalWork,
					blockchain.CalcWork(reorgHeader.Bits))
				b.reorgList.PushBack(&headerNode{
					header: reorgHeader,
					height: int32(backHeight+1) + int32(j),
				})
			}
			log.Tracef("Sane reorg attempted. Total work from "+
				"reorg chain: %v", totalWork)
			// All the headers pass sanity checks. Now we calculate
			// the total work for the known chain.
			knownWork := big.NewInt(0)
			// This should NEVER be nil because the most recent
			// block is always pushed back by resetHeaderState
			knownEl := b.headerList.Back()
			var knownHead wire.BlockHeader
			for j := uint32(prevNode.height); j > backHeight; j-- {
				if knownEl != nil {
					knownHead = *knownEl.Value.(*headerNode).header
					knownEl = knownEl.Prev()
				} else {
					knownHead, _, err = b.server.GetBlockByHash(
						knownHead.PrevBlock)
					if err != nil {
						log.Criticalf("Can't get block"+
							"header for hash %s: "+
							"%v",
							knownHead.PrevBlock,
							err)
						// Should we panic here?
					}
				}
				knownWork.Add(knownWork,
					blockchain.CalcWork(knownHead.Bits))
			}
			log.Tracef("Total work from known chain: %v", knownWork)
			// Compare the two work totals and reject the new chain
			// if it doesn't have more work than the previously
			// known chain. Disconnect if it's actually less than
			// the known chain.
			switch knownWork.Cmp(totalWork) {
			case 1:
				log.Warnf("Reorg attempt that has less work "+
					"than known chain from peer %s -- "+
					"disconnecting", hmsg.peer.Addr())
				hmsg.peer.Disconnect()
				fallthrough
			case 0:
				return
			default:
			}
			// At this point, we have a valid reorg, so we roll
			// back the existing chain and add the new block header.
			// We also change the sync peer. Then we can continue
			// with the rest of the headers in the message as if
			// nothing has happened.
			b.syncPeer = hmsg.peer
			_, err = b.server.rollBackToHeight(backHeight)
			if err != nil {
				log.Criticalf("Rollback failed: %s",
					err)
				// Should we panic here?
			}
			err = b.server.putBlock(*blockHeader, backHeight+1)
			if err != nil {
				log.Criticalf("Couldn't write block to "+
					"database: %s", err)
				// Should we panic here?
			}
			err = b.server.putMaxBlockHeight(backHeight + 1)
			if err != nil {
				log.Criticalf("Couldn't write max block height"+
					" to database: %s", err)
				// Should we panic here?
			}
			b.resetHeaderState(&backHead, int32(backHeight))
			b.headerList.PushBack(&headerNode{
				header: blockHeader,
				height: int32(backHeight + 1),
			})
			b.mapMutex.Lock()
			b.basicHeaders[blockHeader.BlockHash()] = make(
				map[chainhash.Hash][]*serverPeer,
			)
			b.extendedHeaders[blockHeader.BlockHash()] = make(
				map[chainhash.Hash][]*serverPeer,
			)
			b.mapMutex.Unlock()
			if b.lastBasicCFHeaderHeight > int32(backHeight) {
				b.lastBasicCFHeaderHeight = int32(backHeight)
			}
			if b.lastExtCFHeaderHeight > int32(backHeight) {
				b.lastExtCFHeaderHeight = int32(backHeight)
			}
		}

		// Verify the header at the next checkpoint height matches.
		if b.nextCheckpoint != nil &&
			node.height == b.nextCheckpoint.Height {
			nodeHash := node.header.BlockHash()
			if nodeHash.IsEqual(b.nextCheckpoint.Hash) {
				receivedCheckpoint = true
				log.Infof("Verified downloaded block "+
					"header against checkpoint at height "+
					"%d/hash %s", node.height, nodeHash)
			} else {
				log.Warnf("Block header at height %d/hash "+
					"%s from peer %s does NOT match "+
					"expected checkpoint hash of %s -- "+
					"disconnecting", node.height,
					nodeHash, hmsg.peer.Addr(),
					b.nextCheckpoint.Hash)
				prevCheckpoint :=
					b.findPreviousHeaderCheckpoint(
						node.height)
				log.Infof("Rolling back to previous validated "+
					"checkpoint at height %d/hash %s",
					prevCheckpoint.Height,
					prevCheckpoint.Hash)
				_, err := b.server.rollBackToHeight(uint32(
					prevCheckpoint.Height))
				if err != nil {
					log.Criticalf("Rollback failed: %s",
						err)
					// Should we panic here?
				}
				hmsg.peer.Disconnect()
				return
			}
			break
		}
	}

	// When this header is a checkpoint, switch to fetching the blocks for
	// all of the headers since the last checkpoint.
	if receivedCheckpoint {
		b.nextCheckpoint = b.findNextHeaderCheckpoint(finalHeight)
	}

	// Send getcfheaders to each peer based on these headers.
	cfhLocator := blockchain.BlockLocator([]*chainhash.Hash{
		&msg.Headers[0].PrevBlock,
	})
	cfhStopHash := msg.Headers[len(msg.Headers)-1].BlockHash()
	cfhCount := len(msg.Headers)
	cfhReqB := cfhRequest{
		extended: false,
		stopHash: cfhStopHash,
	}
	cfhReqE := cfhRequest{
		extended: true,
		stopHash: cfhStopHash,
	}
	b.server.ForAllPeers(func(sp *serverPeer) {
		// Should probably use better isolation for this but we're in
		// the same package. One of the things to clean up when we do
		// more general cleanup.
		sp.mtxReqCFH.Lock()
		sp.requestedCFHeaders[cfhReqB] = cfhCount
		sp.requestedCFHeaders[cfhReqE] = cfhCount
		sp.mtxReqCFH.Unlock()
		sp.pushGetCFHeadersMsg(cfhLocator, &cfhStopHash, false)
		sp.pushGetCFHeadersMsg(cfhLocator, &cfhStopHash, true)
	})

	// If not current, request the next batch of headers starting from the
	// latest known header and ending with the next checkpoint.
	if !b.current() || b.server.chainParams.Net ==
		chaincfg.SimNetParams.Net {
		locator := blockchain.BlockLocator([]*chainhash.Hash{finalHash})
		nextHash := zeroHash
		if b.nextCheckpoint != nil {
			nextHash = *b.nextCheckpoint.Hash
		}
		err := hmsg.peer.PushGetHeadersMsg(locator, &nextHash)
		if err != nil {
			log.Warnf("Failed to send getheaders message to "+
				"peer %s: %s", hmsg.peer.Addr(), err)
			// Unnecessary but we might put other code after this
			// eventually.
			return
		}
	}
}

// QueueCFHeaders adds the passed headers message and peer to the block handling
// queue.
func (b *blockManager) QueueCFHeaders(cfheaders *wire.MsgCFHeaders,
	sp *serverPeer) {
	// No channel handling here because peers do not need to block on
	// cfheaders messages.
	if atomic.LoadInt32(&b.shutdown) != 0 {
		return
	}

	// Ignore messages with 0 headers.
	if len(cfheaders.HeaderHashes) == 0 {
		return
	}

	// Check that the count is correct. This works even when the map lookup
	// fails as it returns 0 in that case.
	req := cfhRequest{
		extended: cfheaders.Extended,
		stopHash: cfheaders.StopHash,
	}
	// TODO: Get rid of this by refactoring all of this using the query API
	sp.mtxReqCFH.Lock()
	expLen := sp.requestedCFHeaders[req]
	sp.mtxReqCFH.Unlock()
	if expLen != len(cfheaders.HeaderHashes) {
		log.Warnf("Received cfheaders message doesn't match any "+
			"getcfheaders request. Peer %s is probably on a "+
			"different chain -- ignoring", sp.Addr())
		return
	}
	// TODO: Remove this by refactoring this section into a query client.
	sp.mtxReqCFH.Lock()
	delete(sp.requestedCFHeaders, req)
	sp.mtxReqCFH.Unlock()

	// Track number of pending cfheaders messsages for both basic and
	// extended filters.
	pendingMsgs := &b.numBasicCFHeadersMsgs
	if cfheaders.Extended {
		pendingMsgs = &b.numExtCFHeadersMsgs
	}
	atomic.AddInt32(pendingMsgs, 1)
	b.peerChan <- &cfheadersMsg{cfheaders: cfheaders, peer: sp}
}

// handleCFHeadersMsg handles cfheaders messages from all peers.
func (b *blockManager) handleCFHeadersMsg(cfhmsg *cfheadersMsg) {
	// Grab the matching request we sent, as this message should correspond
	// to that, and delete it from the map on return as we're now handling
	// it.
	headerMap := b.basicHeaders
	pendingMsgs := &b.numBasicCFHeadersMsgs
	if cfhmsg.cfheaders.Extended {
		headerMap = b.extendedHeaders
		pendingMsgs = &b.numExtCFHeadersMsgs
	}
	atomic.AddInt32(pendingMsgs, -1)
	headerList := cfhmsg.cfheaders.HeaderHashes
	respLen := len(headerList)
	// Find the block header matching the last filter header, if any.
	el := b.headerList.Back()
	for el != nil {
		if el.Value.(*headerNode).header.BlockHash() ==
			cfhmsg.cfheaders.StopHash {
			break
		}
		el = el.Prev()
	}
	// If nothing matched, there's nothing more to do.
	if el == nil {
		return
	}
	// Cycle through the filter header hashes and process them.
	var node *headerNode
	var hash chainhash.Hash
	for i := respLen - 1; i >= 0 && el != nil; i-- {
		// If there's no map for this header, the header is either no
		// longer valid or has already been processed and committed to
		// the database. Either way, break processing.
		node = el.Value.(*headerNode)
		hash = node.header.BlockHash()
		b.mapMutex.Lock()
		if _, ok := headerMap[hash]; !ok {
			b.mapMutex.Unlock()
			log.Tracef("Breaking at %d (%s)", node.height, hash)
			break
		}
		// Process this header and set up the next iteration.
		headerMap[hash][*headerList[i]] = append(
			headerMap[hash][*headerList[i]], cfhmsg.peer,
		)
		b.mapMutex.Unlock()
		el = el.Prev()
	}
	b.intChan <- &processCFHeadersMsg{
		earliestNode: node,
		stopHash:     cfhmsg.cfheaders.StopHash,
		extended:     cfhmsg.cfheaders.Extended,
	}
	log.Tracef("Processed cfheaders starting at %d(%s), ending at %s, from"+
		" peer %s, extended: %t", node.height, node.header.BlockHash(),
		cfhmsg.cfheaders.StopHash, cfhmsg.peer.Addr(),
		cfhmsg.cfheaders.Extended)
}

// handleProcessCFHeadersMsg checks to see if we have enough cfheaders to make
// a decision about what the correct headers are, makes that decision if
// possible, and downloads any cfilters and blocks necessary to make that
// decision.
func (b *blockManager) handleProcessCFHeadersMsg(msg *processCFHeadersMsg) {
	// Assume we aren't ready to make a decision about correct headers yet.
	ready := false

	headerMap := b.basicHeaders
	writeFunc := b.server.putBasicHeader
	readFunc := b.server.GetBasicHeader
	lastCFHeaderHeight := &b.lastBasicCFHeaderHeight
	pendingMsgs := &b.numBasicCFHeadersMsgs
	if msg.extended {
		headerMap = b.extendedHeaders
		writeFunc = b.server.putExtHeader
		readFunc = b.server.GetExtHeader
		lastCFHeaderHeight = &b.lastExtCFHeaderHeight
		pendingMsgs = &b.numExtCFHeadersMsgs
	}

	stopHash := msg.earliestNode.header.PrevBlock

	// If we have started receiving cfheaders messages for blocks farther
	// than the last set we haven't made a decision on, it's time to make
	// a decision.
	if msg.earliestNode.height > *lastCFHeaderHeight+1 {
		ready = true
	}

	// If we have fewer processed cfheaders messages for the earliest node
	// than the number of connected peers, give the other peers some time to
	// catch up before checking if we've processed all of the queued
	// cfheaders messages.
	numHeaders := 0
	blockMap := headerMap[msg.earliestNode.header.BlockHash()]
	for headerHash := range blockMap {
		numHeaders += len(blockMap[headerHash])
	}
	// Sleep for a bit if we have more peers than cfheaders messages for the
	// earliest node for which we're trying to get cfheaders. This lets us
	// wait for other peers to send cfheaders messages before making any
	// decisions about whether we should write the headers in this message.
	connCount := int(b.server.ConnectedCount())
	log.Tracef("Number of peers for which we've processed a cfheaders for "+
		"block %s: %d of %d", msg.earliestNode.header.BlockHash(),
		numHeaders, connCount)
	if numHeaders <= connCount {
		time.Sleep(WaitForMoreCFHeaders)
	}

	// If there are no other cfheaders messages left for this type (basic vs
	// extended), we should go ahead and make a decision because we have all
	// the info we're going to get.
	if atomic.LoadInt32(pendingMsgs) == 0 {
		ready = true
		stopHash = msg.stopHash
	}

	// Do nothing if we're not ready to make a decision yet.
	if !ready {
		return
	}

	// At this point, we've got all the cfheaders messages we're going to
	// get for the range of headers described by the passed message. We now
	// iterate through all of those headers, looking for conflicts. If we
	// find a conflict, we have to do additional checks; otherwise, we write
	// the filter header to the database.
	el := b.headerList.Front()
	for el != nil {
		node := el.Value.(*headerNode)
		hash := node.header.BlockHash()
		if node.height > *lastCFHeaderHeight {
			b.mapMutex.Lock()
			blockMap := headerMap[hash]
			switch len(blockMap) {
			// This should only happen if the filter has already
			// been written to the database.
			case 0:
				if _, err := readFunc(hash); err != nil {
					// We don't have the filter stored in
					// the DB, there's something wrong.
					log.Warnf("Somehow we have 0 cfheaders"+
						" for block %d (%s)",
						node.height, hash)
					b.mapMutex.Unlock()
					return
				}
			// This is the normal case when nobody's trying to
			// bamboozle us (or ALL our peers are).
			case 1:
				// This will only cycle once
				for headerHash := range blockMap {
					writeFunc(hash, headerHash)
					log.Tracef("Wrote header for block %d "+
						"with %d cfheaders messages, "+
						"extended: %t", node.height,
						len(blockMap[headerHash]),
						msg.extended)
				}
				*lastCFHeaderHeight = node.height
			// This is when we have conflicting information from
			// multiple peers.
			// TODO: Handle this case as an adversarial condition.
			default:
				log.Warnf("Got more than 1 possible filter "+
					"header for block %d (%s)", node.height,
					node.header.BlockHash())
			}
			b.mapMutex.Unlock()
		}

		//elToRemove := el
		el = el.Next()
		//b.headerList.Remove(elToRemove)
		//b.startHeader = el

		// If we've reached the end, we can return
		if hash == stopHash {
			log.Tracef("Finished processing cfheaders messages up "+
				"to height %d/hash %s, extended: %t",
				node.height, hash, msg.extended)
			return
		}
	}
}

// checkHeaderSanity checks the PoW, and timestamp of a block header.
func (b *blockManager) checkHeaderSanity(blockHeader *wire.BlockHeader,
	maxTimestamp time.Time, reorgAttempt bool) error {
	diff, err := b.calcNextRequiredDifficulty(
		blockHeader.Timestamp, reorgAttempt)
	if err != nil {
		return err
	}
	stubBlock := btcutil.NewBlock(&wire.MsgBlock{
		Header: *blockHeader,
	})
	err = blockchain.CheckProofOfWork(stubBlock,
		blockchain.CompactToBig(diff))
	if err != nil {
		return err
	}
	// Ensure the block time is not too far in the future.
	if blockHeader.Timestamp.After(maxTimestamp) {
		return fmt.Errorf("block timestamp of %v is too far in the "+
			"future", blockHeader.Timestamp)
	}
	return nil
}

// calcNextRequiredDifficulty calculates the required difficulty for the block
// after the passed previous block node based on the difficulty retarget rules.
func (b *blockManager) calcNextRequiredDifficulty(newBlockTime time.Time,
	reorgAttempt bool) (uint32, error) {

	hList := b.headerList
	if reorgAttempt {
		hList = b.reorgList
	}

	lastNodeEl := hList.Back()

	// Genesis block.
	if lastNodeEl == nil {
		return b.server.chainParams.PowLimitBits, nil
	}

	lastNode := lastNodeEl.Value.(*headerNode)

	// Return the previous block's difficulty requirements if this block
	// is not at a difficulty retarget interval.
	if (lastNode.height+1)%b.blocksPerRetarget != 0 {
		// For networks that support it, allow special reduction of the
		// required difficulty once too much time has elapsed without
		// mining a block.
		if b.server.chainParams.ReduceMinDifficulty {
			// Return minimum difficulty when more than the desired
			// amount of time has elapsed without mining a block.
			reductionTime := int64(
				b.server.chainParams.MinDiffReductionTime /
					time.Second)
			allowMinTime := lastNode.header.Timestamp.Unix() +
				reductionTime
			if newBlockTime.Unix() > allowMinTime {
				return b.server.chainParams.PowLimitBits, nil
			}

			// The block was mined within the desired timeframe, so
			// return the difficulty for the last block which did
			// not have the special minimum difficulty rule applied.
			prevBits, err := b.findPrevTestNetDifficulty(hList)
			if err != nil {
				return 0, err
			}
			return prevBits, nil
		}

		// For the main network (or any unrecognized networks), simply
		// return the previous block's difficulty requirements.
		return lastNode.header.Bits, nil
	}

	// Get the block node at the previous retarget (targetTimespan days
	// worth of blocks).
	firstNode, err := b.server.GetBlockByHeight(
		uint32(lastNode.height + 1 - b.blocksPerRetarget))
	if err != nil {
		return 0, err
	}

	// Limit the amount of adjustment that can occur to the previous
	// difficulty.
	actualTimespan := lastNode.header.Timestamp.Unix() -
		firstNode.Timestamp.Unix()
	adjustedTimespan := actualTimespan
	if actualTimespan < b.minRetargetTimespan {
		adjustedTimespan = b.minRetargetTimespan
	} else if actualTimespan > b.maxRetargetTimespan {
		adjustedTimespan = b.maxRetargetTimespan
	}

	// Calculate new target difficulty as:
	//  currentDifficulty * (adjustedTimespan / targetTimespan)
	// The result uses integer division which means it will be slightly
	// rounded down.  Bitcoind also uses integer division to calculate this
	// result.
	oldTarget := blockchain.CompactToBig(lastNode.header.Bits)
	newTarget := new(big.Int).Mul(oldTarget, big.NewInt(adjustedTimespan))
	targetTimeSpan := int64(b.server.chainParams.TargetTimespan /
		time.Second)
	newTarget.Div(newTarget, big.NewInt(targetTimeSpan))

	// Limit new value to the proof of work limit.
	if newTarget.Cmp(b.server.chainParams.PowLimit) > 0 {
		newTarget.Set(b.server.chainParams.PowLimit)
	}

	// Log new target difficulty and return it.  The new target logging is
	// intentionally converting the bits back to a number instead of using
	// newTarget since conversion to the compact representation loses
	// precision.
	newTargetBits := blockchain.BigToCompact(newTarget)
	log.Debugf("Difficulty retarget at block height %d", lastNode.height+1)
	log.Debugf("Old target %08x (%064x)", lastNode.header.Bits, oldTarget)
	log.Debugf("New target %08x (%064x)", newTargetBits,
		blockchain.CompactToBig(newTargetBits))
	log.Debugf("Actual timespan %v, adjusted timespan %v, target timespan %v",
		time.Duration(actualTimespan)*time.Second,
		time.Duration(adjustedTimespan)*time.Second,
		b.server.chainParams.TargetTimespan)

	return newTargetBits, nil
}

// findPrevTestNetDifficulty returns the difficulty of the previous block which
// did not have the special testnet minimum difficulty rule applied.
func (b *blockManager) findPrevTestNetDifficulty(hList *list.List) (uint32, error) {
	startNodeEl := hList.Back()

	// Genesis block.
	if startNodeEl == nil {
		return b.server.chainParams.PowLimitBits, nil
	}

	startNode := startNodeEl.Value.(*headerNode)

	// Search backwards through the chain for the last block without
	// the special rule applied.
	iterEl := startNodeEl
	iterNode := startNode.header
	iterHeight := startNode.height
	for iterNode != nil && iterHeight%b.blocksPerRetarget != 0 &&
		iterNode.Bits == b.server.chainParams.PowLimitBits {

		// Get the previous block node.  This function is used over
		// simply accessing iterNode.parent directly as it will
		// dynamically create previous block nodes as needed.  This
		// helps allow only the pieces of the chain that are needed
		// to remain in memory.
		iterHeight--
		el := iterEl.Prev()
		if el != nil {
			iterNode = el.Value.(*headerNode).header
		} else {
			node, err := b.server.GetBlockByHeight(
				uint32(iterHeight))
			if err != nil {
				log.Errorf("GetBlockByHeight: %s", err)
				return 0, err
			}
			iterNode = &node
		}
	}

	// Return the found difficulty or the minimum difficulty if no
	// appropriate block was found.
	lastBits := b.server.chainParams.PowLimitBits
	if iterNode != nil {
		lastBits = iterNode.Bits
	}
	return lastBits, nil
}

/*
import (
	"os"
	"path/filepath"
	"sort"

	"github.com/btcsuite/btcd/database"
)

// handleBlockMsg handles block messages from all peers.
func (b *blockManager) handleBlockMsg(bmsg *blockMsg) {
	// If we didn't ask for this block then the peer is misbehaving.
	blockHash := bmsg.block.Hash()
	if _, exists := bmsg.peer.requestedBlocks[*blockHash]; !exists {
		log.Warnf("Got unrequested block %v from %s -- "+
			"disconnecting", blockHash, bmsg.peer.Addr())
		bmsg.peer.Disconnect()
		return
	}

	// When in headers-first mode, if the block matches the hash of the
	// first header in the list of headers that are being fetched, it's
	// eligible for less validation since the headers have already been
	// verified to link together and are valid up to the next checkpoint.
	// Also, remove the list entry for all blocks except the checkpoint
	// since it is needed to verify the next round of headers links
	// properly.
	isCheckpointBlock := false
	behaviorFlags := blockchain.BFNone
	firstNodeEl := b.headerList.Front()
	if firstNodeEl != nil {
		firstNode := firstNodeEl.Value.(*headerNode)
		if blockHash.IsEqual(firstNode.hash) {
			behaviorFlags |= blockchain.BFFastAdd
			if firstNode.hash.IsEqual(b.nextCheckpoint.Hash) {
				isCheckpointBlock = true
			} else {
				b.headerList.Remove(firstNodeEl)
			}
		}
	}

	// Remove block from request maps. Either chain will know about it and
	// so we shouldn't have any more instances of trying to fetch it, or we
	// will fail the insert and thus we'll retry next time we get an inv.
	delete(bmsg.peer.requestedBlocks, *blockHash)
	delete(b.requestedBlocks, *blockHash)

	// Process the block to include validation, best chain selection, orphan
	// handling, etc.

        _, isOrphan, err := b.chain.ProcessBlock(bmsg.block, behaviorFlags)
	if err != nil {
		// When the error is a rule error, it means the block was simply
		// rejected as opposed to something actually going wrong, so log
		// it as such.  Otherwise, something really did go wrong, so log
		// it as an actual error.
		if _, ok := err.(blockchain.RuleError); ok {
			log.Infof("Rejected block %v from %s: %v", blockHash,
				bmsg.peer, err)
		} else {
			log.Errorf("Failed to process block %v: %v",
				blockHash, err)
		}
		if dbErr, ok := err.(database.Error); ok && dbErr.ErrorCode ==
			database.ErrCorruption {
			panic(dbErr)
		}

		// Convert the error into an appropriate reject message and
		// send it.
		code, reason := mempool.ErrToRejectErr(err)
		bmsg.peer.PushRejectMsg(wire.CmdBlock, code, reason,
			blockHash, false)
		return
	}

	// Meta-data about the new block this peer is reporting. We use this
	// below to update this peer's lastest block height and the heights of
	// other peers based on their last announced block hash. This allows us
	// to dynamically update the block heights of peers, avoiding stale
	// heights when looking for a new sync peer. Upon acceptance of a block
	// or recognition of an orphan, we also use this information to update
	// the block heights over other peers who's invs may have been ignored
	// if we are actively syncing while the chain is not yet current or
	// who may have lost the lock announcment race.
	var heightUpdate int32
	var blkHashUpdate *chainhash.Hash

	// Request the parents for the orphan block from the peer that sent it.
	if isOrphan {
		// We've just received an orphan block from a peer. In order
		// to update the height of the peer, we try to extract the
		// block height from the scriptSig of the coinbase transaction.
		// Extraction is only attempted if the block's version is
		// high enough (ver 2+).
		header := &bmsg.block.MsgBlock().Header
		if blockchain.ShouldHaveSerializedBlockHeight(header) {
			coinbaseTx := bmsg.block.Transactions()[0]
			cbHeight, err := blockchain.ExtractCoinbaseHeight(coinbaseTx)
			if err != nil {
				log.Warnf("Unable to extract height from "+
					"coinbase tx: %v", err)
			} else {
				log.Debugf("Extracted height of %v from "+
					"orphan block", cbHeight)
				heightUpdate = cbHeight
				blkHashUpdate = blockHash
			}
		}

		orphanRoot := b.chain.GetOrphanRoot(blockHash)
		locator, err := b.chain.LatestBlockLocator()
		if err != nil {
			log.Warnf("Failed to get block locator for the "+
				"latest block: %v", err)
		} else {
			bmsg.peer.PushGetBlocksMsg(locator, orphanRoot)
		}
	} else {
		// When the block is not an orphan, log information about it and
		// update the chain state.
		b.progressLogger.LogBlockHeight(bmsg.block)

		// Update this peer's latest block height, for future
		// potential sync node candidacy.
		best := b.chain.BestSnapshot()
		heightUpdate = best.Height
		blkHashUpdate = &best.Hash

		// Clear the rejected transactions.
		b.rejectedTxns = make(map[chainhash.Hash]struct{})

		// Allow any clients performing long polling via the
		// getblocktemplate RPC to be notified when the new block causes
		// their old block template to become stale.
		rpcServer := b.server.rpcServer
		if rpcServer != nil {
			rpcServer.gbtWorkState.NotifyBlockConnected(blockHash)
		}
	}

	// Update the block height for this peer. But only send a message to
	// the server for updating peer heights if this is an orphan or our
	// chain is "current". This avoids sending a spammy amount of messages
	// if we're syncing the chain from scratch.
	if blkHashUpdate != nil && heightUpdate != 0 {
		bmsg.peer.UpdateLastBlockHeight(heightUpdate)
		if isOrphan || b.current() {
			go b.server.UpdatePeerHeights(blkHashUpdate, heightUpdate, bmsg.peer)
		}
	}

	// Nothing more to do if we aren't in headers-first mode.
	if !b.headersFirstMode {
		return
	}

	// This is headers-first mode, so if the block is not a checkpoint
	// request more blocks using the header list when the request queue is
	// getting short.
	if !isCheckpointBlock {
		if b.startHeader != nil &&
			len(bmsg.peer.requestedBlocks) < minInFlightBlocks {
			b.fetchHeaderBlocks()
		}
		return
	}

	// This is headers-first mode and the block is a checkpoint.  When
	// there is a next checkpoint, get the next round of headers by asking
	// for headers starting from the block after this one up to the next
	// checkpoint.
	prevHeight := b.nextCheckpoint.Height
	prevHash := b.nextCheckpoint.Hash
	b.nextCheckpoint = b.findNextHeaderCheckpoint(prevHeight)
	if b.nextCheckpoint != nil {
		locator := blockchain.BlockLocator([]*chainhash.Hash{prevHash})
		err := bmsg.peer.PushGetHeadersMsg(locator, b.nextCheckpoint.Hash)
		if err != nil {
			log.Warnf("Failed to send getheaders message to "+
				"peer %s: %v", bmsg.peer.Addr(), err)
			return
		}
		log.Infof("Downloading headers for blocks %d to %d from "+
			"peer %s", prevHeight+1, b.nextCheckpoint.Height,
			b.syncPeer.Addr())
		return
	}

	// This is headers-first mode, the block is a checkpoint, and there are
	// no more checkpoints, so switch to normal mode by requesting blocks
	// from the block after this one up to the end of the chain (zero hash).
	b.headersFirstMode = false
	b.headerList.Init()
	log.Infof("Reached the final checkpoint -- switching to normal mode")
	locator := blockchain.BlockLocator([]*chainhash.Hash{blockHash})
	err = bmsg.peer.PushGetBlocksMsg(locator, &zeroHash)
	if err != nil {
		log.Warnf("Failed to send getblocks message to peer %s: %v",
			bmsg.peer.Addr(), err)
		return
	}
}

// fetchHeaderBlocks creates and sends a request to the syncPeer for the next
// list of blocks to be downloaded based on the current list of headers.
func (b *blockManager) fetchHeaderBlocks() {
	// Nothing to do if there is no start header.
	if b.startHeader == nil {
		log.Warnf("fetchHeaderBlocks called with no start header")
		return
	}

	// Build up a getdata request for the list of blocks the headers
	// describe.  The size hint will be limited to wire.MaxInvPerMsg by
	// the function, so no need to double check it here.
	gdmsg := wire.NewMsgGetDataSizeHint(uint(b.headerList.Len()))
	numRequested := 0
	for e := b.startHeader; e != nil; e = e.Next() {
		node, ok := e.Value.(*headerNode)
		if !ok {
			log.Warn("Header list node type is not a headerNode")
			continue
		}

		iv := wire.NewInvVect(wire.InvTypeBlock, node.hash)
		haveInv, err := b.haveInventory(iv)
		if err != nil {
			log.Warnf("Unexpected failure when checking for "+
				"existing inventory during header block "+
				"fetch: %v", err)
		}
		if !haveInv {
			b.requestedBlocks[*node.hash] = struct{}{}
			b.syncPeer.requestedBlocks[*node.hash] = struct{}{}
			gdmsg.AddInvVect(iv)
			numRequested++
		}
		b.startHeader = e.Next()
		if numRequested >= wire.MaxInvPerMsg {
			break
		}
	}
	if len(gdmsg.InvList) > 0 {
		b.syncPeer.QueueMessage(gdmsg, nil)
	}
}

// haveInventory returns whether or not the inventory represented by the passed
// inventory vector is known.  This includes checking all of the various places
// inventory can be when it is in different states such as blocks that are part
// of the main chain, on a side chain, in the orphan pool, and transactions that
// are in the memory pool (either the main pool or orphan pool).
func (b *blockManager) haveInventory(invVect *wire.InvVect) (bool, error) {
	switch invVect.Type {
	case wire.InvTypeBlock:
		// Ask chain if the block is known to it in any form (main
		// chain, side chain, or orphan).
		return b.chain.HaveBlock(&invVect.Hash)

	case wire.InvTypeTx:
		// Ask the transaction memory pool if the transaction is known
		// to it in any form (main pool or orphan).
		if b.server.txMemPool.HaveTransaction(&invVect.Hash) {
			return true, nil
		}

		// Check if the transaction exists from the point of view of the
		// end of the main chain.
		entry, err := b.chain.FetchUtxoEntry(&invVect.Hash)
		if err != nil {
			return false, err
		}
		return entry != nil && !entry.IsFullySpent(), nil
	}

	// The requested inventory is is an unsupported type, so just claim
	// it is known to avoid requesting it.
	return true, nil
}

// limitMap is a helper function for maps that require a maximum limit by
// evicting a random transaction if adding a new value would cause it to
// overflow the maximum allowed.
func (b *blockManager) limitMap(m map[chainhash.Hash]struct{}, limit int) {
	if len(m)+1 > limit {
		// Remove a random entry from the map.  For most compilers, Go's
		// range statement iterates starting at a random item although
		// that is not 100% guaranteed by the spec.  The iteration order
		// is not important here because an adversary would have to be
		// able to pull off preimage attacks on the hashing function in
		// order to target eviction of specific entries anyways.
		for txHash := range m {
			delete(m, txHash)
			return
		}
	}
}

// handleNotifyMsg handles notifications from blockchain.  It does things such
// as request orphan block parents and relay accepted blocks to connected peers.
func (b *blockManager) handleNotifyMsg(notification *blockchain.Notification) {
	switch notification.Type {
	// A block has been accepted into the block chain.  Relay it to other
	// peers.
	case blockchain.NTBlockAccepted:
		// Don't relay if we are not current. Other peers that are
		// current should already know about it.
		if !b.current() {
			return
		}

		block, ok := notification.Data.(*btcutil.Block)
		if !ok {
			log.Warnf("Chain accepted notification is not a block.")
			break
		}

		// Generate the inventory vector and relay it.
		//iv := wire.NewInvVect(wire.InvTypeBlock, block.Hash())
		//b.server.RelayInventory(iv, block.MsgBlock().Header)

	// A block has been connected to the main block chain.
	case blockchain.NTBlockConnected:
		block, ok := notification.Data.(*btcutil.Block)
		if !ok {
			log.Warnf("Chain connected notification is not a block.")
			break
		}

		// Remove all of the transactions (except the coinbase) in the
		// connected block from the transaction pool.  Secondly, remove any
		// transactions which are now double spends as a result of these
		// new transactions.  Finally, remove any transaction that is
		// no longer an orphan. Transactions which depend on a confirmed
		// transaction are NOT removed recursively because they are still
		// valid.
		for _, tx := range block.Transactions()[1:] {
			b.server.txMemPool.RemoveTransaction(tx, false)
			b.server.txMemPool.RemoveDoubleSpends(tx)
			b.server.txMemPool.RemoveOrphan(tx)
			acceptedTxs := b.server.txMemPool.ProcessOrphans(tx)
			b.server.AnnounceNewTransactions(acceptedTxs)
		}

		if r := b.server.rpcServer; r != nil {
			// Now that this block is in the blockchain we can mark
			// all the transactions (except the coinbase) as no
			// longer needing rebroadcasting.
			for _, tx := range block.Transactions()[1:] {
				iv := wire.NewInvVect(wire.InvTypeTx, tx.Hash())
				b.server.RemoveRebroadcastInventory(iv)
			}

			// Notify registered websocket clients of incoming block.
			r.ntfnMgr.NotifyBlockConnected(block)
		}

	// A block has been disconnected from the main block chain.
	case blockchain.NTBlockDisconnected:
		block, ok := notification.Data.(*btcutil.Block)
		if !ok {
			log.Warnf("Chain disconnected notification is not a block.")
			break
		}

		// Reinsert all of the transactions (except the coinbase) into
		// the transaction pool.
		for _, tx := range block.Transactions()[1:] {
			_, _, err := b.server.txMemPool.MaybeAcceptTransaction(tx,
				false, false)
			if err != nil {
				// Remove the transaction and all transactions
				// that depend on it if it wasn't accepted into
				// the transaction pool.
				b.server.txMemPool.RemoveTransaction(tx, true)
			}
		}

		// Notify registered websocket clients.
		if r := b.server.rpcServer; r != nil {
			r.ntfnMgr.NotifyBlockDisconnected(block)
		}
	}
}

// QueueBlock adds the passed block message and peer to the block handling queue.
func (b *blockManager) QueueBlock(block *btcutil.Block, sp *serverPeer) {
	// Don't accept more blocks if we're shutting down.
	if atomic.LoadInt32(&b.shutdown) != 0 {
		sp.blockProcessed <- struct{}{}
		return
	}

	b.msgChan <- &blockMsg{block: block, peer: sp}
}

// SyncPeer returns the current sync peer.
func (b *blockManager) SyncPeer() *serverPeer {
	reply := make(chan *serverPeer)
	b.msgChan <- getSyncPeerMsg{reply: reply}
	return <-reply
}

// ProcessBlock makes use of ProcessBlock on an internal instance of a block
// chain.  It is funneled through the block manager since btcchain is not safe
// for concurrent access.
func (b *blockManager) ProcessBlock(block *btcutil.Block, flags blockchain.BehaviorFlags) (bool, error) {
	reply := make(chan processBlockResponse, 1)
	b.msgChan <- processBlockMsg{block: block, flags: flags, reply: reply}
	response := <-reply
	return response.isOrphan, response.err
}


// checkpointSorter implements sort.Interface to allow a slice of checkpoints to
// be sorted.
type checkpointSorter []chaincfg.Checkpoint

// Len returns the number of checkpoints in the slice.  It is part of the
// sort.Interface implementation.
func (s checkpointSorter) Len() int {
	return len(s)
}

// Swap swaps the checkpoints at the passed indices.  It is part of the
// sort.Interface implementation.
func (s checkpointSorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less returns whether the checkpoint with index i should sort before the
// checkpoint with index j.  It is part of the sort.Interface implementation.
func (s checkpointSorter) Less(i, j int) bool {
	return s[i].Height < s[j].Height
}

// mergeCheckpoints returns two slices of checkpoints merged into one slice
// such that the checkpoints are sorted by height.  In the case the additional
// checkpoints contain a checkpoint with the same height as a checkpoint in the
// default checkpoints, the additional checkpoint will take precedence and
// overwrite the default one.
func mergeCheckpoints(defaultCheckpoints, additional []chaincfg.Checkpoint) []chaincfg.Checkpoint {
	// Create a map of the additional checkpoints to remove duplicates while
	// leaving the most recently-specified checkpoint.
	extra := make(map[int32]chaincfg.Checkpoint)
	for _, checkpoint := range additional {
		extra[checkpoint.Height] = checkpoint
	}

	// Add all default checkpoints that do not have an override in the
	// additional checkpoints.
	numDefault := len(defaultCheckpoints)
	checkpoints := make([]chaincfg.Checkpoint, 0, numDefault+len(extra))
	for _, checkpoint := range defaultCheckpoints {
		if _, exists := extra[checkpoint.Height]; !exists {
			checkpoints = append(checkpoints, checkpoint)
		}
	}

	// Append the additional checkpoints and return the sorted results.
	for _, checkpoint := range extra {
		checkpoints = append(checkpoints, checkpoint)
	}
	sort.Sort(checkpointSorter(checkpoints))
	return checkpoints
}

// removeRegressionDB removes the existing regression test database if running
// in regression test mode and it already exists.
func removeRegressionDB(dbPath string) error {
	// Don't do anything if not in regression test mode.
	if !cfg.RegressionTest {
		return nil
	}

	// Remove the old regression test database if it already exists.
	fi, err := os.Stat(dbPath)
	if err == nil {
		btcdLog.Infof("Removing regression test database from '%s'", dbPath)
		if fi.IsDir() {
			err := os.RemoveAll(dbPath)
			if err != nil {
				return err
			}
		} else {
			err := os.Remove(dbPath)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// dbPath returns the path to the block database given a database type.
func blockDbPath(dbType string) string {
	// The database name is based on the database type.
	dbName := blockDbNamePrefix + "_" + dbType
	if dbType == "sqlite" {
		dbName = dbName + ".db"
	}
	dbPath := filepath.Join(cfg.DataDir, dbName)
	return dbPath
}

// warnMultipeDBs shows a warning if multiple block database types are detected.
// This is not a situation most users want.  It is handy for development however
// to support multiple side-by-side databases.
func warnMultipeDBs() {
	// This is intentionally not using the known db types which depend
	// on the database types compiled into the binary since we want to
	// detect legacy db types as well.
	dbTypes := []string{"ffldb", "leveldb", "sqlite"}
	duplicateDbPaths := make([]string, 0, len(dbTypes)-1)
	for _, dbType := range dbTypes {
		if dbType == cfg.DbType {
			continue
		}

		// Store db path as a duplicate db if it exists.
		dbPath := blockDbPath(dbType)
		if fileExists(dbPath) {
			duplicateDbPaths = append(duplicateDbPaths, dbPath)
		}
	}

	// Warn if there are extra databases.
	if len(duplicateDbPaths) > 0 {
		selectedDbPath := blockDbPath(cfg.DbType)
		btcdLog.Warnf("WARNING: There are multiple block chain databases "+
			"using different database types.\nYou probably don't "+
			"want to waste disk space by having more than one.\n"+
			"Your current database is located at [%v].\nThe "+
			"additional database is located at %v", selectedDbPath,
			duplicateDbPaths)
	}
}

// loadBlockDB loads (or creates when needed) the block database taking into
// account the selected database backend and returns a handle to it.  It also
// contains additional logic such warning the user if there are multiple
// databases which consume space on the file system and ensuring the regression
// test database is clean when in regression test mode.
func loadBlockDB() (database.DB, error) {
	// The memdb backend does not have a file path associated with it, so
	// handle it uniquely.  We also don't want to worry about the multiple
	// database type warnings when running with the memory database.
	if cfg.DbType == "memdb" {
		btcdLog.Infof("Creating block database in memory.")
		db, err := database.Create(cfg.DbType)
		if err != nil {
			return nil, err
		}
		return db, nil
	}

	warnMultipeDBs()

	// The database name is based on the database type.
	dbPath := blockDbPath(cfg.DbType)

	// The regression test is special in that it needs a clean database for
	// each run, so remove it now if it already exists.
	removeRegressionDB(dbPath)

	btcdLog.Infof("Loading block database from '%s'", dbPath)
	db, err := database.Open(cfg.DbType, dbPath, activeNetParams.Net)
	if err != nil {
		// Return the error if it's not because the database doesn't
		// exist.
		if dbErr, ok := err.(database.Error); !ok || dbErr.ErrorCode !=
			database.ErrDbDoesNotExist {

			return nil, err
		}

		// Create the db if it does not exist.
		err = os.MkdirAll(cfg.DataDir, 0700)
		if err != nil {
			return nil, err
		}
		db, err = database.Create(cfg.DbType, dbPath, activeNetParams.Net)
		if err != nil {
			return nil, err
		}
	}

	btcdLog.Info("Block database loaded")
	return db, nil
}
*/
