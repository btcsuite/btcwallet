package chain

import (
	"bytes"
	"container/list"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/lightninglabs/gozmq"
)

// BitcoindClient represents a persistent client connection to a bitcoind server
// for information regarding the current best block chain.
type BitcoindClient struct {
	client      *rpcclient.Client
	connConfig  *rpcclient.ConnConfig // Work around unexported field
	chainParams *chaincfg.Params

	zmqConnect      string
	zmqPollInterval time.Duration

	enqueueNotification chan interface{}
	dequeueNotification chan interface{}
	currentBlock        chan *waddrmgr.BlockStamp

	clientMtx      sync.RWMutex
	rescanUpdate   chan interface{}
	startTime      time.Time
	watchOutPoints map[wire.OutPoint]struct{}
	watchAddrs     map[string]struct{}
	watchTxIDs     map[chainhash.Hash]struct{}
	notify         uint32

	quit    chan struct{}
	wg      sync.WaitGroup
	started bool
	quitMtx sync.Mutex

	memPool    map[chainhash.Hash]struct{}
	memPoolExp map[int32]map[chainhash.Hash]struct{}
}

// NewBitcoindClient creates a client connection to the server described by the
// connect string.  If disableTLS is false, the remote RPC certificate must be
// provided in the certs slice.  The connection is not established immediately,
// but must be done using the Start method.  If the remote server does not
// operate on the same bitcoin network as described by the passed chain
// parameters, the connection will be disconnected.
func NewBitcoindClient(chainParams *chaincfg.Params, connect, user, pass,
	zmqConnect string, zmqPollInterval time.Duration) (*BitcoindClient,
	error) {

	client := &BitcoindClient{
		connConfig: &rpcclient.ConnConfig{
			Host:                 connect,
			User:                 user,
			Pass:                 pass,
			DisableAutoReconnect: false,
			DisableConnectOnNew:  true,
			DisableTLS:           true,
			HTTPPostMode:         true,
		},
		chainParams:         chainParams,
		zmqConnect:          zmqConnect,
		zmqPollInterval:     zmqPollInterval,
		enqueueNotification: make(chan interface{}),
		dequeueNotification: make(chan interface{}),
		currentBlock:        make(chan *waddrmgr.BlockStamp),
		rescanUpdate:        make(chan interface{}),
		watchOutPoints:      make(map[wire.OutPoint]struct{}),
		watchAddrs:          make(map[string]struct{}),
		watchTxIDs:          make(map[chainhash.Hash]struct{}),
		quit:                make(chan struct{}),
		memPool:             make(map[chainhash.Hash]struct{}),
		memPoolExp:          make(map[int32]map[chainhash.Hash]struct{}),
	}
	rpcClient, err := rpcclient.New(client.connConfig, nil)
	if err != nil {
		return nil, err
	}
	client.client = rpcClient
	return client, nil
}

// BackEnd returns the name of the driver.
func (c *BitcoindClient) BackEnd() string {
	return "bitcoind"
}

// GetCurrentNet returns the network on which the bitcoind instance is running.
func (c *BitcoindClient) GetCurrentNet() (wire.BitcoinNet, error) {
	hash, err := c.client.GetBlockHash(0)
	if err != nil {
		return 0, err
	}

	switch *hash {
	case *chaincfg.TestNet3Params.GenesisHash:
		return chaincfg.TestNet3Params.Net, nil
	case *chaincfg.RegressionNetParams.GenesisHash:
		return chaincfg.RegressionNetParams.Net, nil
	case *chaincfg.MainNetParams.GenesisHash:
		return chaincfg.MainNetParams.Net, nil
	default:
		return 0, errors.New("unknown network")
	}
}

// GetBestBlock returns the highest block known to bitcoind.
func (c *BitcoindClient) GetBestBlock() (*chainhash.Hash, int32, error) {
	bcinfo, err := c.client.GetBlockChainInfo()
	if err != nil {
		return nil, 0, err
	}

	hash, err := chainhash.NewHashFromStr(bcinfo.BestBlockHash)
	if err != nil {
		return nil, 0, err
	}

	return hash, bcinfo.Blocks, nil
}

// GetBlockHeight returns the height for the hash, if known, or returns an
// error.
func (c *BitcoindClient) GetBlockHeight(hash *chainhash.Hash) (int32, error) {
	header, err := c.GetBlockHeaderVerbose(hash)
	if err != nil {
		return 0, err
	}

	return header.Height, nil
}

// GetBlock returns a block from the hash.
func (c *BitcoindClient) GetBlock(hash *chainhash.Hash) (*wire.MsgBlock,
	error) {
	return c.client.GetBlock(hash)
}

// GetBlockVerbose returns a verbose block from the hash.
func (c *BitcoindClient) GetBlockVerbose(hash *chainhash.Hash) (
	*btcjson.GetBlockVerboseResult, error) {
	return c.client.GetBlockVerbose(hash)
}

// GetBlockHash returns a block hash from the height.
func (c *BitcoindClient) GetBlockHash(height int64) (*chainhash.Hash, error) {
	return c.client.GetBlockHash(height)
}

// GetBlockHeader returns a block header from the hash.
func (c *BitcoindClient) GetBlockHeader(
	hash *chainhash.Hash) (*wire.BlockHeader, error) {
	return c.client.GetBlockHeader(hash)
}

// GetBlockHeaderVerbose returns a block header from the hash.
func (c *BitcoindClient) GetBlockHeaderVerbose(hash *chainhash.Hash) (
	*btcjson.GetBlockHeaderVerboseResult, error) {
	return c.client.GetBlockHeaderVerbose(hash)
}

// GetRawTransactionVerbose returns a transaction from the tx hash.
func (c *BitcoindClient) GetRawTransactionVerbose(hash *chainhash.Hash) (
	*btcjson.TxRawResult, error) {
	return c.client.GetRawTransactionVerbose(hash)
}

// GetTxOut returns a txout from the outpoint info provided.
func (c *BitcoindClient) GetTxOut(txHash *chainhash.Hash, index uint32,
	mempool bool) (*btcjson.GetTxOutResult, error) {
	return c.client.GetTxOut(txHash, index, mempool)
}

// NotifyReceived updates the watch list with the passed addresses.
func (c *BitcoindClient) NotifyReceived(addrs []btcutil.Address) error {
	c.NotifyBlocks()
	select {
	case c.rescanUpdate <- addrs:
	case <-c.quit:
	}
	return nil
}

// NotifySpent updates the watch list with the passed outPoints.
func (c *BitcoindClient) NotifySpent(outPoints []*wire.OutPoint) error {
	c.NotifyBlocks()
	select {
	case c.rescanUpdate <- outPoints:
	case <-c.quit:
	}
	return nil
}

// NotifyTxIDs updates the watch list with the passed TxIDs.
func (c *BitcoindClient) NotifyTxIDs(txids []chainhash.Hash) error {
	c.NotifyBlocks()
	select {
	case c.rescanUpdate <- txids:
	case <-c.quit:
	}
	return nil
}

// NotifyBlocks enables notifications.
func (c *BitcoindClient) NotifyBlocks() error {
	atomic.StoreUint32(&c.notify, 1)
	return nil
}

// notifying returns true if notifications have been turned on; false otherwise.
func (c *BitcoindClient) notifying() bool {
	return (atomic.LoadUint32(&c.notify) == 1)
}

// LoadTxFilter updates the transaction watchlists for the client. Acceptable
// arguments after `reset` are any combination of []btcutil.Address,
// []wire.OutPoint, []*wire.OutPoint, []chainhash.Hash, and []*chainhash.Hash.
func (c *BitcoindClient) LoadTxFilter(reset bool,
	watchLists ...interface{}) error {

	// If we reset, signal that.
	if reset {
		select {
		case c.rescanUpdate <- reset:
		case <-c.quit:
			return nil
		}
	}

	// This helper function will send an update to the filter. If the quit
	// channel is closed, it will allow the outer loop below to finish,
	// but skip over any updates as the quit case is triggered each time.
	sendList := func(list interface{}) {
		select {
		case c.rescanUpdate <- list:
		case <-c.quit:
		}
	}

	for _, watchList := range watchLists {
		switch list := watchList.(type) {
		case []wire.OutPoint:
			sendList(list)
		case []*wire.OutPoint:
			sendList(list)
		case []btcutil.Address:
			sendList(list)
		case []chainhash.Hash:
			sendList(list)
		case []*chainhash.Hash:
			sendList(list)
		default:
			log.Warnf("Couldn't add item to filter: unknown type")
		}
	}
	return nil
}

// RescanBlocks rescans any blocks passed, returning only the blocks that
// matched as []btcjson.BlockDetails.
func (c *BitcoindClient) RescanBlocks(blockHashes []chainhash.Hash) (
	[]btcjson.RescannedBlock, error) {

	rescannedBlocks := make([]btcjson.RescannedBlock, 0, len(blockHashes))
	for _, hash := range blockHashes {
		header, err := c.GetBlockHeaderVerbose(&hash)
		if err != nil {
			log.Warnf("Unable to get header %s from bitcoind: %s",
				hash, err)
			continue
		}

		block, err := c.GetBlock(&hash)
		if err != nil {
			log.Warnf("Unable to get block %s from bitcoind: %s",
				hash, err)
			continue
		}

		relevantTxes, err := c.filterBlock(block, header.Height, false)
		if len(relevantTxes) > 0 {
			rescannedBlock := btcjson.RescannedBlock{
				Hash: hash.String(),
			}
			for _, tx := range relevantTxes {
				rescannedBlock.Transactions = append(
					rescannedBlock.Transactions,
					hex.EncodeToString(tx.SerializedTx),
				)
			}
			rescannedBlocks = append(rescannedBlocks,
				rescannedBlock)
		}
	}
	return rescannedBlocks, nil
}

// Rescan rescans from the block with the given hash until the current block,
// after adding the passed addresses and outpoints to the client's watch list.
func (c *BitcoindClient) Rescan(blockHash *chainhash.Hash,
	addrs []btcutil.Address, outPoints map[wire.OutPoint]btcutil.Address) error {

	if blockHash == nil {
		return errors.New("rescan requires a starting block hash")
	}

	// Update addresses.
	select {
	case c.rescanUpdate <- addrs:
	case <-c.quit:
		return nil
	}

	// Update outpoints.
	select {
	case c.rescanUpdate <- outPoints:
	case <-c.quit:
		return nil
	}

	// Kick off the rescan with the starting block hash.
	select {
	case c.rescanUpdate <- blockHash:
	case <-c.quit:
		return nil
	}

	return nil
}

// SendRawTransaction sends a raw transaction via bitcoind.
func (c *BitcoindClient) SendRawTransaction(tx *wire.MsgTx,
	allowHighFees bool) (*chainhash.Hash, error) {

	return c.client.SendRawTransaction(tx, allowHighFees)
}

// Start attempts to establish a client connection with the remote server.
// If successful, handler goroutines are started to process notifications
// sent by the server.  After a limited number of connection attempts, this
// function gives up, and therefore will not block forever waiting for the
// connection to be established to a server that may not exist.
func (c *BitcoindClient) Start() error {
	// Verify that the server is running on the expected network.
	net, err := c.GetCurrentNet()
	if err != nil {
		c.client.Disconnect()
		return err
	}
	if net != c.chainParams.Net {
		c.client.Disconnect()
		return errors.New("mismatched networks")
	}

	// Connect a ZMQ socket for block notifications
	zmqClient, err := gozmq.Subscribe(c.zmqConnect, []string{"rawblock",
		"rawtx"}, c.zmqPollInterval)
	if err != nil {
		return err
	}

	c.quitMtx.Lock()
	c.started = true
	c.quitMtx.Unlock()

	c.wg.Add(2)
	go c.handler()
	go c.socketHandler(zmqClient)
	return nil
}

// Stop disconnects the client and signals the shutdown of all goroutines
// started by Start.
func (c *BitcoindClient) Stop() {
	c.quitMtx.Lock()
	select {
	case <-c.quit:
	default:
		close(c.quit)
		c.client.Shutdown()

		if !c.started {
			close(c.dequeueNotification)
		}
	}
	c.quitMtx.Unlock()
}

// WaitForShutdown blocks until both the client has finished disconnecting
// and all handlers have exited.
func (c *BitcoindClient) WaitForShutdown() {
	c.client.WaitForShutdown()
	c.wg.Wait()
}

// Notifications returns a channel of parsed notifications sent by the remote
// bitcoin RPC server.  This channel must be continually read or the process
// may abort for running out memory, as unread notifications are queued for
// later reads.
func (c *BitcoindClient) Notifications() <-chan interface{} {
	return c.dequeueNotification
}

// SetStartTime is a non-interface method to set the birthday of the wallet
// using this object. Since only a single rescan at a time is currently
// supported, only one birthday needs to be set. This does not fully restart a
// running rescan, so should not be used to update a rescan while it is running.
// TODO: When factoring out to multiple rescans per bitcoind client, add a
// birthday per client.
func (c *BitcoindClient) SetStartTime(startTime time.Time) {
	c.clientMtx.Lock()
	defer c.clientMtx.Unlock()

	c.startTime = startTime
}

// BlockStamp returns the latest block notified by the client, or an error
// if the client has been shut down.
func (c *BitcoindClient) BlockStamp() (*waddrmgr.BlockStamp, error) {
	select {
	case bs := <-c.currentBlock:
		return bs, nil
	case <-c.quit:
		return nil, errors.New("disconnected")
	}
}

func (c *BitcoindClient) onClientConnect() {
	select {
	case c.enqueueNotification <- ClientConnected{}:
	case <-c.quit:
	}
}

func (c *BitcoindClient) onBlockConnected(hash *chainhash.Hash, height int32, time time.Time) {
	if c.notifying() {
		select {
		case c.enqueueNotification <- BlockConnected{
			Block: wtxmgr.Block{
				Hash:   *hash,
				Height: height,
			},
			Time: time,
		}:
		case <-c.quit:
		}
	}
}

func (c *BitcoindClient) onFilteredBlockConnected(height int32,
	header *wire.BlockHeader, relevantTxs []*wtxmgr.TxRecord) {
	if c.notifying() {
		select {
		case c.enqueueNotification <- FilteredBlockConnected{
			Block: &wtxmgr.BlockMeta{
				Block: wtxmgr.Block{
					Hash:   header.BlockHash(),
					Height: height,
				},
				Time: header.Timestamp,
			},
			RelevantTxs: relevantTxs,
		}:
		case <-c.quit:
		}
	}
}

func (c *BitcoindClient) onBlockDisconnected(hash *chainhash.Hash, height int32, time time.Time) {
	if c.notifying() {
		select {
		case c.enqueueNotification <- BlockDisconnected{
			Block: wtxmgr.Block{
				Hash:   *hash,
				Height: height,
			},
			Time: time,
		}:
		case <-c.quit:
		}
	}
}

func (c *BitcoindClient) onRelevantTx(rec *wtxmgr.TxRecord,
	block *btcjson.BlockDetails) {
	blk, err := parseBlock(block)
	if err != nil {
		// Log and drop improper notification.
		log.Errorf("recvtx notification bad block: %v", err)
		return
	}

	select {
	case c.enqueueNotification <- RelevantTx{rec, blk}:
	case <-c.quit:
	}
}

func (c *BitcoindClient) onRescanProgress(hash *chainhash.Hash, height int32, blkTime time.Time) {
	select {
	case c.enqueueNotification <- &RescanProgress{hash, height, blkTime}:
	case <-c.quit:
	}
}

func (c *BitcoindClient) onRescanFinished(hash *chainhash.Hash, height int32, blkTime time.Time) {
	log.Infof("Rescan finished at %d (%s)", height, hash)
	select {
	case c.enqueueNotification <- &RescanFinished{hash, height, blkTime}:
	case <-c.quit:
	}

}

// socketHandler reads events from the ZMQ socket, processes them as
// appropriate, and queues them as btcd or neutrino would.
func (c *BitcoindClient) socketHandler(zmqClient *gozmq.Conn) {
	defer c.wg.Done()
	defer zmqClient.Close()

	log.Infof("Started listening for blocks via ZMQ on %s", c.zmqConnect)
	c.onClientConnect()

	// Get initial conditions.
	bestHash, bestHeight, err := c.GetBestBlock()
	if err != nil {
		log.Error(err)
		return
	}
	bestHeader, err := c.GetBlockHeaderVerbose(bestHash)
	if err != nil {
		log.Error(err)
		return
	}
	bs := &waddrmgr.BlockStamp{
		Height:    bestHeight,
		Hash:      *bestHash,
		Timestamp: time.Unix(bestHeader.Time, 0),
	}

mainLoop:
	for {
	selectLoop:
		for {
			// Check for any requests before we poll events from
			// bitcoind.
			select {

			// Quit if requested
			case <-c.quit:
				return

			// Update our monitored watchlists or do a rescan.
			case event := <-c.rescanUpdate:
				switch e := event.(type) {
				case struct{}:
					// We're clearing the watchlists.
					c.clientMtx.Lock()
					c.watchAddrs = make(map[string]struct{})
					c.watchTxIDs = make(map[chainhash.Hash]struct{})
					c.watchOutPoints =
						make(map[wire.OutPoint]struct{})
					c.clientMtx.Unlock()
				case []btcutil.Address:
					// We're updating monitored addresses.
					c.clientMtx.Lock()
					for _, addr := range e {
						c.watchAddrs[addr.EncodeAddress()] =
							struct{}{}
					}
					c.clientMtx.Unlock()
				case []*wire.OutPoint:
					// We're updating monitored outpoints
					// from pointers.
					c.clientMtx.Lock()
					for _, op := range e {
						c.watchOutPoints[*op] = struct{}{}
					}
					c.clientMtx.Unlock()
				case map[wire.OutPoint]btcutil.Address:
					// We're updating monitored outpoints.
					c.clientMtx.Lock()
					for op := range e {
						c.watchOutPoints[op] = struct{}{}
					}
					c.clientMtx.Unlock()
				case []*chainhash.Hash:
					// We're adding monitored TXIDs from
					// pointers.
					c.clientMtx.Lock()
					for _, txid := range e {
						c.watchTxIDs[*txid] = struct{}{}
					}
					c.clientMtx.Unlock()
				case []chainhash.Hash:
					// We're adding monitored TXIDs.
					c.clientMtx.Lock()
					for _, txid := range e {
						c.watchTxIDs[txid] = struct{}{}
					}
					c.clientMtx.Unlock()
				case *chainhash.Hash:
					// We're rescanning from the passed
					// hash.
					err = c.rescan(e)
					if err != nil {
						log.Errorf("rescan failed: %s",
							err)
					}
				}
			default:
				break selectLoop
			}
		}

		// Now, poll events from bitcoind.
		msgBytes, err := zmqClient.Receive()
		if err != nil {
			switch e := err.(type) {
			case net.Error:
				if !e.Timeout() {
					log.Error(err)
				}
			default:
				log.Error(err)
			}
			continue mainLoop
		}

		// We have an event!
		switch string(msgBytes[0]) {

		// We have a transaction, so process it.
		case "rawtx":
			tx := &wire.MsgTx{}
			err = tx.Deserialize(bytes.NewBuffer(msgBytes[1]))
			if err != nil {
				log.Error(err)
				continue mainLoop
			}
			// filterTx automatically detects whether this tx has
			// been mined and responds appropriately.
			_, _, err := c.filterTx(tx, nil, true)
			if err != nil {
				log.Error(err)
			}

		// We have a raw block, so we process it.
		case "rawblock":
			block := &wire.MsgBlock{}
			err = block.Deserialize(bytes.NewBuffer(msgBytes[1]))
			if err != nil {
				log.Error(err)
				continue mainLoop
			}

			// Check if the block is logically next. If not, we
			// have a reorg.
			if block.Header.PrevBlock == bs.Hash {
				// No reorg. Notify the subscriber of the block.
				bs.Hash = block.BlockHash()
				bs.Height++
				bs.Timestamp = block.Header.Timestamp
				_, err = c.filterBlock(block, bs.Height, true)
				if err != nil {
					log.Error(err)
				}
				continue mainLoop
			}

			// We have a reorg.
			err = c.reorg(bs, block)
			if err != nil {
				log.Errorf("Error during reorg: %v", err)
			}

		// Our event is not a block or other type we're
		// watching, so we ignore it.
		default:
		}
	}
}

// reorg processes a reorganization during chain synchronization. This is
// separate from a rescan's handling of a reorg.
func (c *BitcoindClient) reorg(bs *waddrmgr.BlockStamp, block *wire.MsgBlock) error {
	// We rewind until we find a common ancestor between the known chain
	//and the current chain, and then fast forward again. This relies on
	// being able to fetch both from bitcoind; to change that would require
	// changes in downstream code.
	// TODO: Make this more robust in order not to rely on this behavior.
	log.Debugf("Possible reorg at block %s", block.BlockHash())
	knownHeader, err := c.GetBlockHeader(&bs.Hash)
	if err != nil {
		return err
	}

	// We also get the best known height based on the block which was
	// notified. This way, we can preserve the chain of blocks we need to
	// retrieve.
	bestHash := block.BlockHash()
	bestHeight, err := c.GetBlockHeight(&bestHash)
	if err != nil {
		return err
	}
	if bestHeight < bs.Height {
		log.Debug("multiple reorgs in a row")
		return nil
	}

	// We track the block headers from the notified block to the current
	// block at the known block height. This will let us fast-forward
	// despite any future reorgs.
	var reorgBlocks list.List
	reorgBlocks.PushFront(block)
	for i := bestHeight - 1; i >= bs.Height; i-- {
		block, err = c.GetBlock(&block.Header.PrevBlock)
		if err != nil {
			return err
		}
		reorgBlocks.PushFront(block)
	}

	// Now we rewind back to the last common ancestor block, using the
	// prevblock hash from each header to avoid any race conditions. If we
	// get more reorgs, they'll be queued and we'll repeat the cycle.
	for block.Header.PrevBlock != knownHeader.PrevBlock {
		log.Debugf("Disconnecting block %d (%s)", bs.Height, bs.Hash)
		c.onBlockDisconnected(&bs.Hash, bs.Height,
			knownHeader.Timestamp)
		bs.Height--
		bs.Hash = knownHeader.PrevBlock
		block, err = c.GetBlock(&block.Header.PrevBlock)
		if err != nil {
			return err
		}
		reorgBlocks.PushFront(block)
		knownHeader, err = c.GetBlockHeader(&knownHeader.PrevBlock)
		if err != nil {
			return err
		}
		bs.Timestamp = knownHeader.Timestamp
	}

	// Disconnect the last block from the old chain. Since the PrevBlock is
	// equal between the old and new chains, the tip will now be the last
	// common ancestor.
	log.Debugf("Disconnecting block %d (%s)", bs.Height, bs.Hash)
	c.onBlockDisconnected(&bs.Hash, bs.Height, knownHeader.Timestamp)
	bs.Height--

	// Now we fast-forward to the notified block, notifying along the way.
	for reorgBlocks.Front() != nil {
		block = reorgBlocks.Front().Value.(*wire.MsgBlock)
		bs.Height++
		bs.Hash = block.BlockHash()
		c.filterBlock(block, bs.Height, true)
		reorgBlocks.Remove(reorgBlocks.Front())
	}

	return nil
}

// FilterBlocks scans the blocks contained in the FilterBlocksRequest for any
// addresses of interest. Each block will be fetched and filtered sequentially,
// returning a FilterBlocksReponse for the first block containing a matching
// address. If no matches are found in the range of blocks requested, the
// returned response will be nil.
func (c *BitcoindClient) FilterBlocks(
	req *FilterBlocksRequest) (*FilterBlocksResponse, error) {

	blockFilterer := NewBlockFilterer(c.chainParams, req)

	// Iterate over the requested blocks, fetching each from the rpc client.
	// Each block will scanned using the reverse addresses indexes generated
	// above, breaking out early if any addresses are found.
	for i, block := range req.Blocks {
		// TODO(conner): add prefetching, since we already know we'll be
		// fetching *every* block
		rawBlock, err := c.client.GetBlock(&block.Hash)
		if err != nil {
			return nil, err
		}

		if !blockFilterer.FilterBlock(rawBlock) {
			continue
		}

		// If any external or internal addresses were detected in this
		// block, we return them to the caller so that the rescan
		// windows can widened with subsequent addresses. The
		// `BatchIndex` is returned so that the caller can compute the
		// *next* block from which to begin again.
		resp := &FilterBlocksResponse{
			BatchIndex:         uint32(i),
			BlockMeta:          block,
			FoundExternalAddrs: blockFilterer.FoundExternal,
			FoundInternalAddrs: blockFilterer.FoundInternal,
			FoundOutPoints:     blockFilterer.FoundOutPoints,
			RelevantTxns:       blockFilterer.RelevantTxns,
		}

		return resp, nil
	}

	// No addresses were found for this range.
	return nil, nil
}

// rescan performs a rescan of the chain using a bitcoind back-end, from the
// specified hash to the best-known hash, while watching out for reorgs that
// happen during the rescan. It uses the addresses and outputs being tracked
// by the client in the watch list. This is called only within a queue
// processing loop.
func (c *BitcoindClient) rescan(hash *chainhash.Hash) error {
	// We start by getting the best already-processed block. We only use
	// the height, as the hash can change during a reorganization, which we
	// catch by testing connectivity from known blocks to the previous
	// block.
	log.Infof("Starting rescan from block %s", hash)
	bestHash, bestHeight, err := c.GetBestBlock()
	if err != nil {
		return err
	}
	bestHeader, err := c.GetBlockHeaderVerbose(bestHash)
	if err != nil {
		return err
	}
	bestBlock := &waddrmgr.BlockStamp{
		Hash:      *bestHash,
		Height:    bestHeight,
		Timestamp: time.Unix(bestHeader.Time, 0),
	}
	lastHeader, err := c.GetBlockHeaderVerbose(hash)
	if err != nil {
		return err
	}
	lastHash, err := chainhash.NewHashFromStr(lastHeader.Hash)
	if err != nil {
		return err
	}
	firstHeader := lastHeader

	headers := list.New()
	headers.PushBack(lastHeader)

	// We always send a RescanFinished message when we're done.
	defer func() {
		c.onRescanFinished(lastHash, lastHeader.Height, time.Unix(
			lastHeader.Time, 0))
	}()

	// Cycle through all of the blocks known to bitcoind, being mindful of
	// reorgs.
	for i := firstHeader.Height + 1; i <= bestBlock.Height; i++ {
		// Get the block at the current height.
		hash, err := c.GetBlockHash(int64(i))
		if err != nil {
			return err
		}

		// This relies on the fact that bitcoind returns blocks from
		// non-best chains it knows about.
		// TODO: Make this more robust in order to not rely on this
		// behavior.
		//
		// If the last known header isn't after the wallet birthday,
		// try only fetching the next header and constructing a dummy
		// block. If, in this event, the next header's timestamp is
		// after the wallet birthday, go ahead and fetch the full block.
		var block *wire.MsgBlock
		c.clientMtx.RLock()
		afterBirthday := lastHeader.Time >= c.startTime.Unix()
		c.clientMtx.RUnlock()
		if !afterBirthday {
			header, err := c.GetBlockHeader(hash)
			if err != nil {
				return err
			}
			block = &wire.MsgBlock{
				Header: *header,
			}
			c.clientMtx.RLock()
			afterBirthday = c.startTime.Before(header.Timestamp)
			if afterBirthday {
				c.onRescanProgress(lastHash, i,
					block.Header.Timestamp)
			}
			c.clientMtx.RUnlock()
		}

		if afterBirthday {
			block, err = c.GetBlock(hash)
			if err != nil {
				return err
			}
		}

		for block.Header.PrevBlock.String() != lastHeader.Hash {
			// If we're in this for loop, it looks like we've been
			// reorganized. We now walk backwards to the common
			// ancestor between the best chain and the known chain.
			//
			// First, we signal a disconnected block to rewind the
			// rescan state.
			c.onBlockDisconnected(lastHash, lastHeader.Height,
				time.Unix(lastHeader.Time, 0))

			// Next, we get the previous block of the best chain.
			hash, err = c.GetBlockHash(int64(i - 1))
			if err != nil {
				return err
			}

			block, err = c.GetBlock(hash)
			if err != nil {
				return err
			}

			// Then, we get the previous header for the known chain.
			if headers.Back() != nil {
				// If it's already in the headers list, we can
				// just get it from there and remove the
				// current hash).
				headers.Remove(headers.Back())
				if headers.Back() != nil {
					lastHeader = headers.Back().
						Value.(*btcjson.
						GetBlockHeaderVerboseResult)
					lastHash, err = chainhash.
						NewHashFromStr(lastHeader.Hash)
					if err != nil {
						return err
					}
				}
			} else {
				// Otherwise, we get it from bitcoind.
				lastHash, err = chainhash.NewHashFromStr(
					lastHeader.PreviousHash)
				if err != nil {
					return err
				}
				lastHeader, err = c.GetBlockHeaderVerbose(
					lastHash)
				if err != nil {
					return err
				}
			}
		}

		// We are at the latest known block, so we notify.
		lastHeader = &btcjson.GetBlockHeaderVerboseResult{
			Hash:         block.BlockHash().String(),
			Height:       i,
			PreviousHash: block.Header.PrevBlock.String(),
			Time:         block.Header.Timestamp.Unix(),
		}
		blockHash := block.BlockHash()
		lastHash = &blockHash
		headers.PushBack(lastHeader)

		_, err = c.filterBlock(block, i, true)
		if err != nil {
			return err
		}

		if i%10000 == 0 {
			c.onRescanProgress(lastHash, i, block.Header.Timestamp)
		}

		// If we've reached the previously best-known block, check to
		// make sure the underlying node hasn't synchronized additional
		// blocks. If it has, update the best-known block and continue
		// to rescan to that point.
		if i == bestBlock.Height {
			bestHash, bestHeight, err = c.GetBestBlock()
			if err != nil {
				return err
			}
			bestHeader, err = c.GetBlockHeaderVerbose(bestHash)
			if err != nil {
				return err
			}
			bestBlock = &waddrmgr.BlockStamp{
				Hash:      *bestHash,
				Height:    bestHeight,
				Timestamp: time.Unix(bestHeader.Time, 0),
			}
		}
	}

	return nil
}

// filterBlock filters a block for watched outpoints and addresses, and returns
// any matching transactions, sending notifications along the way.
func (c *BitcoindClient) filterBlock(block *wire.MsgBlock, height int32,
	notify bool) ([]*wtxmgr.TxRecord, error) {
	// If we're earlier than wallet birthday, don't do any notifications.
	c.clientMtx.RLock()
	startTime := c.startTime
	c.clientMtx.RUnlock()
	if block.Header.Timestamp.Before(startTime) {
		return nil, nil
	}

	// Only mention that we're filtering a block if the client wallet has
	// started monitoring the chain.
	if !c.notifying() {
		log.Debugf("Filtering block %d (%s) with %d transactions",
			height, block.BlockHash(), len(block.Transactions))
	}

	// Create block details for notifications.
	blockHash := block.BlockHash()
	blockDetails := &btcjson.BlockDetails{
		Hash:   blockHash.String(),
		Height: height,
		Time:   block.Header.Timestamp.Unix(),
	}

	// Cycle through all transactions in the block.
	var relevantTxs []*wtxmgr.TxRecord
	blockConfirmed := make(map[chainhash.Hash]struct{})
	for i, tx := range block.Transactions {
		// Update block and tx details for notifications.
		blockDetails.Index = i
		found, rec, err := c.filterTx(tx, blockDetails, notify)
		if err != nil {
			log.Warnf("Unable to filter tx: %v", err)
			continue
		}
		if found {
			relevantTxs = append(relevantTxs, rec)
			blockConfirmed[tx.TxHash()] = struct{}{}
		}
	}

	// Update the expiration map by setting the block's confirmed
	// transactions and deleting any in the mempool that were confirmed
	// over 288 blocks ago.
	c.clientMtx.Lock()
	c.memPoolExp[height] = blockConfirmed
	if oldBlock, ok := c.memPoolExp[height-288]; ok {
		for txHash := range oldBlock {
			delete(c.memPool, txHash)
		}
		delete(c.memPoolExp, height-288)
	}
	c.clientMtx.Unlock()

	if notify {
		c.onFilteredBlockConnected(height, &block.Header, relevantTxs)
		c.onBlockConnected(&blockHash, height, block.Header.Timestamp)
	}

	return relevantTxs, nil
}

// filterTx filters a single transaction against the client's watch list.
func (c *BitcoindClient) filterTx(tx *wire.MsgTx,
	blockDetails *btcjson.BlockDetails, notify bool) (bool,
	*wtxmgr.TxRecord, error) {

	txDetails := btcutil.NewTx(tx)
	if blockDetails != nil {
		txDetails.SetIndex(blockDetails.Index)
	}

	rec, err := wtxmgr.NewTxRecordFromMsgTx(txDetails.MsgTx(), time.Now())
	if err != nil {
		log.Errorf("Cannot create transaction record for relevant "+
			"tx: %v", err)
		return false, nil, err
	}
	if blockDetails != nil {
		rec.Received = time.Unix(blockDetails.Time, 0)
	}

	var notifyTx bool

	// If we already know this is a relevant tx from a previous ntfn, we
	// can shortcut the filter process and let the caller know the filter
	// matches.
	c.clientMtx.RLock()
	if _, ok := c.memPool[tx.TxHash()]; ok {
		c.clientMtx.RUnlock()
		if notify && blockDetails != nil {
			c.onRelevantTx(rec, blockDetails)
		}
		return true, rec, nil
	}
	c.clientMtx.RUnlock()

	// Cycle through outputs and check if we've matched a known address.
	// Add any matched outpoints to watchOutPoints.
	for i, out := range tx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			out.PkScript, c.chainParams)
		if err != nil {
			log.Debugf("Couldn't parse output script in %s:%d: %v",
				tx.TxHash(), i, err)
			continue
		}
		for _, addr := range addrs {
			c.clientMtx.RLock()
			if _, ok := c.watchAddrs[addr.EncodeAddress()]; ok {
				notifyTx = true
				c.watchOutPoints[wire.OutPoint{
					Hash:  tx.TxHash(),
					Index: uint32(i),
				}] = struct{}{}
			}
			c.clientMtx.RUnlock()
		}
	}

	// If an output hasn't already matched, see if an input will.
	if !notifyTx {
		for _, in := range tx.TxIn {
			c.clientMtx.RLock()
			if _, ok := c.watchOutPoints[in.PreviousOutPoint]; ok {
				c.clientMtx.RUnlock()
				notifyTx = true
				break
			}
			c.clientMtx.RUnlock()
		}
	}

	// If we have a match and it's not mined, notify the TX. If the TX is
	// mined, we notify as part of FilteredBlockConnected. The boolean map
	// value will let us know if we last saw it as mined or unmined.
	if notifyTx {
		c.clientMtx.Lock()
		if _, ok := c.memPool[tx.TxHash()]; blockDetails == nil || !ok {
			c.onRelevantTx(rec, blockDetails)
		}
		c.memPool[tx.TxHash()] = struct{}{}
		c.clientMtx.Unlock()
	}

	return notifyTx, rec, nil
}

// handler maintains a queue of notifications and the current state (best
// block) of the chain.
func (c *BitcoindClient) handler() {
	hash, height, err := c.GetBestBlock()
	if err != nil {
		log.Errorf("Failed to receive best block from chain server: %v", err)
		c.Stop()
		c.wg.Done()
		return
	}

	bs := &waddrmgr.BlockStamp{Hash: *hash, Height: height}

	// TODO: Rather than leaving this as an unbounded queue for all types of
	// notifications, try dropping ones where a later enqueued notification
	// can fully invalidate one waiting to be processed.  For example,
	// blockconnected notifications for greater block heights can remove the
	// need to process earlier blockconnected notifications still waiting
	// here.

	// TODO(aakselrod): Factor this logic out so it can be reused for each
	// chain back end, rather than copying it.

	var notifications []interface{}
	enqueue := c.enqueueNotification
	var dequeue chan interface{}
	var next interface{}
out:
	for {
		select {
		case n, ok := <-enqueue:
			if !ok {
				// If no notifications are queued for handling,
				// the queue is finished.
				if len(notifications) == 0 {
					break out
				}
				// nil channel so no more reads can occur.
				enqueue = nil
				continue
			}
			if len(notifications) == 0 {
				next = n
				dequeue = c.dequeueNotification
			}
			notifications = append(notifications, n)

		case dequeue <- next:
			if n, ok := next.(BlockConnected); ok {
				bs = &waddrmgr.BlockStamp{
					Height: n.Height,
					Hash:   n.Hash,
				}
			}

			notifications[0] = nil
			notifications = notifications[1:]
			if len(notifications) != 0 {
				next = notifications[0]
			} else {
				// If no more notifications can be enqueued, the
				// queue is finished.
				if enqueue == nil {
					break out
				}
				dequeue = nil
			}

		case c.currentBlock <- bs:

		case <-c.quit:
			break out
		}
	}

	c.Stop()
	close(c.dequeueNotification)
	c.wg.Done()
}
