package chain

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/gozmq"
	"github.com/lightningnetwork/lnd/ticker"
)

const (
	// rawBlockZMQCommand is the command used to receive raw block
	// notifications from bitcoind through ZMQ.
	rawBlockZMQCommand = "rawblock"

	// rawTxZMQCommand is the command used to receive raw transaction
	// notifications from bitcoind through ZMQ.
	rawTxZMQCommand = "rawtx"

	// maxRawBlockSize is the maximum size in bytes for a raw block received
	// from bitcoind through ZMQ.
	maxRawBlockSize = 4e6

	// maxRawTxSize is the maximum size in bytes for a raw transaction
	// received from bitcoind through ZMQ.
	maxRawTxSize = maxRawBlockSize

	// seqNumLen is the length of the sequence number of a message sent from
	// bitcoind through ZMQ.
	seqNumLen = 4

	// errBlockPrunedStr is the error message returned by bitcoind upon
	// calling GetBlock on a pruned block.
	errBlockPrunedStr = "Block not available (pruned data)"

	// defaulPollBlockTime sets how often we'll poll for fresh blocks.
	defaultPollBlockTime = time.Second * 10

	// defaultTxPollTime sets how oftwen we'll poll for fresh mempool
	// transactions.
	defaultPollTxTime = time.Second * 3

	// defaultCheckForOldTxsTime sets how often we'll check for lingering
	// transactions in the mempool map that may no longer be useful. This
	// is used when we're using RPC to poll for new txs and blocks, rather
	// than using ZMQ.
	defaultCheckForOldTxsTime = time.Hour * 24

	// defaultEvictionTime sets how long a transaction should be in our
	// mempool map before we kick it out.
	defaultEvictionTime = time.Hour * 24
)

// BitcoindConfig contains all of the parameters required to establish a
// connection to a bitcoind's RPC.
type BitcoindConfig struct {
	// ChainParams are the chain parameters the bitcoind server is running
	// on.
	ChainParams *chaincfg.Params

	// Host is the IP address and port of the bitcoind's RPC server.
	Host string

	// User is the username to use to authenticate to bitcoind's RPC server.
	User string

	// Pass is the passphrase to use to authenticate to bitcoind's RPC
	// server.
	Pass string

	// RPCPolling is set if we would rather retrieve new block and
	// transactions from polling RPC, rather than ZMQ.
	RPCPolling bool

	// ZMQBlockHost is the IP address and port of the bitcoind's rawblock
	// listener.
	ZMQBlockHost string

	// ZMQTxHost is the IP address and port of the bitcoind's rawtx
	// listener.
	ZMQTxHost string

	// ZMQReadDeadline represents the read deadline we'll apply when reading
	// ZMQ messages from either subscription.
	ZMQReadDeadline time.Duration

	// PollBlockTimer sets how often we'll poll for fresh blocks.
	PollBlockTimer time.Duration

	// PollTxTimer sets how often we'll poll for fresh txs from the mempool.
	PollTxTimer time.Duration

	// CheckForOldTxsTime sets how often we'll check for lingering
	// transactions in the mempool map that may no longer be useful. This
	// is used when we're using RPC to poll for new txs and blocks, rather
	// than using ZMQ.
	CheckForOldTxsTime time.Duration

	// EvictionTime sets how long a transaction can sit in our mempool map
	// before we kick it out.
	EvictionTime time.Duration

	// Dialer is a closure we'll use to dial Bitcoin peers. If the chain
	// backend is running over Tor, this must support dialing peers over Tor
	// as well.
	Dialer Dialer

	// PrunedModeMaxPeers is the maximum number of peers we'll attempt to
	// retrieve pruned blocks from.
	//
	// NOTE: This only applies for pruned bitcoind nodes.
	PrunedModeMaxPeers int
}

// BitcoindConn represents a persistent client connection to a bitcoind node
// that listens for events read from a ZMQ connection.
type BitcoindConn struct {
	started int32 // To be used atomically.
	stopped int32 // To be used atomically.

	// rescanClientCounter is an atomic counter that assigns a unique ID to
	// each new bitcoind rescan client using the current bitcoind
	// connection.
	rescanClientCounter uint64

	cfg BitcoindConfig

	// client is the RPC client to the bitcoind node.
	client *rpcclient.Client

	// prunedBlockDispatcher handles all of the pruned block requests.
	//
	// NOTE: This is nil when the bitcoind node is not pruned.
	prunedBlockDispatcher *PrunedBlockDispatcher

	// zmqBlockConn is the ZMQ connection we'll use to read raw block
	// events.
	zmqBlockConn *gozmq.Conn

	// zmqTxConn is the ZMQ connection we'll use to read raw transaction
	// events.
	zmqTxConn *gozmq.Conn

	// mempool keeps track of all of the transactions, needed
	// when polling rpc to obtain the latest transactions. This map allows
	// us to ensure we aren't processing any transactions more than
	// once.
	//
	// We'll keep a timestamp of when we retrieve each transaction, so
	// that we can prune any transactions that are too old. This helps to
	// prevent against forever holding transactions that were added to the
	// mempool, but were never confirmed.
	mempoolMtx sync.Mutex
	mempool    map[chainhash.Hash]time.Time

	// rescanClients is the set of active bitcoind rescan clients to which
	// ZMQ or RPC polling event notfications will be sent to.
	rescanClientsMtx sync.Mutex
	rescanClients    map[uint64]*BitcoindClient

	quit chan struct{}
	wg   sync.WaitGroup
}

// Dialer represents a way to dial Bitcoin peers. If the chain backend is
// running over Tor, this must support dialing peers over Tor as well.
type Dialer = func(string) (net.Conn, error)

// NewBitcoindConn creates a client connection to the node described by the host
// string. The ZMQ connections are established immediately to ensure liveness.
// If the remote node does not operate on the same bitcoin network as described
// by the passed chain parameters, the connection will be disconnected.
func NewBitcoindConn(cfg *BitcoindConfig) (*BitcoindConn, error) {
	clientCfg := &rpcclient.ConnConfig{
		Host:                 cfg.Host,
		User:                 cfg.User,
		Pass:                 cfg.Pass,
		DisableAutoReconnect: false,
		DisableConnectOnNew:  true,
		DisableTLS:           true,
		HTTPPostMode:         true,
	}
	client, err := rpcclient.New(clientCfg, nil)
	if err != nil {
		return nil, err
	}

	// Verify that the node is running on the expected network.
	net, err := getCurrentNet(client)
	if err != nil {
		return nil, err
	}
	if net != cfg.ChainParams.Net {
		return nil, fmt.Errorf("expected network %v, got %v",
			cfg.ChainParams.Net, net)
	}

	// Check if the node is pruned, as we'll need to perform additional
	// operations if so.
	chainInfo, err := client.GetBlockChainInfo()
	if err != nil {
		return nil, fmt.Errorf("unable to determine if bitcoind is "+
			"pruned: %v", err)
	}

	var (
		zmqBlockConn *gozmq.Conn
		zmqTxConn    *gozmq.Conn
	)
	// If we're polling for blocks and transactions via an RPC connection,
	// then we don't need to set up zmq connections.
	if !cfg.RPCPolling {
		// Establish two different ZMQ connections to bitcoind to
		// retrieve block and transaction event notifications. We'll
		// use two as a separation of concern to ensure one type of
		// event isn't dropped from the connection queue due to another
		// type of event filling it up.
		zmqBlockConn, err = gozmq.Subscribe(
			cfg.ZMQBlockHost, []string{rawBlockZMQCommand},
			cfg.ZMQReadDeadline,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to subscribe for zmq block "+
				"events: %v", err)
		}

		zmqTxConn, err = gozmq.Subscribe(
			cfg.ZMQTxHost, []string{rawTxZMQCommand}, cfg.ZMQReadDeadline,
		)
		if err != nil {
			zmqBlockConn.Close()
			return nil, fmt.Errorf("unable to subscribe for zmq tx "+
				"events: %v", err)
		}
	} else {
		// If custom poll times weren't set for polling for blocks and
		// transactions, we'll set it to the default polling time.
		if cfg.PollBlockTimer == 0 {
			cfg.PollBlockTimer = defaultPollBlockTime
		}
		if cfg.PollTxTimer == 0 {
			cfg.PollTxTimer = defaultPollTxTime
		}

		// Same for the time durations for checking for old txs in the
		// mempool.
		if cfg.CheckForOldTxsTime == 0 {
			cfg.CheckForOldTxsTime = defaultCheckForOldTxsTime
		}
		if cfg.EvictionTime == 0 {
			cfg.EvictionTime = defaultEvictionTime
		}
	}

	// Only initialize the PrunedBlockDispatcher when the connected bitcoind
	// node is pruned.
	var prunedBlockDispatcher *PrunedBlockDispatcher
	if chainInfo.Pruned {
		prunedBlockDispatcher, err = NewPrunedBlockDispatcher(
			&PrunedBlockDispatcherConfig{
				ChainParams:        cfg.ChainParams,
				NumTargetPeers:     cfg.PrunedModeMaxPeers,
				Dial:               cfg.Dialer,
				GetPeers:           client.GetPeerInfo,
				GetNodeAddresses:   client.GetNodeAddresses,
				PeerReadyTimeout:   defaultPeerReadyTimeout,
				RefreshPeersTicker: ticker.New(defaultRefreshPeersInterval),
				MaxRequestInvs:     wire.MaxInvPerMsg,
			},
		)
		if err != nil {
			return nil, err
		}
	}

	return &BitcoindConn{
		cfg:                   *cfg,
		client:                client,
		prunedBlockDispatcher: prunedBlockDispatcher,
		zmqBlockConn:          zmqBlockConn,
		zmqTxConn:             zmqTxConn,
		mempool:               make(map[chainhash.Hash]time.Time),
		rescanClients:         make(map[uint64]*BitcoindClient),
		quit:                  make(chan struct{}),
	}, nil
}

// Start attempts to establish a RPC and ZMQ connection to a bitcoind node. If
// successful, a goroutine is spawned to read events from the ZMQ connection.
// It's possible for this function to fail due to a limited number of connection
// attempts. This is done to prevent waiting forever on the connection to be
// established in the case that the node is down.
func (c *BitcoindConn) Start() error {
	if !atomic.CompareAndSwapInt32(&c.started, 0, 1) {
		return nil
	}

	// If we're connected to a pruned backend, we'll need to also start our
	// pruned block dispatcher to handle pruned block requests.
	if c.prunedBlockDispatcher != nil {
		log.Debug("Detected pruned bitcoind backend")
		if err := c.prunedBlockDispatcher.Start(); err != nil {
			return err
		}
	}

	if c.cfg.RPCPolling {
		c.wg.Add(3)
		go c.blockEventHandlerRPC()
		go c.txEventHandlerRPC()
		go c.checkForOldTxs()
	} else {
		c.wg.Add(2)
		go c.blockEventHandlerZMQ()
		go c.txEventHandlerZMQ()
	}

	return nil
}

// Stop terminates the RPC and ZMQ connection to a bitcoind node and removes any
// active rescan clients.
func (c *BitcoindConn) Stop() {
	if !atomic.CompareAndSwapInt32(&c.stopped, 0, 1) {
		return
	}

	for _, client := range c.rescanClients {
		client.Stop()
	}

	close(c.quit)
	c.client.Shutdown()
	if !c.cfg.RPCPolling {
		c.zmqBlockConn.Close()
		c.zmqTxConn.Close()
	}

	if c.prunedBlockDispatcher != nil {
		c.prunedBlockDispatcher.Stop()
	}

	c.client.WaitForShutdown()
	c.wg.Wait()
}

// blockEventHandler reads raw blocks events from the ZMQ block socket and
// forwards them along to the current rescan clients.
//
// NOTE: This must be run as a goroutine.
func (c *BitcoindConn) blockEventHandlerZMQ() {
	defer c.wg.Done()

	log.Info("Started listening for bitcoind block notifications via ZMQ "+
		"on", c.zmqBlockConn.RemoteAddr())

	// Set up the buffers we expect our messages to consume. ZMQ
	// messages from bitcoind include three parts: the command, the
	// data, and the sequence number.
	//
	// We'll allocate a fixed data slice that we'll reuse when reading
	// blocks from bitcoind through ZMQ. There's no need to recycle this
	// slice (zero out) after using it, as further reads will overwrite the
	// slice and we'll only be deserializing the bytes needed.
	var (
		command [len(rawBlockZMQCommand)]byte
		seqNum  [seqNumLen]byte
		data    = make([]byte, maxRawBlockSize)
	)

	for {
		// Before attempting to read from the ZMQ socket, we'll make
		// sure to check if we've been requested to shut down.
		select {
		case <-c.quit:
			return
		default:
		}

		// Poll an event from the ZMQ socket.
		var (
			bufs = [][]byte{command[:], data, seqNum[:]}
			err  error
		)
		bufs, err = c.zmqBlockConn.Receive(bufs)
		if err != nil {
			// EOF should only be returned if the connection was
			// explicitly closed, so we can exit at this point.
			if err == io.EOF {
				return
			}

			// It's possible that the connection to the socket
			// continuously times out, so we'll prevent logging this
			// error to prevent spamming the logs.
			netErr, ok := err.(net.Error)
			if ok && netErr.Timeout() {
				log.Trace("Re-establishing timed out ZMQ " +
					"block connection")
				continue
			}

			log.Errorf("Unable to receive ZMQ %v message: %v",
				rawBlockZMQCommand, err)
			continue
		}

		// We have an event! We'll now ensure it is a block event,
		// deserialize it, and report it to the different rescan
		// clients.
		eventType := string(bufs[0])
		switch eventType {
		case rawBlockZMQCommand:
			block := &wire.MsgBlock{}
			r := bytes.NewReader(bufs[1])
			if err := block.Deserialize(r); err != nil {
				log.Errorf("Unable to deserialize block: %v",
					err)
				continue
			}

			c.sendBlockToClients(block)

		default:
			// It's possible that the message wasn't fully read if
			// bitcoind shuts down, which will produce an unreadable
			// event type. To prevent from logging it, we'll make
			// sure it conforms to the ASCII standard.
			if eventType == "" || !isASCII(eventType) {
				continue
			}

			log.Warnf("Received unexpected event type from %v "+
				"subscription: %v", rawBlockZMQCommand,
				eventType)
		}
	}
}

// blockEventHandlerRPC is a goroutine that uses the rpc client to check if we
// have a new block every so often.
func (c *BitcoindConn) blockEventHandlerRPC() {
	defer c.wg.Done()

	log.Info("Started polling for new bitcoind blocks via RPC.")
	ticker := time.NewTicker(c.cfg.PollBlockTimer)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Every so many seconds, we poll to see if there's a new
			// block.
			newBlockHash, err := c.client.GetBestBlockHash()
			if err != nil || newBlockHash == nil {
				log.Errorf("Unable to retrieve best block "+
					"hash: %v", err)
				continue
			}
			newBlockHeader, err := c.client.GetBlockHeaderVerbose(
				newBlockHash,
			)
			if err != nil {
				log.Errorf("Unable to retrieve block height: "+
					"%v", err)
				continue
			}

			c.rescanClientsMtx.Lock()
			if c.rescanClients == nil || len(c.rescanClients) < 1 {
				log.Errorf("No client added yet")
				c.rescanClientsMtx.Unlock()
				continue
			}

			// Grab one of the clients from the rescanClients map
			// so we can look at its latest block height.
			var client *BitcoindClient
			for _, currClient := range c.rescanClients {
				client = currClient
				break
			}
			c.rescanClientsMtx.Unlock()

			// Check the block height of one of the clients to see
			// if we're up to date or not.
			bestBlock, err := client.BlockStamp()
			if err != nil {
				log.Errorf("Unable to get most recent block: "+
					"%v", err)
				continue
			}

			// If the block isn't new, we continue. Else, we need
			// grab the full block data to send to the clients.
			// Further, if the new block height is more than
			// oldBlock+1, we are behind on blocks and need to also
			// retrieve any missing blocks.
			switch {
			case newBlockHeader.Height == bestBlock.Height+1:
				newBlock, err := c.client.GetBlock(newBlockHash)
				if err != nil {
					log.Errorf("Unable to retrieve block: %v",
						err)
					continue
				}

				c.pruneMempoolTransactions(newBlock)
				c.sendBlockToClients(newBlock)

			case newBlockHeader.Height > bestBlock.Height+1:
				for i := 1; i < int(newBlockHeader.Height)-int(bestBlock.Height); i++ {
					blockHash, err := c.client.GetBlockHash(
						int64(bestBlock.Height) + int64(i),
					)
					if err != nil {
						log.Errorf("Unable to retrieve"+
							" block hash: %v", err)
						continue
					}

					newBlock, err := c.client.GetBlock(blockHash)
					if err != nil {
						log.Errorf("Unable to retrieve block: %v",
							err)
						continue
					}

					c.pruneMempoolTransactions(newBlock)
					c.sendBlockToClients(newBlock)
				}

			default:
				continue
			}

		case <-c.quit:
			return
		}
	}
}

// pruneMempoolTransactions loops through the txs is in the most recent block,
// and, since they're no longer in the mempol, deletes them from our local
// mempool map.
func (c *BitcoindConn) pruneMempoolTransactions(block *wire.MsgBlock) {
	// From the local mempool map, remove each
	// of the transactions that are confirmed in
	// this new block, since they are no longer in
	// the mempool.
	for _, tx := range block.Transactions {
		// If the transaction is in our mempool
		// map, we need to delete it.
		c.mempoolMtx.Lock()
		if _, ok := c.mempool[tx.TxHash()]; ok {
			delete(c.mempool, tx.TxHash())
		}
		c.mempoolMtx.Unlock()
	}
}

// sendBlockToClients sends the block to all of the clients waiting to be
// notified of the next block.
func (c *BitcoindConn) sendBlockToClients(block *wire.MsgBlock) {
	c.rescanClientsMtx.Lock()
	for _, client := range c.rescanClients {
		select {
		case client.blockNtfns <- block:
		case <-client.quit:
		case <-c.quit:
			c.rescanClientsMtx.Unlock()
			return
		}
	}
	c.rescanClientsMtx.Unlock()
}

// txEventHandler reads raw blocks events from the ZMQ block socket and forwards
// them along to the current rescan clients.
//
// NOTE: This must be run as a goroutine.
func (c *BitcoindConn) txEventHandlerZMQ() {
	defer c.wg.Done()

	log.Info("Started listening for bitcoind transaction notifications "+
		"via ZMQ on", c.zmqTxConn.RemoteAddr())

	// Set up the buffers we expect our messages to consume. ZMQ
	// messages from bitcoind include three parts: the command, the
	// data, and the sequence number.
	//
	// We'll allocate a fixed data slice that we'll reuse when reading
	// transactions from bitcoind through ZMQ. There's no need to recycle
	// this slice (zero out) after using it, as further reads will overwrite
	// the slice and we'll only be deserializing the bytes needed.
	var (
		command [len(rawTxZMQCommand)]byte
		seqNum  [seqNumLen]byte
		data    = make([]byte, maxRawTxSize)
	)

	for {
		// Before attempting to read from the ZMQ socket, we'll make
		// sure to check if we've been requested to shut down.
		select {
		case <-c.quit:
			return
		default:
		}

		// Poll an event from the ZMQ socket.
		var (
			bufs = [][]byte{command[:], data, seqNum[:]}
			err  error
		)
		bufs, err = c.zmqTxConn.Receive(bufs)
		if err != nil {
			// EOF should only be returned if the connection was
			// explicitly closed, so we can exit at this point.
			if err == io.EOF {
				return
			}

			// It's possible that the connection to the socket
			// continuously times out, so we'll prevent logging this
			// error to prevent spamming the logs.
			netErr, ok := err.(net.Error)
			if ok && netErr.Timeout() {
				log.Trace("Re-establishing timed out ZMQ " +
					"transaction connection")
				continue
			}

			log.Errorf("Unable to receive ZMQ %v message: %v",
				rawTxZMQCommand, err)
			continue
		}

		// We have an event! We'll now ensure it is a transaction event,
		// deserialize it, and report it to the different rescan
		// clients.
		eventType := string(bufs[0])
		switch eventType {
		case rawTxZMQCommand:
			tx := &wire.MsgTx{}
			r := bytes.NewReader(bufs[1])
			if err := tx.Deserialize(r); err != nil {
				log.Errorf("Unable to deserialize "+
					"transaction: %v", err)
				continue
			}

			c.rescanClientsMtx.Lock()
			for _, client := range c.rescanClients {
				select {
				case client.txNtfns <- tx:
				case <-client.quit:
				case <-c.quit:
					c.rescanClientsMtx.Unlock()
					return
				}
			}
			c.rescanClientsMtx.Unlock()
		default:
			// It's possible that the message wasn't fully read if
			// bitcoind shuts down, which will produce an unreadable
			// event type. To prevent from logging it, we'll make
			// sure it conforms to the ASCII standard.
			if eventType == "" || !isASCII(eventType) {
				continue
			}

			log.Warnf("Received unexpected event type from %v "+
				"subscription: %v", rawTxZMQCommand, eventType)
		}
	}
}

// txEventHandlerRPC is a goroutine that uses the RPC client to check the
// mempool for new transactions.
func (c *BitcoindConn) txEventHandlerRPC() {
	defer c.wg.Done()

	log.Info("Started polling for new bitcoind transactions via RPC.")
	ticker := time.NewTicker(c.cfg.PollTxTimer)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Every few seconds, we poll the mempool to check for
			// transactions we haven't seen yet.
			txs, err := c.client.GetRawMempool()
			if err != nil {
				log.Errorf("Unable to retrieve mempool"+
					" txs: %v", err)
				continue
			}

			// We'll scan through the most recent txs in the
			// mempool to see whether there are new txs that we
			// need to send to the client.
			for _, txHash := range txs {
				// If the transaction isn't in the local
				// mempool, we'll send it to all of the
				// clients.
				c.mempoolMtx.Lock()
				if _, ok := c.mempool[*txHash]; ok {
					c.mempoolMtx.Unlock()
					continue
				}
				c.mempoolMtx.Unlock()

				// Grab full mempool transaction from hash.
				tx, err := c.client.GetRawTransaction(
					txHash,
				)
				if err != nil {
					log.Errorf("Unable to retrieve raw "+
						"transaction hash %s: %v",
						txHash, err)
					continue
				}

				c.mempoolMtx.Lock()
				c.mempool[*txHash] = time.Now()
				c.mempoolMtx.Unlock()

				c.sendTxToClients(tx.MsgTx())
			}

		case <-c.quit:
			return
		}
	}
}

// sendTxToClients sends the tx to all of the clients waiting to be notified
// of the newest txs.
func (c *BitcoindConn) sendTxToClients(tx *wire.MsgTx) {
	c.rescanClientsMtx.Lock()
	for _, client := range c.rescanClients {
		select {
		case client.txNtfns <- tx:
		case <-client.quit:
		case <-c.quit:
			c.rescanClientsMtx.Unlock()
			return
		}
	}
	c.rescanClientsMtx.Unlock()
}

// checkForOldTxs looks at our local mempool map once every 24 hours, pruning
// any transactions that have been in it for a long time.
func (c *BitcoindConn) checkForOldTxs() {
	defer c.wg.Done()

	log.Info("Now checking for old unconfirmed transactions once every 24" +
		" hours.")
	ticker := time.NewTicker(defaultCheckForOldTxsTime)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.checkForUnconfTxs()
		case <-c.quit:
			return
		}
	}
}

// checkForUnconfTxs looks at the local mempool map, pruning any transactions
// that have been in it for a long time frame, since these mempool transactions
// might be
func (c *BitcoindConn) checkForUnconfTxs() {
	c.mempoolMtx.Lock()
	defer c.mempoolMtx.Unlock()

	for txHash, timeAdded := range c.mempool {
		if time.Now().Sub(timeAdded) > (defaultEvictionTime) {
			delete(c.mempool, txHash)
		}
	}
}

// getCurrentNet returns the network on which the bitcoind node is running.
func getCurrentNet(client *rpcclient.Client) (wire.BitcoinNet, error) {
	hash, err := client.GetBlockHash(0)
	if err != nil {
		return 0, err
	}

	switch *hash {
	case *chaincfg.TestNet3Params.GenesisHash:
		return chaincfg.TestNet3Params.Net, nil
	case *chaincfg.RegressionNetParams.GenesisHash:
		return chaincfg.RegressionNetParams.Net, nil
	case *chaincfg.SigNetParams.GenesisHash:
		return chaincfg.SigNetParams.Net, nil
	case *chaincfg.MainNetParams.GenesisHash:
		return chaincfg.MainNetParams.Net, nil
	default:
		return 0, fmt.Errorf("unknown network with genesis hash %v", hash)
	}
}

// NewBitcoindClient returns a bitcoind client using the current bitcoind
// connection. This allows us to share the same connection using multiple
// clients.
func (c *BitcoindConn) NewBitcoindClient() *BitcoindClient {
	return &BitcoindClient{
		quit: make(chan struct{}),

		id: atomic.AddUint64(&c.rescanClientCounter, 1),

		chainConn: c,

		rescanUpdate:     make(chan interface{}),
		watchedAddresses: make(map[string]struct{}),
		watchedOutPoints: make(map[wire.OutPoint]struct{}),
		watchedTxs:       make(map[chainhash.Hash]struct{}),

		notificationQueue: NewConcurrentQueue(20),
		txNtfns:           make(chan *wire.MsgTx),
		blockNtfns:        make(chan *wire.MsgBlock),

		mempool:        make(map[chainhash.Hash]struct{}),
		expiredMempool: make(map[int32]map[chainhash.Hash]struct{}),
	}
}

// AddClient adds a client to the set of active rescan clients of the current
// chain connection. This allows the connection to include the specified client
// in its notification delivery.
//
// NOTE: This function is safe for concurrent access.
func (c *BitcoindConn) AddClient(client *BitcoindClient) {
	c.rescanClientsMtx.Lock()
	defer c.rescanClientsMtx.Unlock()

	c.rescanClients[client.id] = client
}

// RemoveClient removes the client with the given ID from the set of active
// rescan clients. Once removed, the client will no longer receive block and
// transaction notifications from the chain connection.
//
// NOTE: This function is safe for concurrent access.
func (c *BitcoindConn) RemoveClient(id uint64) {
	c.rescanClientsMtx.Lock()
	defer c.rescanClientsMtx.Unlock()

	delete(c.rescanClients, id)
}

// isBlockPrunedErr determines if the error returned by the GetBlock RPC
// corresponds to the requested block being pruned.
func isBlockPrunedErr(err error) bool {
	rpcErr, ok := err.(*btcjson.RPCError)
	return ok && rpcErr.Code == btcjson.ErrRPCMisc &&
		rpcErr.Message == errBlockPrunedStr
}

// GetBlock returns a raw block from the server given its hash. If the server
// has already pruned the block, it will be retrieved from one of its peers.
func (c *BitcoindConn) GetBlock(hash *chainhash.Hash) (*wire.MsgBlock, error) {
	block, err := c.client.GetBlock(hash)
	// Got the block from the backend successfully, return it.
	if err == nil {
		return block, nil
	}

	// We failed getting the block from the backend for whatever reason. If
	// it wasn't due to the block being pruned, return the error
	// immediately.
	if !isBlockPrunedErr(err) || c.prunedBlockDispatcher == nil {
		return nil, err
	}

	// Now that we know the block has been pruned for sure, request it from
	// our backend peers.
	blockChan, errChan := c.prunedBlockDispatcher.Query(
		[]*chainhash.Hash{hash},
	)

	for {
		select {
		case block := <-blockChan:
			return block, nil

		case err := <-errChan:
			if err != nil {
				return nil, err
			}

			// errChan fired before blockChan with a nil error, wait
			// for the block now.

		case <-c.quit:
			return nil, ErrBitcoindClientShuttingDown
		}
	}
}

// isASCII is a helper method that checks whether all bytes in `data` would be
// printable ASCII characters if interpreted as a string.
func isASCII(s string) bool {
	for _, c := range s {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}
