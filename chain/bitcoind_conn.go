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

	// ZMQBlockHost is the IP address and port of the bitcoind's rawblock
	// listener.
	ZMQBlockHost string

	// ZMQTxHost is the IP address and port of the bitcoind's rawtx
	// listener.
	ZMQTxHost string

	// ZMQReadDeadline represents the read deadline we'll apply when reading
	// ZMQ messages from either subscription.
	ZMQReadDeadline time.Duration

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

	// rescanClients is the set of active bitcoind rescan clients to which
	// ZMQ event notfications will be sent to.
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

	// Establish two different ZMQ connections to bitcoind to retrieve block
	// and transaction event notifications. We'll use two as a separation of
	// concern to ensure one type of event isn't dropped from the connection
	// queue due to another type of event filling it up.
	zmqBlockConn, err := gozmq.Subscribe(
		cfg.ZMQBlockHost, []string{rawBlockZMQCommand},
		cfg.ZMQReadDeadline,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to subscribe for zmq block "+
			"events: %v", err)
	}

	zmqTxConn, err := gozmq.Subscribe(
		cfg.ZMQTxHost, []string{rawTxZMQCommand}, cfg.ZMQReadDeadline,
	)
	if err != nil {
		zmqBlockConn.Close()
		return nil, fmt.Errorf("unable to subscribe for zmq tx "+
			"events: %v", err)
	}

	// Only initialize the PrunedBlockDispatcher when the connected bitcoind
	// node is pruned.
	var prunedBlockDispatcher *PrunedBlockDispatcher
	if chainInfo.Pruned {
		prunedBlockDispatcher, err = NewPrunedBlockDispatcher(
			&PrunedBlockDispatcherConfig{
				ChainParams:      cfg.ChainParams,
				NumTargetPeers:   cfg.PrunedModeMaxPeers,
				Dial:             cfg.Dialer,
				GetPeers:         client.GetPeerInfo,
				PeerReadyTimeout: defaultPeerReadyTimeout,
				RefreshPeersTicker: ticker.New(
					defaultRefreshPeersInterval,
				),
				MaxRequestInvs: wire.MaxInvPerMsg,
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

	c.wg.Add(2)
	go c.blockEventHandler()
	go c.txEventHandler()

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
	c.zmqBlockConn.Close()
	c.zmqTxConn.Close()

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
func (c *BitcoindConn) blockEventHandler() {
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

			c.rescanClientsMtx.Lock()
			for _, client := range c.rescanClients {
				select {
				case client.zmqBlockNtfns <- block:
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
				"subscription: %v", rawBlockZMQCommand,
				eventType)
		}
	}
}

// txEventHandler reads raw blocks events from the ZMQ block socket and forwards
// them along to the current rescan clients.
//
// NOTE: This must be run as a goroutine.
func (c *BitcoindConn) txEventHandler() {
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
				case client.zmqTxNtfns <- tx:
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
		zmqTxNtfns:        make(chan *wire.MsgTx),
		zmqBlockNtfns:     make(chan *wire.MsgBlock),

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
