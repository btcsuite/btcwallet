package chain

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
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

	// errStillLoadingCode is the error code returned when an RPC request
	// is made but bitcoind is still in the process of loading or verifying
	// blocks.
	errStillLoadingCode = "-28"

	// bitcoindStartTimeout is the time we wait for bitcoind to finish
	// loading and verifying blocks and become ready to serve RPC requests.
	bitcoindStartTimeout = 30 * time.Second
)

// ErrBitcoindStartTimeout is returned when the bitcoind daemon fails to load
// and verify blocks under 30s during startup.
var ErrBitcoindStartTimeout = errors.New("bitcoind start timeout")

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

	// ZMQConfig holds the configuration settings required for setting up
	// zmq connections to bitcoind.
	ZMQConfig *ZMQConfig

	// PollingConfig holds the configuration settings required for using
	// RPC polling for block and transaction notifications instead of the
	// ZMQ interface.
	PollingConfig *PollingConfig

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

	// events handles the block and transaction events that are received or
	// retrieved from bitcoind.
	events BitcoindEvents

	// rescanClients is the set of active bitcoind rescan clients to which
	// ZMQ event notifications will be sent to.
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

	batchClient, err := rpcclient.NewBatch(clientCfg)
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
			"pruned: %w", err)
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

	bc := &BitcoindConn{
		cfg:                   *cfg,
		client:                client,
		prunedBlockDispatcher: prunedBlockDispatcher,
		rescanClients:         make(map[uint64]*BitcoindClient),
		quit:                  make(chan struct{}),
	}

	bc.events, err = NewBitcoindEventSubscriber(cfg, client, batchClient)
	if err != nil {
		return nil, err
	}

	return bc, nil
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
	go c.sendBlockToClients()
	go c.sendTxToClients()

	return c.events.Start()
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

	if err := c.events.Stop(); err != nil {
		log.Errorf("error shutting down bitcoind events: %w", err)
	}

	if c.prunedBlockDispatcher != nil {
		c.prunedBlockDispatcher.Stop()
	}

	c.client.WaitForShutdown()
	c.wg.Wait()
}

// sendBlockToClients is used to notify all rescan clients of a new block. It
// MUST be run in a goroutine.
func (c *BitcoindConn) sendBlockToClients() {
	defer c.wg.Done()

	// sendBlock is a helper function that sends the given block to each
	// of the rescan clients
	sendBlock := func(block *wire.MsgBlock) {
		c.rescanClientsMtx.Lock()
		defer c.rescanClientsMtx.Unlock()

		for _, client := range c.rescanClients {
			select {
			case client.blockNtfns <- block:
			case <-client.quit:
			case <-c.quit:
				return
			}
		}
	}

	var block *wire.MsgBlock
	for {
		select {
		case block = <-c.events.BlockNotifications():
		case <-c.quit:
			return
		}

		sendBlock(block)
	}
}

// sendTxToClients is used to notify all rescan clients of a new transaction.
// It MUST be run as a goroutine.
func (c *BitcoindConn) sendTxToClients() {
	defer c.wg.Done()

	sendTx := func(tx *wire.MsgTx) {
		c.rescanClientsMtx.Lock()
		defer c.rescanClientsMtx.Unlock()

		for _, client := range c.rescanClients {
			select {
			case client.txNtfns <- tx:
			case <-client.quit:
			case <-c.quit:
				return
			}
		}
	}

	var tx *wire.MsgTx
	for {
		select {
		case tx = <-c.events.TxNotifications():
		case <-c.quit:
			return
		}

		sendTx(tx)
	}
}

// getBlockHashDuringStartup is used to call the getblockhash RPC during
// startup. It catches the case where bitcoind is still in the process of
// loading blocks, which returns the following error,
// - "-28: Loading block index..."
// - "-28: Verifying blocks..."
// In this case we'd retry every second until we time out after 30 seconds.
func getBlockHashDuringStartup(
	client *rpcclient.Client) (*chainhash.Hash, error) {

	hash, err := client.GetBlockHash(0)

	// Exit early if there's no error.
	if err == nil {
		return hash, nil
	}

	// If the error doesn't start with "-28", it's an unexpected error so
	// we exit with it.
	if !strings.Contains(err.Error(), errStillLoadingCode) {
		return nil, err
	}

	// Starts the timeout ticker(30s).
	timeout := time.After(bitcoindStartTimeout)

	// Otherwise, we'd retry calling getblockhash or time out after 30s.
	for {
		select {
		case <-timeout:
			return nil, ErrBitcoindStartTimeout

		// Retry every second.
		case <-time.After(1 * time.Second):
			hash, err = client.GetBlockHash(0)
			// If there's no error, we return the hash.
			if err == nil {
				return hash, nil
			}

			// Otherwise, retry until we time out. We also check if
			// the error returned here is still expected.
			if !strings.Contains(err.Error(), errStillLoadingCode) {
				return nil, err
			}
		}
	}
}

// getCurrentNet returns the network on which the bitcoind node is running.
func getCurrentNet(client *rpcclient.Client) (wire.BitcoinNet, error) {
	hash, err := getBlockHashDuringStartup(client)
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
		txNtfns:           make(chan *wire.MsgTx, 1000),
		blockNtfns:        make(chan *wire.MsgBlock, 100),

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

	// cancelChan is needed in case a block request with the same hash is
	// already registered and fails via the returned errChan. Because we
	// don't register a new request in this case this cancelChan is used
	// to signal the failure of the dependant block request.
	cancelChan := make(chan error, 1)

	// Now that we know the block has been pruned for sure, request it from
	// our backend peers.
	blockChan, errChan := c.prunedBlockDispatcher.Query(
		[]*chainhash.Hash{hash}, cancelChan,
	)

	for {
		select {
		case block := <-blockChan:
			return block, nil

		case err := <-errChan:
			if err != nil {
				// An error was returned for this block request.
				// We have to make sure we remove the blockhash
				// from the list of queried blocks.
				// Moreover because in case a block is requested
				// more than once no redundant block requests
				// are registered but rather a reply channel is
				// added to the pending block request. This
				// means we need to cancel all dependent
				// `GetBlock` calls via the cancel channel when
				// the fetching of the block was NOT successful.
				c.prunedBlockDispatcher.CancelRequest(
					*hash, err,
				)

				return nil, err
			}

			// errChan fired before blockChan with a nil error, wait
			// for the block now.

		// The cancelChan is only used when there is already a pending
		// block request for this hash and that block request fails via
		// the error channel above.
		case err := <-cancelChan:
			return nil, err

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
