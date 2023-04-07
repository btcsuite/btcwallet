package chain

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/gozmq"
)

const (
	// defaultBlockPollInterval is the default interval used for querying
	// for new blocks.
	defaultBlockPollInterval = time.Second * 10

	// defaultTxPollInterval is the default interval used for querying
	// for new mempool transactions.
	defaultTxPollInterval = time.Second * 10
)

// BitcoindEvents is the interface that must be satisfied by any type that
// serves bitcoind block and transactions events.
type BitcoindEvents interface {
	// TxNotifications will return a channel which will deliver new
	// transactions.
	TxNotifications() <-chan *wire.MsgTx

	// BlockNotifications will return a channel which will deliver new
	// blocks.
	BlockNotifications() <-chan *wire.MsgBlock

	// Start will kick off any goroutines required for operation.
	Start() error

	// Stop will clean up any resources and goroutines.
	Stop() error
}

// NewBitcoindEventSubscriber initialises a new BitcoinEvents object impl
// depending on the config passed.
func NewBitcoindEventSubscriber(cfg *BitcoindConfig,
	client *rpcclient.Client) (BitcoindEvents, error) {

	if cfg.PollingConfig != nil && cfg.ZMQConfig != nil {
		return nil, fmt.Errorf("either PollingConfig or ZMQConfig " +
			"should be specified, not both")
	}

	if cfg.PollingConfig != nil {
		if client == nil {
			return nil, fmt.Errorf("rpc client must be given " +
				"if rpc polling is to be used for event " +
				"subscriptions")
		}

		pollingEvents := newBitcoindRPCPollingEvents(
			cfg.PollingConfig, client,
		)

		return pollingEvents, nil
	}

	if cfg.ZMQConfig == nil {
		return nil, fmt.Errorf("ZMQConfig must be specified if " +
			"rpcpolling is disabled")
	}

	return newBitcoindZMQEvents(cfg.ZMQConfig)
}

// ZMQConfig holds all the config values needed to set up a ZMQ connection to
// bitcoind.
type ZMQConfig struct {
	// ZMQBlockHost is the IP address and port of the bitcoind's rawblock
	// listener.
	ZMQBlockHost string

	// ZMQTxHost is the IP address and port of the bitcoind's rawtx
	// listener.
	ZMQTxHost string

	// ZMQReadDeadline represents the read deadline we'll apply when reading
	// ZMQ messages from either subscription.
	ZMQReadDeadline time.Duration
}

// bitcoindZMQEvents delivers block and transaction notifications that it gets
// from ZMQ connections to bitcoind.
type bitcoindZMQEvents struct {
	cfg *ZMQConfig

	// blockConn is the ZMQ connection we'll use to read raw block events.
	blockConn *gozmq.Conn

	// txConn is the ZMQ connection we'll use to read raw transaction
	// events.
	txConn *gozmq.Conn

	// blockNtfns is a channel to which any new blocks will be sent.
	blockNtfns chan *wire.MsgBlock

	// txNtfns is a channel to which any new transactions will be sent.
	txNtfns chan *wire.MsgTx

	wg   sync.WaitGroup
	quit chan struct{}
}

// newBitcoindZMQEvents initialises the necessary zmq connections to bitcoind.
func newBitcoindZMQEvents(cfg *ZMQConfig) (*bitcoindZMQEvents, error) {
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
		// Ensure that the block zmq connection is closed in the case
		// that it succeeded but the tx zmq connection failed.
		if err := zmqBlockConn.Close(); err != nil {
			log.Errorf("could not close zmq block conn: %v", err)
		}

		return nil, fmt.Errorf("unable to subscribe for zmq tx "+
			"events: %v", err)
	}

	return &bitcoindZMQEvents{
		cfg:        cfg,
		blockConn:  zmqBlockConn,
		txConn:     zmqTxConn,
		blockNtfns: make(chan *wire.MsgBlock),
		txNtfns:    make(chan *wire.MsgTx),
		quit:       make(chan struct{}),
	}, nil
}

// Start spins off the bitcoindZMQEvent goroutines.
func (b *bitcoindZMQEvents) Start() error {
	b.wg.Add(2)
	go b.blockEventHandler()
	go b.txEventHandler()
	return nil
}

// Stop cleans up any of the resources and goroutines held by bitcoindZMQEvents.
func (b *bitcoindZMQEvents) Stop() error {
	var returnErr error
	if err := b.txConn.Close(); err != nil {
		returnErr = err
	}

	if err := b.blockConn.Close(); err != nil {
		returnErr = err
	}

	close(b.quit)
	b.wg.Wait()
	return returnErr
}

// TxNotifications returns a channel which will deliver new transactions.
func (b *bitcoindZMQEvents) TxNotifications() <-chan *wire.MsgTx {
	return b.txNtfns
}

// BlockNotifications returns a channel which will deliver new blocks.
func (b *bitcoindZMQEvents) BlockNotifications() <-chan *wire.MsgBlock {
	return b.blockNtfns
}

// blockEventHandler reads raw blocks events from the ZMQ block socket and
// forwards them along to the current rescan clients.
//
// NOTE: This must be run as a goroutine.
func (b *bitcoindZMQEvents) blockEventHandler() {
	defer b.wg.Done()

	log.Info("Started listening for bitcoind block notifications via ZMQ "+
		"on", b.blockConn.RemoteAddr())

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
		case <-b.quit:
			return
		default:
		}

		// Poll an event from the ZMQ socket.
		var (
			bufs = [][]byte{command[:], data, seqNum[:]}
			err  error
		)
		bufs, err = b.blockConn.Receive(bufs)
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

			select {
			case b.blockNtfns <- block:
			case <-b.quit:
				return
			}

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
func (b *bitcoindZMQEvents) txEventHandler() {
	defer b.wg.Done()

	log.Info("Started listening for bitcoind transaction notifications "+
		"via ZMQ on", b.txConn.RemoteAddr())

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
		case <-b.quit:
			return
		default:
		}

		// Poll an event from the ZMQ socket.
		var (
			bufs = [][]byte{command[:], data, seqNum[:]}
			err  error
		)
		bufs, err = b.txConn.Receive(bufs)
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

			select {
			case b.txNtfns <- tx:
			case <-b.quit:
				return
			}

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

// PollingConfig holds all the config options used for setting up
// bitcoindRPCPollingEvents.
type PollingConfig struct {
	// BlockPollingInterval is the interval that will be used to poll
	// bitcoind for new blocks.
	BlockPollingInterval time.Duration

	// TxPollingInterval is the interval that will be used to poll bitcoind
	// for new transactions. If a jitter factor is configed, it will be
	// applied to this value to provide randomness in the range,
	// - max: TxPollingInterval * (1 + TxPollingIntervalJitter)
	// - min: TxPollingInterval * (1 - TxPollingIntervalJitter)
	TxPollingInterval time.Duration

	// TxPollingIntervalScale defines a factor that's used to simulates
	// jitter by scaling TxPollingInterval with it. This value must be no
	// less than 0. Default to 0, meaning no jitter will be applied.
	TxPollingIntervalJitter float64
}

// bitcoindRPCPollingEvents delivers block and transaction notifications that
// it gets by polling bitcoind's rpc interface at regular intervals.
type bitcoindRPCPollingEvents struct {
	cfg *PollingConfig

	client *rpcclient.Client

	// mempool holds all the transactions that we currently see as being in
	// the mempool. This is used so that we know which transactions we have
	// already sent notifications for.
	mempool *mempool

	// blockNtfns is a channel to which any new blocks will be sent.
	blockNtfns chan *wire.MsgBlock

	// txNtfns is a channel to which any new transactions will be sent.
	txNtfns chan *wire.MsgTx

	wg   sync.WaitGroup
	quit chan struct{}
}

// newBitcoindRPCPollingEvents instantiates a new bitcoindRPCPollingEvents
// object.
func newBitcoindRPCPollingEvents(cfg *PollingConfig,
	client *rpcclient.Client) *bitcoindRPCPollingEvents {

	if cfg.BlockPollingInterval == 0 {
		cfg.BlockPollingInterval = defaultBlockPollInterval
	}

	if cfg.TxPollingInterval == 0 {
		cfg.TxPollingInterval = defaultTxPollInterval
	}

	// Floor the jitter value to be 0.
	if cfg.TxPollingIntervalJitter < 0 {
		log.Warnf("Jitter value(%v) must be positive, setting to 0",
			cfg.TxPollingIntervalJitter)
		cfg.TxPollingIntervalJitter = 0
	}

	return &bitcoindRPCPollingEvents{
		cfg:        cfg,
		client:     client,
		txNtfns:    make(chan *wire.MsgTx),
		blockNtfns: make(chan *wire.MsgBlock),
		mempool:    newMempool(),
		quit:       make(chan struct{}),
	}
}

// Start kicks off all the bitcoindRPCPollingEvents goroutines.
func (b *bitcoindRPCPollingEvents) Start() error {
	info, err := b.client.GetBlockChainInfo()
	if err != nil {
		return err
	}

	b.wg.Add(2)
	go b.blockEventHandlerRPC(info.Blocks)
	go b.txEventHandlerRPC()
	return nil
}

// Stop cleans up all the bitcoindRPCPollingEvents resources and goroutines.
func (b *bitcoindRPCPollingEvents) Stop() error {
	close(b.quit)
	b.wg.Wait()
	return nil
}

// TxNotifications returns a channel which will deliver new transactions.
func (b *bitcoindRPCPollingEvents) TxNotifications() <-chan *wire.MsgTx {
	return b.txNtfns
}

// BlockNotifications returns a channel which will deliver new blocks.
func (b *bitcoindRPCPollingEvents) BlockNotifications() <-chan *wire.MsgBlock {
	return b.blockNtfns
}

// blockEventHandlerRPC is a goroutine that uses the rpc client to check if we
// have a new block every so often.
func (b *bitcoindRPCPollingEvents) blockEventHandlerRPC(startHeight int32) {
	defer b.wg.Done()

	ticker := time.NewTicker(b.cfg.BlockPollingInterval)
	defer ticker.Stop()

	height := startHeight
	log.Infof("Started polling for new bitcoind blocks via RPC at "+
		"height %d", height)

	for {
		select {
		case <-ticker.C:
			// At every interval, we poll to see if there's a block
			// with a height that exceeds the height that we
			// previously recorded.
			info, err := b.client.GetBlockChainInfo()
			if err != nil {
				log.Errorf("Unable to retrieve best block: "+
					"%v", err)
				continue
			}

			// If the block isn't new, we continue and wait for the
			// next interval tick. In order to replicate the
			// behaviour of the zmq block subscription, we only do
			// a height based check here. We only deliver
			// notifications if the new block has a height above the
			// one we previously saw. The caller is left to
			// determine if there has been a reorg.
			if info.Blocks <= height {
				continue
			}

			// Since we do a height based check, we send
			// notifications for each block with a height between
			// the last height we recorded and the new height.
			for i := height + 1; i <= info.Blocks; i++ {
				newHash, err := b.client.GetBlockHash(int64(i))
				if err != nil {
					log.Errorf("Unable to retrieve "+
						"block hash: %v", err)
					continue
				}

				newBlock, err := b.client.GetBlock(newHash)
				if err != nil {
					log.Errorf("Unable to retrieve "+
						"block: %v", err)
					continue
				}

				// notify the client of the new block.
				select {
				case b.blockNtfns <- newBlock:
				case <-b.quit:
					return
				}

				// From our local mempool map, let's remove each
				// of the transactions that are confirmed in
				// this new block, since they are no longer in
				// the mempool.
				b.mempool.clean(newBlock.Transactions)

				height++
			}

		case <-b.quit:
			return
		}
	}
}

// txEventHandlerRPC is a goroutine that uses the RPC client to check the
// mempool for new transactions.
func (b *bitcoindRPCPollingEvents) txEventHandlerRPC() {
	defer b.wg.Done()

	log.Info("Started polling for new bitcoind transactions via RPC.")

	// Create a ticker that fires randomly.
	rand.Seed(time.Now().UnixNano())
	ticker := NewJitterTicker(
		b.cfg.TxPollingInterval, b.cfg.TxPollingIntervalJitter,
	)

	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// After each ticker interval, we poll the mempool to
			// check for transactions we haven't seen yet.
			txs, err := b.client.GetRawMempool()
			if err != nil {
				log.Errorf("Unable to retrieve mempool txs: "+
					"%v", err)
				continue
			}

			// Set all mempool txs to false.
			b.mempool.unmarkAll()

			// We'll scan through the most recent txs in the
			// mempool to see whether there are new txs that we
			// need to send to the client.
			for _, txHash := range txs {
				// If the transaction is already in our local
				// mempool, then we have already sent it to the
				// client.
				if b.mempool.contains(*txHash) {
					// Mark the tx as true so that we know
					// not to remove it from our internal
					// mempool.
					b.mempool.mark(*txHash)
					continue
				}

				// Grab full mempool transaction from hash.
				tx, err := b.client.GetRawTransaction(txHash)
				if err != nil {
					log.Errorf("unable to fetch "+
						"transaction %s from "+
						"mempool: %v", txHash, err)
					continue
				}

				// Add the transaction to our local mempool.
				// Note that we only do this after fetching
				// the full raw transaction from bitcoind.
				// We do this so that if that call happens to
				// initially fail, then we will retry it on the
				// next interval since it is still not in our
				// local mempool.
				b.mempool.add(*txHash)

				select {
				case b.txNtfns <- tx.MsgTx():
				case <-b.quit:
					return
				}
			}

			// Now, we clear our internal mempool of any unmarked
			// transactions. These are all the transactions that
			// we still have in the mempool but that were not
			// returned in the latest GetRawMempool query.
			b.mempool.deleteUnmarked()

		case <-b.quit:
			return
		}
	}
}

// mempool represents our view of the mempool and helps to keep track of which
// mempool transactions we already know about. The boolean in the txs map is
// used to indicate if we should remove the tx from our local mempool due to
// the chain backend's mempool no longer containing it.
type mempool struct {
	sync.RWMutex
	txs map[chainhash.Hash]bool
}

// newMempool creates a new mempool object.
func newMempool() *mempool {
	return &mempool{
		txs: make(map[chainhash.Hash]bool),
	}
}

// clean removes any of the given transactions from the mempool if they are
// found there.
func (m *mempool) clean(txs []*wire.MsgTx) {
	m.Lock()
	defer m.Unlock()

	for _, tx := range txs {
		// If the transaction is in our mempool map, we need to delete
		// it.
		delete(m.txs, tx.TxHash())
	}
}

// contains returns true if the given transaction hash is already in our
// mempool.
func (m *mempool) contains(hash chainhash.Hash) bool {
	m.RLock()
	defer m.RUnlock()

	_, ok := m.txs[hash]
	return ok
}

// add inserts the given hash into our mempool and marks it to indicate that it
// should not be deleted.
func (m *mempool) add(hash chainhash.Hash) {
	m.Lock()
	defer m.Unlock()

	m.txs[hash] = true
}

// unmarkAll un-marks all the transactions in the mempool. This should be done
// just before we re-evaluate the contents of our local mempool comared to the
// chain backend's mempool.
func (m *mempool) unmarkAll() {
	m.Lock()
	defer m.Unlock()

	for hash := range m.txs {
		m.txs[hash] = false
	}
}

// mark marks the transaction of the given hash to indicate that it is still
// present in the chain backend's mempool.
func (m *mempool) mark(hash chainhash.Hash) {
	m.Lock()
	defer m.Unlock()

	if _, ok := m.txs[hash]; !ok {
		return
	}

	m.txs[hash] = true
}

// deleteUnmarked removes all the unmarked transactions from our local mempool.
func (m *mempool) deleteUnmarked() {
	m.Lock()
	defer m.Unlock()

	for hash, marked := range m.txs {
		if marked {
			continue
		}

		delete(m.txs, hash)
	}
}
