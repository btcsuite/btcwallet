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

	// MempoolPollingInterval is the interval that will be used to poll
	// bitcoind to update the local mempool. If a jitter factor is
	// configed, it will be
	// applied to this value to provide randomness in the range,
	// - max: MempoolPollingInterval * (1 + PollingIntervalJitter)
	// - min: MempoolPollingInterval * (1 - PollingIntervalJitter)
	//
	// TODO(yy): replace this temp config with SEQUENCE check.
	MempoolPollingInterval time.Duration

	// PollingIntervalJitter a factor that's used to simulates jitter by
	// scaling MempoolPollingInterval with it. This value must be no less
	// than 0. Default to 0, meaning no jitter will be applied.
	//
	// TODO(yy): replace this temp config with SEQUENCE check.
	PollingIntervalJitter float64

	// RPCBatchSize defines the number of RPC requests to be batches before
	// sending them to the bitcoind node.
	RPCBatchSize uint32

	// RPCBatchInterval defines the time to wait before attempting the next
	// batch when the current one finishes.
	RPCBatchInterval time.Duration
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

	// mempool holds all the transactions that we currently see as being in
	// the mempool. This is used so that we know which transactions we have
	// already sent notifications for. This will be nil if we are using the
	// gettxspendingprevout endpoint.
	mempool *mempool

	// client is an rpc client to the bitcoind backend.
	client *rpcclient.Client

	// hasPrevoutRPC is set when the bitcoind version is >= 24.0.0 and
	// doesn't need to maintain its own mempool.
	hasPrevoutRPC bool

	wg   sync.WaitGroup
	quit chan struct{}
}

// Ensure bitcoindZMQEvent implements the BitcoinEvents interface at compile
// time.
var _ BitcoindEvents = (*bitcoindZMQEvents)(nil)

// newBitcoindZMQEvents initialises the necessary zmq connections to bitcoind.
// If bitcoind is on a version with the gettxspendingprevout RPC, we can omit
// the mempool.
func newBitcoindZMQEvents(cfg *ZMQConfig, client *rpcclient.Client,
	bClient batchClient, hasRPC bool) (*bitcoindZMQEvents, error) {

	// Check polling config.
	if cfg.MempoolPollingInterval == 0 {
		cfg.MempoolPollingInterval = defaultTxPollInterval
	}

	// Floor the jitter value to be 0.
	if cfg.PollingIntervalJitter < 0 {
		log.Warnf("Jitter value(%v) must be positive, setting to 0",
			cfg.PollingIntervalJitter)
		cfg.PollingIntervalJitter = 0
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
			"events: %w", err)
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
			"events: %w", err)
	}

	// Create the config for mempool and attach default values if not
	// configed.
	mCfg := &mempoolConfig{
		client:            bClient,
		getRawTxBatchSize: cfg.RPCBatchSize,
		batchWaitInterval: cfg.RPCBatchInterval,
	}

	if cfg.RPCBatchSize == 0 {
		mCfg.getRawTxBatchSize = DefaultGetRawTxBatchSize
	}

	if cfg.RPCBatchInterval == 0 {
		mCfg.batchWaitInterval = DefaultBatchWaitInterval
	}

	zmqEvents := &bitcoindZMQEvents{
		cfg:           cfg,
		client:        client,
		blockConn:     zmqBlockConn,
		txConn:        zmqTxConn,
		hasPrevoutRPC: hasRPC,
		blockNtfns:    make(chan *wire.MsgBlock),
		txNtfns:       make(chan *wire.MsgTx),
		mempool:       newMempool(mCfg),
		quit:          make(chan struct{}),
	}

	return zmqEvents, nil

}

// Start spins off the bitcoindZMQEvent goroutines.
func (b *bitcoindZMQEvents) Start() error {
	// Load the mempool so we don't miss transactions, but only if we need
	// one.
	if !b.hasPrevoutRPC {
		if err := b.mempool.LoadMempool(); err != nil {
			return err
		}
	}

	b.wg.Add(3)
	go b.blockEventHandler()
	go b.txEventHandler()
	go b.mempoolPoller()

	return nil
}

// Stop cleans up any of the resources and goroutines held by bitcoindZMQEvents.
func (b *bitcoindZMQEvents) Stop() error {
	b.mempool.Shutdown()

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

// LookupInputSpend returns the transaction that spends the given outpoint
// found in the mempool.
func (b *bitcoindZMQEvents) LookupInputSpend(
	op wire.OutPoint) (chainhash.Hash, bool) {

	if !b.hasPrevoutRPC {
		b.mempool.RLock()
		defer b.mempool.RUnlock()

		// Check whether the input is in mempool.
		return b.mempool.containsInput(op)
	}

	// Otherwise, we aren't maintaining a mempool and can use the
	// gettxspendingprevout RPC.
	return getTxSpendingPrevOut(op, b.client)
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

			// Add the tx to mempool if we're using one.
			if !b.hasPrevoutRPC {
				b.mempool.Add(tx)
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

// NOTE: This must be run as a goroutine.
func (b *bitcoindZMQEvents) mempoolPoller() {
	defer b.wg.Done()

	if b.hasPrevoutRPC {
		// Exit if we're not using a mempool.
		return
	}

	// We'll wait to start the main reconciliation loop until we're doing
	// the initial mempool load.
	b.mempool.WaitForInit()

	log.Info("Started polling mempool to cache new transactions")

	// Create a ticker that fires randomly.
	rand.Seed(time.Now().UnixNano())
	ticker := NewJitterTicker(
		b.cfg.MempoolPollingInterval, b.cfg.PollingIntervalJitter,
	)

	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Tracef("Reconciling mempool spends with node " +
				"mempool...")

			now := time.Now()

			// After each ticker interval, we poll the mempool to
			// check for transactions we haven't seen yet and
			// update our local mempool with the new mempool.
			b.mempool.UpdateMempoolTxes()

			log.Tracef("Reconciled mempool spends in %v",
				time.Since(now))

		case <-b.quit:
			return
		}
	}
}

// getTxSpendingPrevOut makes an RPC call to `gettxspendingprevout` and returns
// the result.
func getTxSpendingPrevOut(op wire.OutPoint,
	client *rpcclient.Client) (chainhash.Hash, bool) {

	prevoutResps, err := client.GetTxSpendingPrevOut([]wire.OutPoint{op})
	if err != nil {
		return chainhash.Hash{}, false
	}

	// We should only get a single item back since we only requested with a
	// single item.
	if len(prevoutResps) != 1 {
		return chainhash.Hash{}, false
	}

	result := prevoutResps[0]

	// If the "spendingtxid" field is empty, then the utxo has no spend in
	// the mempool at the moment.
	if result.SpendingTxid == "" {
		return chainhash.Hash{}, false
	}

	spendHash, err := chainhash.NewHashFromStr(result.SpendingTxid)
	if err != nil {
		return chainhash.Hash{}, false
	}

	return *spendHash, true
}
