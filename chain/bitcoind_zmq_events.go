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

	// client is the rpc client that we'll use to query for the mempool.
	client *rpcclient.Client

	// mempool holds all the transactions that we currently see as being in
	// the mempool. This is used so that we know which transactions we have
	// already sent notifications for.
	mempool *mempool

	wg   sync.WaitGroup
	quit chan struct{}
}

// Ensure bitcoindZMQEvent implements the BitcoinEvents interface at compile
// time.
var _ BitcoindEvents = (*bitcoindZMQEvents)(nil)

// newBitcoindZMQEvents initialises the necessary zmq connections to bitcoind.
func newBitcoindZMQEvents(cfg *ZMQConfig,
	client *rpcclient.Client) (*bitcoindZMQEvents, error) {

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
		client:     client,
		mempool:    newMempool(),
		quit:       make(chan struct{}),
	}, nil
}

// Start spins off the bitcoindZMQEvent goroutines.
func (b *bitcoindZMQEvents) Start() error {
	// Load the mempool so we don't miss transactions.
	if err := b.loadMempool(); err != nil {
		return err
	}

	b.wg.Add(3)
	go b.blockEventHandler()
	go b.txEventHandler()
	go b.mempoolPoller()

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

// LookupInputSpend returns the transaction that spends the given outpoint
// found in the mempool.
func (b *bitcoindZMQEvents) LookupInputSpend(
	op wire.OutPoint) (chainhash.Hash, bool) {

	b.mempool.RLock()
	defer b.mempool.RUnlock()

	// Check whether the input is in mempool.
	return b.mempool.containsInput(op)
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

// NOTE: This must be run as a goroutine.
func (b *bitcoindZMQEvents) mempoolPoller() {
	defer b.wg.Done()

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
			// After each ticker interval, we poll the mempool to
			// check for transactions we haven't seen yet.
			txs, err := b.client.GetRawMempool()
			if err != nil {
				log.Errorf("Unable to retrieve mempool txs: "+
					"%v", err)
				continue
			}

			// Update our local mempool with the new mempool.
			b.updateMempoolTxes(txs)

		case <-b.quit:
			return
		}
	}
}

// updateMempoolTxes takes a slice of transactions from the current mempool and
// use it to update its internal mempool. It returns a slice of transactions
// that's new to its internal mempool.
//
// TODO(yy): replace this temp config with SEQUENCE check.
func (b *bitcoindZMQEvents) updateMempoolTxes(
	txids []*chainhash.Hash) []*wire.MsgTx {

	b.mempool.Lock()
	defer b.mempool.Unlock()

	// txesToNotify is a list of txes to be notified to the client.
	txesToNotify := make([]*wire.MsgTx, 0, len(txids))

	// Set all mempool txs to false.
	b.mempool.unmarkAll()

	// We'll scan through the most recent txs in the mempool to see whether
	// there are new txs that we need to send to the client.
	for _, txHash := range txids {
		// If the transaction is already in our local mempool, then we
		// have already sent it to the client.
		if b.mempool.containsTx(*txHash) {
			// Mark the tx as true so that we know not to remove it
			// from our internal mempool.
			b.mempool.mark(*txHash)
			continue
		}

		// Grab full mempool transaction from hash.
		tx, err := b.client.GetRawTransaction(txHash)
		if err != nil {
			log.Errorf("unable to fetch transaction %s from "+
				"mempool: %v", txHash, err)
			continue
		}

		// Add the transaction to our local mempool. Note that we only
		// do this after fetching the full raw transaction from
		// bitcoind. We do this so that if that call happens to
		// initially fail, then we will retry it on the next interval
		// since it is still not in our local mempool.
		b.mempool.add(tx.MsgTx())

		// Save the tx to the slice.
		txesToNotify = append(txesToNotify, tx.MsgTx())
	}

	// Now, we clear our internal mempool of any unmarked transactions.
	// These are all the transactions that we still have in the mempool but
	// that were not returned in the latest GetRawMempool query.
	b.mempool.deleteUnmarked()

	return txesToNotify
}

// loadMempool loads all the raw transactions found in mempool.
func (b *bitcoindZMQEvents) loadMempool() error {
	txs, err := b.client.GetRawMempool()
	if err != nil {
		log.Errorf("Unable to get raw mempool txs: %v", err)
		return err
	}

	b.mempool.Lock()
	defer b.mempool.Unlock()

	for _, txHash := range txs {
		// Grab full mempool transaction from hash.
		tx, err := b.client.GetRawTransaction(txHash)
		if err != nil {
			log.Errorf("unable to fetch transaction %s for "+
				"mempool: %v", txHash, err)
			continue
		}

		// Add the transaction to our local mempool.
		b.mempool.add(tx.MsgTx())
	}

	return nil
}
