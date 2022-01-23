package chain

import (
	"bytes"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/gozmq"
	"io"
	"net"
	"sync"
	"time"
)

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

type BitcoindZMQEvents struct {
	cfg *ZMQConfig

	notifyBlock func(block *wire.MsgBlock)
	notifyTx    func(tx *wire.MsgTx)

	// blockConn is the ZMQ connection we'll use to read raw block events.
	blockConn *gozmq.Conn

	// txConn is the ZMQ connection we'll use to read raw transaction
	// events.
	txConn *gozmq.Conn

	wg   sync.WaitGroup
	quit chan struct{}
}

func newBitcoindZMQEvents(cfg *ZMQConfig, notifyBlock func(*wire.MsgBlock),
	notifyTx func(tx *wire.MsgTx)) (*BitcoindZMQEvents, error) {

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

	return &BitcoindZMQEvents{
		cfg:         cfg,
		blockConn:   zmqBlockConn,
		txConn:      zmqTxConn,
		notifyBlock: notifyBlock,
		notifyTx:    notifyTx,
		quit:        make(chan struct{}),
	}, nil
}

func (b *BitcoindZMQEvents) Start() error {
	b.wg.Add(2)
	go b.blockEventHandler()
	go b.txEventHandler()
	return nil
}

// blockEventHandler reads raw blocks events from the ZMQ block socket and
// forwards them along to the current rescan clients.
//
// NOTE: This must be run as a goroutine.
func (b *BitcoindZMQEvents) blockEventHandler() {
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

			b.notifyBlock(block)

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
func (b *BitcoindZMQEvents) txEventHandler() {
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

			b.notifyTx(tx)

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

func (b *BitcoindZMQEvents) Stop() error {
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

type PollingConfig struct {
	BlockPollingTime   time.Duration
	TxPollingTime      time.Duration
	MempoolEvictionAge time.Duration
}

type BitcoindRPCPollingEvents struct {
	cfg *PollingConfig

	client *rpcclient.Client

	mempool *mempool

	notifyBlock func(block *wire.MsgBlock)
	notifyTx    func(tx *wire.MsgTx)

	wg   sync.WaitGroup
	quit chan struct{}
}

func newBitcoindRPCPollingEvents(cfg *PollingConfig, client *rpcclient.Client,
	notifyBlock func(block *wire.MsgBlock),
	notifyTx func(tx *wire.MsgTx)) (*BitcoindRPCPollingEvents, error) {

	return &BitcoindRPCPollingEvents{
		cfg:         cfg,
		client:      client,
		notifyTx:    notifyTx,
		notifyBlock: notifyBlock,
		mempool:     newMempool(),
		quit:        make(chan struct{}),
	}, nil
}

func (b *BitcoindRPCPollingEvents) Start() error {
	info, err := b.client.GetBlockChainInfo()
	if err != nil {
		return err
	}

	b.wg.Add(3)
	go b.blockEventHandlerRPC(info.Blocks)
	go b.txEventHandlerRPC()
	go b.evictOldTransactions()

	return nil
}

func (b *BitcoindRPCPollingEvents) Stop() error {
	close(b.quit)
	b.wg.Wait()
	return nil
}

// blockEventHandlerRPC is a goroutine that uses the rpc client to check if we
// have a new block every so often.
func (b *BitcoindRPCPollingEvents) blockEventHandlerRPC(startHeight int32) {
	defer b.wg.Done()

	log.Info("Started polling for new bitcoind blocks via RPC.")
	ticker := time.NewTicker(b.cfg.BlockPollingTime)
	defer ticker.Stop()

	height := startHeight
	log.Info("startheight: ", height)

	for {
		select {
		case <-ticker.C:
			// Every so many seconds, we poll to see if there's a
			// new block.
			info, err := b.client.GetBlockChainInfo()
			if err != nil {
				log.Errorf("Unable to retrieve best block: "+
					"%v", err)
				continue
			}

			// If the block isn't new, we continue. Else, we need
			// grab the full block data to send to the clients.
			if info.Blocks <= height {
				continue
			}

			hash, err := chainhash.NewHashFromStr(info.BestBlockHash)
			if err != nil {
				log.Errorf(err.Error())
				return
			}

			for i := height + 1; i <= info.Blocks; i++ {
				newBlock, err := b.client.GetBlock(hash)
				if err != nil {
					log.Errorf("Unable to retrieve "+
						"block: %v", err)
					continue
				}

				b.notifyBlock(newBlock)

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
func (b *BitcoindRPCPollingEvents) txEventHandlerRPC() {
	defer b.wg.Done()

	log.Info("Started polling for new bitcoind transactions via RPC.")
	ticker := time.NewTicker(b.cfg.TxPollingTime)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Every few seconds, we poll the mempool to check for
			// transactions we haven't seen yet.
			txs, err := b.client.GetRawMempool()
			if err != nil {
				log.Errorf("Unable to retrieve mempool "+
					"txs: %v", err)
				continue
			}

			// We'll scan through the most recent txs in the
			// mempool to see whether there are new txs that we
			// need to send to the client.
			for _, txHash := range txs {
				// If the transaction isn't in the local
				// mempool, we'll send it to all of the
				// clients.
				if b.mempool.contains(txHash) {
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

				b.mempool.add(txHash)

				b.notifyTx(tx.MsgTx())
			}

		case <-b.quit:
			return
		}
	}
}

func (b *BitcoindRPCPollingEvents) evictOldTransactions() {
	defer b.wg.Done()

	log.Info("Now checking for old unconfirmed transactions once every 24" +
		" hours.")
	ticker := time.NewTicker(b.cfg.MempoolEvictionAge)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			b.mempool.removeOldTxs(b.cfg.MempoolEvictionAge)

		case <-b.quit:
			return
		}
	}
}

type mempool struct {
	sync.Mutex
	txs map[chainhash.Hash]time.Time
}

func newMempool() *mempool {
	return &mempool{
		txs: make(map[chainhash.Hash]time.Time),
	}
}

func (m *mempool) clean(txs []*wire.MsgTx) {
	m.Lock()
	defer m.Unlock()

	for _, tx := range txs {
		// If the transaction is in our mempool
		// map, we need to delete it.
		if _, ok := m.txs[tx.TxHash()]; ok {
			delete(m.txs, tx.TxHash())
		}
	}
}

func (m *mempool) contains(hash *chainhash.Hash) bool {
	m.Lock()
	defer m.Unlock()

	_, ok := m.txs[*hash]
	return ok
}

func (m *mempool) add(hash *chainhash.Hash) {
	m.Lock()
	defer m.Unlock()

	m.txs[*hash] = time.Now()
}

func (m *mempool) removeOldTxs(age time.Duration) {
	m.Lock()
	defer m.Unlock()

	for txHash, timeAdded := range m.txs {
		if time.Now().Sub(timeAdded) > age {
			delete(m.txs, txHash)
		}
	}
}
