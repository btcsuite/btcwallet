package chain

import (
	"math/rand"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
)

const (
	// defaultBlockPollInterval is the default interval used for querying
	// for new blocks.
	defaultBlockPollInterval = time.Second * 10

	// defaultTxPollInterval is the default interval used for querying for
	// new mempool transactions.
	defaultTxPollInterval = time.Second * 60
)

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

	// RPCBatchSize defines the number of RPC requests to be batches before
	// sending them to the bitcoind node.
	RPCBatchSize uint32

	// RPCBatchInterval defines the time to wait before attempting the next
	// batch when the current one finishes.
	RPCBatchInterval time.Duration
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

// Ensure bitcoindRPCPollingEvents implements the BitcoinEvents interface at
// compile time.
var _ BitcoindEvents = (*bitcoindRPCPollingEvents)(nil)

// newBitcoindRPCPollingEvents instantiates a new bitcoindRPCPollingEvents
// object.
func newBitcoindRPCPollingEvents(cfg *PollingConfig, client *rpcclient.Client,
	bClient batchClient, hasRPC bool) *bitcoindRPCPollingEvents {

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

	// Create the config for mempool and attach default values if not
	// configed.
	mCfg := &mempoolConfig{
		client:            bClient,
		getRawTxBatchSize: cfg.RPCBatchSize,
		batchWaitInterval: cfg.RPCBatchInterval,
		hasPrevoutRPC:     hasRPC,
	}

	if cfg.RPCBatchSize == 0 {
		mCfg.getRawTxBatchSize = DefaultGetRawTxBatchSize
	}

	if cfg.RPCBatchInterval == 0 {
		mCfg.batchWaitInterval = DefaultBatchWaitInterval
	}

	return &bitcoindRPCPollingEvents{
		cfg:        cfg,
		client:     client,
		txNtfns:    make(chan *wire.MsgTx),
		blockNtfns: make(chan *wire.MsgBlock),
		mempool:    newMempool(mCfg),
		quit:       make(chan struct{}),
	}
}

// Start kicks off all the bitcoindRPCPollingEvents goroutines.
func (b *bitcoindRPCPollingEvents) Start() error {
	info, err := b.client.GetBlockChainInfo()
	if err != nil {
		return err
	}

	// Load the mempool so we don't miss transactions.
	if err := b.mempool.LoadMempool(); err != nil {
		return err
	}

	b.wg.Add(2)
	go b.blockEventHandlerRPC(info.Blocks)
	go b.txEventHandlerRPC()
	return nil
}

// Stop cleans up all the bitcoindRPCPollingEvents resources and goroutines.
func (b *bitcoindRPCPollingEvents) Stop() error {
	b.mempool.Shutdown()

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

// LookupInputSpend returns the transaction that spends the given outpoint
// found in the mempool.
func (b *bitcoindRPCPollingEvents) LookupInputSpend(
	op wire.OutPoint) (chainhash.Hash, bool) {

	b.mempool.RLock()
	defer b.mempool.RUnlock()

	// If `gettxspendingprevout` is not supported, we need to loop it up in
	// our local mempool.
	if !b.mempool.cfg.hasPrevoutRPC {
		// Check whether the input is in mempool.
		return b.mempool.containsInput(op)
	}

	// Otherwise, we can use the `gettxspendingprevout` RPC to look up the
	// input.
	return getTxSpendingPrevOut(op, b.client)
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
				b.mempool.Clean(newBlock.Transactions)

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

	// We'll wait to start the main reconciliation loop until we're doing
	// the initial mempool load.
	b.mempool.WaitForInit()

	log.Info("Started polling mempool for new bitcoind transactions via RPC.")

	// Create a ticker that fires randomly.
	rand.Seed(time.Now().UnixNano())
	ticker := NewJitterTicker(
		b.cfg.TxPollingInterval, b.cfg.TxPollingIntervalJitter,
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
			newTxs := b.mempool.UpdateMempoolTxes()

			log.Tracef("Reconciled mempool spends in %v",
				time.Since(now))

			// Notify the client of each new transaction.
			for _, tx := range newTxs {
				select {
				case b.txNtfns <- tx:
				case <-b.quit:
					return
				}
			}

		case <-b.quit:
			return
		}
	}
}
