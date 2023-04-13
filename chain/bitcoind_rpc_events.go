package chain

import (
	"math/rand"
	"sync"
	"time"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
)

const (
	// defaultBlockPollInterval is the default interval used for querying
	// for new blocks.
	defaultBlockPollInterval = time.Second * 10

	// defaultTxPollInterval is the default interval used for querying
	// for new mempool transactions.
	defaultTxPollInterval = time.Second * 10
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
				if b.mempool.containsTx(*txHash) {
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
				b.mempool.add(tx.MsgTx())

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
