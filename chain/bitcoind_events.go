package chain

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
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

	// LookupInputSpend will return the transaction found in mempool that
	// spends the given input.
	LookupInputSpend(op wire.OutPoint) (chainhash.Hash, bool)

	// Start will kick off any goroutines required for operation.
	Start() error

	// Stop will clean up any resources and goroutines.
	Stop() error
}

// Ensure rpcclient.Client implements the rpcClient interface at compile time.
var _ rpcClient = (*rpcclient.Client)(nil)

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

	return newBitcoindZMQEvents(cfg.ZMQConfig, client)
}
