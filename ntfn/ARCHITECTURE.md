# `ntfn` Package Architecture

This document outlines the architecture of the `ntfn` (notification) package. This package provides a high-level, stateful notification service for on-chain events.

## Core Responsibilities

The `ntfn` package is the stateful counterpart to the stateless `chain` package. Its responsibilities are:

1.  **Stateful Notification Management**: To manage the lifecycle of client subscriptions for transaction confirmations, UTXO spends, and new block epochs.
2.  **Reorg Handling**: To provide a robust, reorg-aware notification service. It contains all the complex logic for tracking confirmation counts across reorgs and notifying clients of chain reorganizations.
3.  **Historical Dispatch**: To scan the historical chain for events that occurred before a client subscribed, ensuring no events are missed.
4.  **Decoupling**: To abstract the complexity of on-chain event handling, providing a simple and powerful API to its clients (like `wallet` and `lnd`).

## Architectural Design

The `ntfn` package contains a central component, the `Notifier`, which implements the primary public interface.

-   **Dependency on `chain`**: The `Notifier` is built on top of the `chain` package. It takes a `chain.Driver` as a dependency and implements the `chain.ChainEventReceiver` interface to consume a raw stream of blockchain events.
-   **State Management**: The `Notifier` is responsible for all state related to notifications, including client subscriptions, confirmation heights, and its view of the chain tip.
-   **Proven Design**: The `Notifier` interface is adopted directly from `@lnd/chainntnfs`, which is a battle-tested design known to meet the needs of its primary consumer, `lnd`.

## `Notifier` Interface Design

The interface and its supporting data structures are migrated directly from `@lnd/chainntnfs/interface.go`, ensuring a seamless transition for `lnd`.

```go
package ntfn

// Notifier represents a trusted source to receive notifications concerning
// targeted events on the Bitcoin blockchain.
type Notifier interface {
	// RegisterConfirmationsNtfn registers an intent to be notified once a
	// txid reaches a specified number of confirmations.
	RegisterConfirmationsNtfn(txid *chainhash.Hash, pkScript []byte,
		numConfs, heightHint uint32) (*ConfirmationEvent, error)

	// RegisterSpendNtfn registers an intent to be notified once a target
	// outpoint is successfully spent.
	RegisterSpendNtfn(outpoint *wire.OutPoint, pkScript []byte,
		heightHint uint32) (*SpendEvent, error)

	// RegisterBlockEpochNtfn registers an intent to be notified of each
	// new block connected to the tip of the main chain.
	RegisterBlockEpochNtfn(*BlockEpoch) (*BlockEpochEvent, error)

	// Start the Notifier.
	Start() error

	// Stop the Notifier.
	Stop() error
}

// TxConfirmation carries details of the block that confirmed a transaction.
type TxConfirmation struct {
	BlockHash   *chainhash.Hash
	BlockHeight uint32
	TxIndex     uint32
	Tx          *wire.MsgTx
	Block       *wire.MsgBlock
}

// ConfirmationEvent encapsulates a confirmation notification.
type ConfirmationEvent struct {
	Confirmed    chan *TxConfirmation
	NegativeConf chan int32 // For reorgs
	Done         chan struct{}
	Cancel       func()
}

// SpendDetail contains details pertaining to a spent output.
type SpendDetail struct {
	SpentOutPoint     *wire.OutPoint
	SpenderTxHash     *chainhash.Hash
	SpendingTx        *wire.MsgTx
	SpenderInputIndex uint32
	SpendingHeight    int32
}

// SpendEvent encapsulates a spentness notification.
type SpendEvent struct {
	Spend chan *SpendDetail
	Reorg chan struct{} // For reorgs
	Done  chan struct{}
	Cancel func()
}

// BlockEpoch represents metadata for each new block.
type BlockEpoch struct {
	Hash        *chainhash.Hash
	Height      int32
	BlockHeader *wire.BlockHeader
}

// BlockEpochEvent encapsulates a stream of block epoch notifications.
type BlockEpochEvent struct {
	Epochs <-chan *BlockEpoch
	Cancel func()
}
```

## Key Architectural Decisions

The design and interaction of the `ntfn` package are governed by several key architectural decisions:

-   **Hybrid "Push" Notification Model**: The `Notifier` uses a primarily asynchronous "push" model. However, to support linear client workflows, registration methods (`Register...Ntfn`) provide an immediate, synchronous check of the notifier's current, in-memory state. If an event has already occurred, the returned channel will be pre-populated.

-   **"Subscribe-First, Sync-Later" Startup**: To eliminate race conditions, all subsystems must subscribe to the `ntfn.Notifier` *before* the `chain.Driver` is started and begins processing blocks. The `Notifier`'s `Start()` method is non-blocking, and historical scans are performed asynchronously in the background.