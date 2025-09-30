# Chain Package Architecture

This document outlines the architecture for the `chain` package, which serves as the foundational layer for interacting with the Bitcoin blockchain.

## Core Principle: A Two-Tiered Architecture

The `btcwallet`'s interaction with the blockchain is defined by a two-tiered architecture that creates a clean separation of concerns:

1.  **`chain` Package (The Driver Layer)**: This package is responsible for **low-level, stateless communication** with different blockchain backends (e.g., `btcd`, `bitcoind`). It provides a clean, abstracted API for direct blockchain queries and transaction broadcasting. It **does not** manage any long-lived state related to notifications.

2.  **`ntfn` Package (The Notification Layer)**: A separate, high-level package is the **stateful notification manager**. It is built *on top of* the `chain` package and consumes its raw events. All complex logic for handling reorgs and managing notifications resides in the `ntfn` package.

This document focuses exclusively on the design of the `chain` package.

## Architectural Design: The Actor Model

To adhere to the project's core philosophy, the `chain` package is designed around the **Actor Model**. Each backend connection (`btcd`, `bitcoind`, etc.) is managed by a dedicated actor (a long-running goroutine). This actor owns all connection state and processes requests sequentially, eliminating the need for complex locking.

## Interface-Driven Design

The `chain` package exposes a set of small, role-based interfaces. This adheres to the Interface Segregation Principle and allows consuming packages to depend only on the functionality they need. A single concrete `ChainDriver` struct (e.g., `BitcoindDriver`) will implement the interfaces it supports.

### `ChainQuery` Interface
*For all methods that **fetch** data from the backend.*
```go
// ChainQuery provides methods for querying the blockchain and mempool.
type ChainQuery interface {
	// GetBestBlock returns the hash and height of the best block known to
	// the backend.
	GetBestBlock(ctx context.Context) (*chainhash.Hash, int32, error)

	// GetBlock returns the block for the given hash.
	GetBlock(ctx context.Context, hash *chainhash.Hash) (*wire.MsgBlock, error)

	// GetBlockHash returns the hash of the block at the given height.
	GetBlockHash(ctx context.Context, height int64) (*chainhash.Hash, error)

	// GetBlockHeader returns the header for the given block hash.
	GetBlockHeader(ctx context.Context, hash *chainhash.Hash) (*wire.BlockHeader, error)

	// GetRawTransaction returns the transaction for the given hash.
	//
	// NOTE: The behavior of this method may differ between backends.
	// Full nodes can query the mempool for unconfirmed transactions,
	// while light clients like Neutrino may only return confirmed
	// transactions.
	GetRawTransaction(ctx context.Context, hash *chainhash.Hash) (*btcutil.Tx, error)
}
```

### `ChainIO` Interface
*For all methods that **send** data to the network.*
```go
// ChainIO provides methods for interacting with the blockchain, such as
// broadcasting transactions.
type ChainIO interface {
	// SendRawTransaction broadcasts a transaction to the network. A
	// successful call does not mean the transaction has been confirmed,
	// only that it has been accepted by the backend for relay.
	SendRawTransaction(ctx context.Context, tx *wire.MsgTx, allowHighFees bool) (*chainhash.Hash, error)
}
```

### `ChainEventReceiver` Interface
*The key to our dependency inversion, this interface is implemented by the `ntfn` package and passed to the `chain` driver.*
```go
// ChainEventReceiver is an interface that a consumer of the chain.Driver
// can implement to receive raw blockchain event notifications.
type ChainEventReceiver interface {
	// OnBlockConnected is called when a new block is connected to the
	// main chain.
	OnBlockConnected(hash *chainhash.Hash, height int32, t time.Time)

	// OnBlockDisconnected is called when a block is disconnected from the
	// main chain.
	OnBlockDisconnected(hash *chainhash.Hash, height int32, t time.Time)

	// OnRelevantTx is called when a transaction relevant to the wallet is
	// discovered.
	OnRelevantTx(tx *btcutil.Tx, details *btcjson.BlockDetails)
}
```

### `MempoolObserver` (Optional) Interface
*For full-node-specific mempool functionality.*
```go
// MempoolObserver provides methods for observing the mempool of a full node.
// This is an optional interface that a ChainDriver may implement.
type MempoolObserver interface {
	// GetRawMempool returns the hashes of all transactions in the mempool.
	GetRawMempool(ctx context.Context) ([]*chainhash.Hash, error)

	// TestMempoolAccept checks whether a transaction would be accepted
	// into the mempool.
	TestMempoolAccept(ctx context.Context, txns []*wire.MsgTx) ([]*btcjson.TestMempoolAcceptResult, error)
}
```

### Driver Implementation Principles

All concrete `chain.Driver` implementations **MUST** adhere to the following principles:

1.  **Drivers MUST Be Stateless**: A driver's responsibility is to be a stateless I/O adapter. All stateful logic (queues, subscription management, reorg tracking) is pushed up to the `ntfn` layer.
2.  **Notification Structs MUST Be Self-Contained**: Event structs passed from the driver to the receiver must not depend on higher-level packages like `wtxmgr`.
3.  **Drivers MUST Return Typed, Exported Errors**: Drivers are responsible for mapping backend-specific errors to a standard set of exported errors in the `chain` package.
4.  **Implementations MUST Be Opaque**: Complex, backend-specific logic (like the `PrunedBlockDispatcher`) must be an opaque, internal implementation detail of a driver and must not leak into the public API.
