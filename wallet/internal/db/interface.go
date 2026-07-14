// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package db defines the backend-neutral transaction boundary used by the
// wallet's address and transaction managers.
package db

import (
	"context"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// AddrReadStore exposes address-manager reads within an existing wallet
// transaction. Backend transaction handles remain private to the adapter.
type AddrReadStore interface {
	// BlockHash returns the block hash at a particular block height.
	BlockHash(height int32) (*chainhash.Hash, error)
}

// AddrReadWriteStore exposes address-manager reads and writes within an
// existing wallet transaction.
type AddrReadWriteStore interface {
	AddrReadStore

	// SetSyncedTo marks the address manager as synced through the block.
	SetSyncedTo(block *waddrmgr.BlockStamp) error
}

// TxReadWriteStore exposes transaction-manager writes within an existing
// wallet transaction. The interface starts with the reorg operation and will
// grow as the remaining wallet paths move behind the same boundary.
type TxReadWriteStore interface {
	// Rollback removes all blocks at height onwards, moving any transactions
	// within each block to the unconfirmed pool.
	Rollback(height int32) error
}

// ReadTx exposes the read-only manager views bound to one backend transaction.
type ReadTx interface {
	// Addr returns the address-manager read view.
	Addr() AddrReadStore
}

// ReadWriteTx exposes the manager views bound to one writable backend
// transaction.
type ReadWriteTx interface {
	// Addr returns the address-manager read/write view.
	Addr() AddrReadWriteStore

	// Tx returns the transaction-manager read/write view.
	Tx() TxReadWriteStore
}

// Store owns backend transactions while preserving the wallet's existing
// callback-oriented control flow. The reset callback runs before each attempt
// because SQL backends may retry a transaction.
type Store interface {
	// View executes body in a read transaction.
	View(ctx context.Context, body func(ReadTx) error, reset func()) error

	// Update executes body in a read/write transaction.
	Update(ctx context.Context, body func(ReadWriteTx) error,
		reset func()) error
}
