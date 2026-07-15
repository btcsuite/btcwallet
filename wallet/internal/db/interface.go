// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package db defines the backend-neutral transaction boundary used by the
// wallet's address and transaction managers.
package db

import (
	"context"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
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

// TxReadStore exposes the existing transaction-manager read surface within an
// existing wallet transaction.
//
//nolint:interfacebloat // The compatibility boundary mirrors wtxmgr exactly.
type TxReadStore interface {
	// Balance returns the spendable wallet balance for the requested
	// confirmation policy and sync height.
	Balance(minConf, syncHeight int32) (btcutil.Amount, error)

	// ListLockedOutputs returns all currently leased outputs.
	ListLockedOutputs() ([]*wtxmgr.LockedOutput, error)

	// OutputsToWatch returns the outputs that startup recovery should watch.
	OutputsToWatch() ([]wtxmgr.Credit, error)

	// PreviousPkScripts returns the scripts for wallet-owned inputs.
	PreviousPkScripts(rec *wtxmgr.TxRecord,
		block *wtxmgr.Block) ([][]byte, error)

	// RangeTransactions visits transaction details over the requested block
	// range using the existing wtxmgr ordering and callback semantics.
	RangeTransactions(begin, end int32,
		visit func([]wtxmgr.TxDetails) (bool, error)) error

	// TxDetails returns the most recent transaction incidence for a hash.
	TxDetails(hash *chainhash.Hash) (*wtxmgr.TxDetails, error)

	// TxLabel returns the label associated with a transaction hash.
	TxLabel(hash chainhash.Hash) (string, error)

	// UniqueTxDetails returns the transaction incidence selected by block.
	UniqueTxDetails(hash *chainhash.Hash,
		block *wtxmgr.Block) (*wtxmgr.TxDetails, error)

	// UnminedTxHashes returns all transaction hashes in the unmined set.
	UnminedTxHashes() ([]*chainhash.Hash, error)

	// UnminedTxs returns the dependency-ordered unmined transactions.
	UnminedTxs() ([]*wire.MsgTx, error)

	// UnspentOutputs returns all currently spendable credits.
	UnspentOutputs() ([]wtxmgr.Credit, error)
}

// TxReadWriteStore exposes the existing transaction-manager read/write surface
// within an existing wallet transaction.
type TxReadWriteStore interface {
	TxReadStore

	// AddCredit marks an output of a recorded transaction as wallet-owned.
	AddCredit(rec *wtxmgr.TxRecord, block *wtxmgr.BlockMeta, index uint32,
		change bool) error

	// DeleteExpiredLockedOutputs removes all expired output leases.
	DeleteExpiredLockedOutputs() error

	// InsertTx records a mined or unmined transaction incidence.
	InsertTx(rec *wtxmgr.TxRecord, block *wtxmgr.BlockMeta) error

	// InsertTxCheckIfExists records a transaction incidence and reports
	// whether it was already present.
	InsertTxCheckIfExists(rec *wtxmgr.TxRecord,
		block *wtxmgr.BlockMeta) (bool, error)

	// LockOutput leases an output to an owner for the requested duration.
	LockOutput(id wtxmgr.LockID, output wire.OutPoint,
		duration time.Duration) (time.Time, error)

	// PutTxLabel stores a transaction label.
	PutTxLabel(hash chainhash.Hash, label string) error

	// RemoveUnminedTx removes an unmined transaction and its descendants.
	RemoveUnminedTx(rec *wtxmgr.TxRecord) error

	// Rollback removes all blocks at height onwards, moving any transactions
	// within each block to the unconfirmed pool.
	Rollback(height int32) error

	// UnlockOutput releases an output lease held by the owner.
	UnlockOutput(id wtxmgr.LockID, output wire.OutPoint) error
}

// ReadTx exposes the read-only manager views bound to one backend transaction.
type ReadTx interface {
	// Addr returns the address-manager read view.
	Addr() AddrReadStore

	// Tx returns the transaction-manager read view.
	Tx() TxReadStore
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
