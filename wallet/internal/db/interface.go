// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package db defines the backend-neutral transaction boundary used by the
// wallet's address and transaction managers.
package db

import (
	"context"
	"fmt"
	"sync"
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
	// ManagerReadStore provides the address-manager read surface.
	waddrmgr.ManagerReadStore
}

// AddrReadWriteStore exposes address-manager reads and writes within an
// existing wallet transaction.
type AddrReadWriteStore interface {
	// ManagerReadWriteTx provides the address-manager write surface.
	waddrmgr.ManagerReadWriteTx
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
	// TxReadStore provides the transaction-manager read surface.
	TxReadStore

	// AddCredit marks an output of a recorded transaction as wallet-owned and
	// reports whether a new credit was added.
	AddCredit(rec *wtxmgr.TxRecord, block *wtxmgr.BlockMeta, index uint32,
		change bool) (bool, error)

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

	// UpdateOnce executes body in a single read/write transaction attempt.
	// It is intended for legacy callbacks whose side effects cannot be
	// replayed safely.
	UpdateOnce(ctx context.Context, body func(ReadWriteTx) error,
		reset func()) error
}

// LifecycleStore extends a manager Store with wallet existence and creation
// operations. A lifecycle store may begin unbound and become bound to the
// wallet created or resolved by its backend-specific identity.
type LifecycleStore interface {
	// Store provides the backend transaction execution surface.
	Store

	// WalletExists reports whether the configured wallet exists. A successful
	// lookup binds an initially unbound store to the durable wallet.
	WalletExists(ctx context.Context) (bool, error)

	// Create executes body in the single transaction that creates and binds
	// the configured wallet. The callback is never replayed.
	Create(ctx context.Context, body func(ReadWriteTx) error,
		reset func()) error
}

// AmbiguousCommitError reports a commit failure for which the caller cannot
// safely assume whether the transaction became durable.
type AmbiguousCommitError struct {
	// Err is the backend error returned while committing the transaction.
	Err error

	hooks     []func()
	hooksOnce sync.Once
}

// NewAmbiguousCommitError records a commit failure and the post-commit hooks
// that can be applied if the caller later proves the transaction became
// durable.
func NewAmbiguousCommitError(err error,
	hooks ...func()) *AmbiguousCommitError {

	return &AmbiguousCommitError{
		Err:   err,
		hooks: append([]func(){}, hooks...),
	}
}

// Error describes the ambiguous commit failure.
func (e *AmbiguousCommitError) Error() string {
	return fmt.Sprintf("transaction commit outcome is ambiguous: %v", e.Err)
}

// Unwrap returns the commit error reported by the backend.
func (e *AmbiguousCommitError) Unwrap() error {
	return e.Err
}

// ApplyCommitHooks publishes deferred in-memory state after the caller proves
// an ambiguously acknowledged transaction committed. Hooks are applied at most
// once.
func (e *AmbiguousCommitError) ApplyCommitHooks() {
	e.hooksOnce.Do(func() {
		for _, hook := range e.hooks {
			hook()
		}
	})
}

// RetryableTransactionError reports a failure known to have left no durable
// transaction changes. The caller may safely retry the whole operation.
type RetryableTransactionError struct {
	// Err is the backend error that prevented the transaction from committing.
	Err error
}

// Error describes the definitely uncommitted transaction failure.
func (e *RetryableTransactionError) Error() string {
	return fmt.Sprintf("transaction did not commit and may be retried: %v",
		e.Err)
}

// Unwrap returns the retryable backend error.
func (e *RetryableTransactionError) Unwrap() error {
	return e.Err
}
