// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr

import (
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/walletdb"
)

// TODO(yy): The TxStore interface is a temporary solution to decouple the
// wallet from the wtxmgr. It is not a good example of a well-designed
// interface. It has the following issues:
//
//  1. Violation of the Interface Segregation Principle (ISP):
//     The current TxStore interface is a "fat" interface, containing over 15
//     methods that span a wide range of responsibilities, from simple balance
//     lookups to administrative tasks like database rollbacks. A component that
//     only needs to read transaction details is forced to depend on the entire
//     interface, including methods for writing data and performing
//     administrative actions. This creates an unnecessarily large dependency
//     surface.
//
//  2. Lack of Cohesion and CRUD-like Grouping:
//     The methods in TxStore are not grouped by the domain entity they operate
//     on. A more intuitive design would follow a classic Create, Read, Update,
//     Delete (CRUD) pattern for each major entity (transactions, UTXOs,
//     labels). The flat structure of the interface makes it harder to
//     understand the available operations for a specific entity. For example,
//     PutTxLabel, FetchTxLabel, and TxDetails are all at the same level, despite
//     operating on different aspects of a transaction.
//
//  3. Leaky Abstractions:
//     The interface methods currently require the caller (the wallet package)
//     to pass in walletdb.ReadWriteBucket or walletdb.ReadBucket handles. This
//     leaks the implementation detail that the store is built on walletdb. The
//     wallet should not need to know about the underlying database technology
//     or manage database transactions for the wtxmgr. This also violates the
//     "Pull Complexity Downwards" principle, as the TxStore should be
//     responsible for its own data access logic.
//
//  4. Missing context.Context Propagation:
//     None of the interface methods accept a context.Context. This is a
//     critical omission. Without a context, we cannot enforce timeouts,
//     propagate cancellation signals, or ensure the graceful shutdown of
//     long-running database queries.
//
// TxStore is an interface that describes a transaction store.
type TxStore interface {
	// Balance returns the spendable wallet balance (total value of all
	// unspent transaction outputs) given a minimum of minConf confirmations,
	// calculated at a current chain height of curHeight. Coinbase outputs
	// are only included in the balance if maturity has been reached.
	Balance(ns walletdb.ReadBucket, minConf int32,
		syncHeight int32) (btcutil.Amount, error)

	// DeleteExpiredLockedOutputs iterates through all existing locked
	// outputs and deletes those which have already expired.
	DeleteExpiredLockedOutputs(ns walletdb.ReadWriteBucket) error

	// InsertTx records a transaction as belonging to a wallet's transaction
	// history. If block is nil, the transaction is considered unspent, and
	// the transaction's index must be unset.
	InsertTx(ns walletdb.ReadWriteBucket, rec *TxRecord,
		block *BlockMeta) error

	// InsertTxCheckIfExists records a transaction as belonging to a wallet's
	// transaction history. If block is nil, the transaction is considered
	// unspent, and the transaction's index must be unset. It will return
	// true if the transaction was already recorded prior to the call.
	InsertTxCheckIfExists(ns walletdb.ReadWriteBucket, rec *TxRecord,
		block *BlockMeta) (bool, error)

	// AddCredit marks a transaction record as containing a transaction
	// output spendable by wallet. The output is added unspent, and is
	// marked spent when a new transaction spending the output is inserted
	// into the store.
	AddCredit(ns walletdb.ReadWriteBucket, rec *TxRecord,
		block *BlockMeta, index uint32, change bool) error

	// ListLockedOutputs returns a list of objects representing the currently
	// locked utxos.
	ListLockedOutputs(ns walletdb.ReadBucket) ([]*LockedOutput, error)

	// LockOutput locks an output to the given ID, preventing it from being
	// available for coin selection. The absolute time of the lock's
	// expiration is returned. The expiration of the lock can be extended by
	// successive invocations of this call.
	LockOutput(ns walletdb.ReadWriteBucket, id LockID, op wire.OutPoint,
		duration time.Duration) (time.Time, error)

	// OutputsToWatch returns a list of outputs to monitor during the
	// wallet's startup. The returned items are similar to UnspentOutputs,
	// exccept the locked outputs and unmined credits are also returned
	// here. In addition, we only set the field `OutPoint` and `PkScript`
	// for the `Credit`, as these are the only fields used during the
	// rescan.
	OutputsToWatch(ns walletdb.ReadBucket) ([]Credit, error)

	// PutTxLabel validates transaction labels and writes them to disk if
	// they are non-zero and within the label length limit.
	PutTxLabel(ns walletdb.ReadWriteBucket, txid chainhash.Hash,
		label string) error

	// RangeTransactions runs the function f on all transaction details
	// between blocks on the best chain over the height range [begin,end].
	// The special height -1 may be used to also include unmined
	// transactions. If the end height comes before the begin height, blocks
	// are iterated in reverse order and unmined transactions (if any) are
	// processed first.
	RangeTransactions(ns walletdb.ReadBucket, begin, end int32,
		f func([]TxDetails) (bool, error)) error

	// Rollback removes all blocks at height onwards, moving any transactions
	// within each block to the unconfirmed pool.
	Rollback(ns walletdb.ReadWriteBucket, height int32) error

	// TxDetails looks up all recorded details regarding a transaction with
	// some hash. In case of a hash collision, the most recent transaction
	// with a matching hash is returned.
	TxDetails(ns walletdb.ReadBucket,
		txHash *chainhash.Hash) (*TxDetails, error)

	// UniqueTxDetails looks up all recorded details for a transaction
	// recorded mined in some particular block, or an unmined transaction if
	// block is nil.
	UniqueTxDetails(ns walletdb.ReadBucket, txHash *chainhash.Hash,
		block *Block) (*TxDetails, error)

	// UnlockOutput unlocks an output, allowing it to be available for coin
	// selection if it remains unspent. The ID should match the one used to
	// originally lock the output.
	UnlockOutput(ns walletdb.ReadWriteBucket, id LockID,
		op wire.OutPoint) error

	// UnspentOutputs returns all unspent received transaction outputs.
	// The order is undefined.
	UnspentOutputs(ns walletdb.ReadBucket) ([]Credit, error)

	// FetchTxLabel reads a transaction label from the tx labels bucket. If
	// a label with 0 length was written, we return an error, since this is
	// unexpected.
	FetchTxLabel(ns walletdb.ReadBucket,
		txid chainhash.Hash) (string, error)

	// GetUtxo returns the credit for a given outpoint, if it is known to
	// the store as a UTXO. It checks for mined (confirmed) UTXOs first,
	// and then unmined (unconfirmed) credits. If the UTXO is not found,
	// ErrUtxoNotFound is returned. This function does not determine if the
	// UTXO is spent by an unmined transaction or locked.
	GetUtxo(ns walletdb.ReadBucket,
		outpoint wire.OutPoint) (*Credit, error)

	// UnminedTxs returns the underlying transactions for all unmined
	// transactions which are not known to have been mined in a block.
	// Transactions are guaranteed to be sorted by their dependency order.
	UnminedTxs(ns walletdb.ReadBucket) ([]*wire.MsgTx, error)

	// UnminedTxHashes returns the hashes of all transactions not known to
	// have been mined in a block.
	UnminedTxHashes(ns walletdb.ReadBucket) ([]*chainhash.Hash, error)

	// RemoveUnminedTx attempts to remove an unmined transaction from the
	// transaction store.
	RemoveUnminedTx(ns walletdb.ReadWriteBucket, rec *TxRecord) error
}
