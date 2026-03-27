package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
)

var (
	// ErrInvalidateTx indicates that InvalidateUnminedTx rejected the requested
	// tx because it is not a current active unmined row.
	ErrInvalidateTx = errors.New("invalidate tx")
)

// invalidateUnminedTxTarget is the normalized metadata the shared invalidation
// workflow needs for the root transaction.
type invalidateUnminedTxTarget struct {
	// id is the backend row ID for the transaction being invalidated.
	id int64

	// txHash is the network transaction hash used for descendant discovery.
	txHash chainhash.Hash

	// status is the wallet-relative state that must still be unmined.
	status TxStatus

	// hasBlock reports whether the row is already confirmed in a block.
	hasBlock bool

	// isCoinbase reports whether the row is a coinbase transaction.
	isCoinbase bool
}

// invalidateUnminedTxOps is the small backend adapter the shared
// InvalidateUnminedTx workflow needs.
//
// The shared invalidation algorithm is intentionally ordered:
//   - load and validate the requested root transaction first
//   - load the active unmined graph snapshot used for descendant discovery
//   - discover every descendant that depends on the root before any mutation
//     starts
//   - clear wallet-owned spent-input edges for the root and every discovered
//     descendant
//   - mark the full invalidated branch failed in one batch update
//
// This sequencing keeps the invalidation event atomic and prevents a partially
// invalid branch from retaining wallet-owned spend edges if any later step
// fails. The backend adapters only supply query wiring and row-shape
// conversions.
type invalidateUnminedTxOps interface {
	// loadInvalidateTarget loads the wallet-scoped root tx metadata.
	loadInvalidateTarget(ctx context.Context, walletID uint32,
		txHash chainhash.Hash) (
		invalidateUnminedTxTarget, error)

	// listUnminedTxRecords loads the wallet's active unmined transaction rows
	// in the normalized shape the descendant walk expects.
	listUnminedTxRecords(ctx context.Context, walletID int64) (
		[]unminedTxRecord, error)

	// clearSpentUtxos restores any wallet-owned parent outputs spent by the
	// given transaction row.
	clearSpentUtxos(ctx context.Context, walletID int64, txID int64) error

	// markTxnsFailed batch-marks the provided tx rows as failed.
	markTxnsFailed(ctx context.Context, walletID int64, txIDs []int64) error
}

// validateUnminedTxTarget checks that the requested root is a current
// unmined non-coinbase transaction.
func validateUnminedTxTarget(target invalidateUnminedTxTarget) error {
	if target.hasBlock {
		return fmt.Errorf("tx %s is confirmed: %w", target.txHash,
			ErrInvalidateTx)
	}

	if target.isCoinbase {
		return fmt.Errorf("tx %s is coinbase: %w", target.txHash,
			ErrInvalidateTx)
	}

	if !isUnminedStatus(target.status) {
		return fmt.Errorf("tx %s has status %d: %w", target.txHash,
			target.status, ErrInvalidateTx)
	}

	return nil
}

// invalidateUnminedTxWithOps invalidates one wallet-owned unmined transaction
// root together with any descendant branch that depends on it.
//
// The helper performs descendant discovery before any spend-edge or status
// mutation begins. It then clears the root spend, clears descendant spends, and
// finally marks the combined branch failed. Keeping that ordering in one shared
// helper ensures postgres and sqlite invalidate branches with identical wallet
// semantics.
func invalidateUnminedTxWithOps(ctx context.Context,
	params InvalidateUnminedTxParams, ops invalidateUnminedTxOps) error {

	target, err := ops.loadInvalidateTarget(ctx, params.WalletID, params.Txid)
	if err != nil {
		return fmt.Errorf("load invalidate tx target: %w", err)
	}

	err = validateUnminedTxTarget(target)
	if err != nil {
		return err
	}

	candidates, err := ops.listUnminedTxRecords(ctx, int64(params.WalletID))
	if err != nil {
		return fmt.Errorf("list unmined invalidation txns: %w", err)
	}

	descendantIDs := collectDescendantTxIDs(
		[]chainhash.Hash{target.txHash}, nil, candidates,
	)

	err = ops.clearSpentUtxos(ctx, int64(params.WalletID), target.id)
	if err != nil {
		return fmt.Errorf("clear root spent utxos: %w", err)
	}

	for _, descendantID := range descendantIDs {
		err = ops.clearSpentUtxos(ctx, int64(params.WalletID), descendantID)
		if err != nil {
			return fmt.Errorf("clear descendant spent utxos: %w", err)
		}
	}

	failedIDs := make([]int64, 0, len(descendantIDs)+1)
	failedIDs = append(failedIDs, target.id)
	failedIDs = append(failedIDs, descendantIDs...)

	err = ops.markTxnsFailed(ctx, int64(params.WalletID), failedIDs)
	if err != nil {
		return fmt.Errorf("mark invalidated txns failed: %w", err)
	}

	return nil
}
