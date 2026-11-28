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

// InvalidateUnminedTxTarget is the normalized metadata the shared unmined
// branch workflows need for the root transaction.
type InvalidateUnminedTxTarget struct {
	// ID is the backend row ID for the root transaction.
	ID int64

	// TxHash is the network transaction hash used for descendant discovery.
	TxHash chainhash.Hash

	// Status is the wallet-relative state that must still be unmined.
	Status TxStatus

	// HasBlock reports whether the row is already confirmed in a block.
	HasBlock bool

	// IsCoinbase reports whether the row is a coinbase transaction.
	IsCoinbase bool
}

// UnminedBranchOps is the branch discovery the unmined branch workflows share:
// it loads the requested root and the rows the descendant walk considers.
type UnminedBranchOps interface {
	// LoadUnminedTxTarget loads the wallet-scoped root tx metadata.
	LoadUnminedTxTarget(ctx context.Context, walletID uint32,
		txHash chainhash.Hash) (UnminedTxTarget, error)

	// ListUnminedTxRecords loads the unmined rows the workflow's descendant
	// walk must consider, in the normalized shape it expects. Invalidation
	// considers the active set; removal also considers rows an earlier event
	// made terminal.
	ListUnminedTxRecords(ctx context.Context, walletID int64) (
		[]UnminedTxRecord, error)
}

// InvalidateUnminedTxOps is the small backend adapter the shared
// InvalidateUnminedTx workflow needs on top of branch discovery.
//
// The shared invalidation algorithm is intentionally ordered:
//   - load and validate the requested root transaction first
//   - load the active unmined graph snapshot used for descendant discovery
//   - discover every descendant that depends on the root before any mutation
//     starts
//   - mark the full invalidated branch failed in one batch update
//
// This sequencing keeps the invalidation event atomic and prevents a partially
// invalid branch from retaining eligibility if any later step fails. Backend
// adapters only supply query wiring and row-shape conversions.
type InvalidateUnminedTxOps interface {
	UnminedBranchOps

	// MarkTxnsFailed batch-marks the provided tx rows as failed.
	MarkTxnsFailed(ctx context.Context, walletID int64, txIDs []int64) error
}

// validateUnminedTxTarget checks that the requested root is a current
// unmined non-coinbase transaction. The caller supplies the sentinel it
// reports.
func validateUnminedTxTarget(target InvalidateUnminedTxTarget,
	rejected error) error {

	if target.HasBlock {
		return fmt.Errorf("tx %s is confirmed: %w", target.TxHash, rejected)
	}

	if target.IsCoinbase {
		return fmt.Errorf("tx %s is coinbase: %w", target.TxHash, rejected)
	}

	if !IsUnminedStatus(target.Status) {
		return fmt.Errorf("tx %s has status %s: %w", target.TxHash,
			target.Status, rejected)
	}

	return nil
}

// InvalidateUnminedTxWithOps invalidates one wallet-owned unmined transaction
// root together with any descendant branch that depends on it.
//
// Discover descendants before status changes can hide them from the walk.
// The shared status update invalidates the branch but retains input facts;
// both SQL backends derive the resulting availability from those facts.
func InvalidateUnminedTxWithOps(ctx context.Context,
	params InvalidateUnminedTxParams, ops InvalidateUnminedTxOps) error {

	target, err := ops.LoadUnminedTxTarget(ctx, params.WalletID, params.Txid)
	if err != nil {
		return fmt.Errorf("load invalidate tx target: %w", err)
	}

	err = validateUnminedTxTarget(target, ErrInvalidateTx)
	if err != nil {
		return err
	}

	candidates, err := ops.ListUnminedTxRecords(ctx, int64(params.WalletID))
	if err != nil {
		return fmt.Errorf("list unmined invalidation txns: %w", err)
	}

	descendantIDs := CollectDescendantTxIDs(
		[]chainhash.Hash{target.TxHash}, nil, candidates,
	)

	failedIDs := make([]int64, 0, len(descendantIDs)+1)
	failedIDs = append(failedIDs, target.ID)
	failedIDs = append(failedIDs, descendantIDs...)

	err = ops.MarkTxnsFailed(ctx, int64(params.WalletID), failedIDs)
	if err != nil {
		return fmt.Errorf("mark invalidated txns failed: %w", err)
	}

	return nil
}
