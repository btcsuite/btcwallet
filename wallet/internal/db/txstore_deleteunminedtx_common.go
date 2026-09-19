// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
)

// UnminedTxTarget is the normalized root metadata a branch workflow needs.
type UnminedTxTarget = InvalidateUnminedTxTarget

// DeleteUnminedTxOps is the small backend adapter the shared DeleteUnminedTx
// workflow needs. Discovery is shared with the invalidation workflow and row
// removal with the leaf DeleteTx flow.
type DeleteUnminedTxOps interface {
	// LoadInvalidateTarget loads the wallet-scoped root tx metadata.
	LoadInvalidateTarget(ctx context.Context, walletID uint32,
		txHash chainhash.Hash) (UnminedTxTarget, error)

	// ListUnminedTxRecords loads the wallet's active unmined transaction rows
	// in the normalized shape the descendant walk expects.
	ListUnminedTxRecords(ctx context.Context, walletID int64) (
		[]UnminedTxRecord, error)

	// ClearSpentUtxos restores any wallet-owned parent outputs spent by the
	// given transaction row.
	ClearSpentUtxos(ctx context.Context, walletID int64, txID int64) error

	// DeleteCreatedUtxos removes the wallet-owned outputs the given
	// transaction row created.
	DeleteCreatedUtxos(ctx context.Context, walletID uint32, txID int64) error

	// DeleteUnminedTransaction removes one unmined transaction row and
	// reports how many rows it removed.
	DeleteUnminedTransaction(ctx context.Context, walletID uint32,
		txHash chainhash.Hash) (int64, error)
}

// DeleteUnminedTxWithOps removes one wallet-owned unmined transaction root
// together with every descendant the wallet recorded as depending on it.
// Unlike InvalidateUnminedTx, it retains no history.
func DeleteUnminedTxWithOps(ctx context.Context, params DeleteUnminedTxParams,
	ops DeleteUnminedTxOps) error {

	target, err := ops.LoadInvalidateTarget(ctx, params.WalletID, params.Txid)
	if err != nil {
		return fmt.Errorf("load delete tx target: %w", err)
	}

	err = validateUnminedTxTarget(target, ErrDeleteRequiresUnmined)
	if err != nil {
		return err
	}

	candidates, err := ops.ListUnminedTxRecords(ctx, int64(params.WalletID))
	if err != nil {
		return fmt.Errorf("list unmined delete txns: %w", err)
	}

	descendantIDs := CollectDescendantTxIDs(
		[]chainhash.Hash{target.TxHash}, nil, candidates,
	)

	hashByID := make(map[int64]chainhash.Hash, len(candidates))
	for _, candidate := range candidates {
		hashByID[candidate.ID] = candidate.Hash
	}

	// Descendants are removed before the root.
	for i := len(descendantIDs) - 1; i >= 0; i-- {
		descendantID := descendantIDs[i]

		hash, ok := hashByID[descendantID]
		if !ok {
			return fmt.Errorf("descendant tx %d: %w", descendantID,
				ErrTxNotFound)
		}

		err = deleteUnminedBranchMember(
			ctx, params.WalletID, descendantID, hash, ops,
		)
		if err != nil {
			return err
		}
	}

	return deleteUnminedBranchMember(
		ctx, params.WalletID, target.ID, target.TxHash, ops,
	)
}

// deleteUnminedBranchMember removes one member of an unmined branch. Its spend
// edges are cleared before its row goes: the schema uses ON DELETE RESTRICT, so
// a transaction another row still points at cannot be dropped.
func deleteUnminedBranchMember(ctx context.Context, walletID uint32,
	txID int64, txHash chainhash.Hash, ops DeleteUnminedTxOps) error {

	err := ops.ClearSpentUtxos(ctx, int64(walletID), txID)
	if err != nil {
		return fmt.Errorf("clear spent utxos: %w", err)
	}

	err = ops.DeleteCreatedUtxos(ctx, walletID, txID)
	if err != nil {
		return fmt.Errorf("delete created utxos: %w", err)
	}

	rows, err := ops.DeleteUnminedTransaction(ctx, walletID, txHash)
	if err != nil {
		return fmt.Errorf("delete unmined tx: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("tx %s: %w", txHash, ErrTxNotFound)
	}

	return nil
}
