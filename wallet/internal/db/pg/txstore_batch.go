package pg

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// ApplyTxBatch atomically records transactions and an optional sync-tip update.
func (s *Store) ApplyTxBatch(ctx context.Context,
	params db.TxBatchParams) error {

	// Reject a batch that mixes wallets before opening the write transaction:
	// the sync tip is updated for params.WalletID, so a transaction owned by a
	// different wallet must not ride along in the same atomic batch.
	err := db.ValidateBatchTransactionsWalletID(
		params.WalletID, params.Transactions,
	)
	if err != nil {
		return err
	}

	// Reject a nil-Tx member before SortTxBatchParentsFirst dereferences each
	// transaction below; the per-tx NewCreateTxRequest check in
	// applyBatchTransaction runs only after the sort.
	err = db.ValidateBatchTransactionsTx(params.Transactions)
	if err != nil {
		return err
	}

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		err := applyBatchSyncTip(ctx, qtx, params)
		if err != nil {
			return err
		}

		// Record any in-batch parent before its children. Each tx claims
		// its spent parent inputs by updating the parent credit's UTXO row,
		// so a child applied before its in-batch parent would update no row
		// and silently drop the spend edge. Sorting parents first makes the
		// batch order-independent; an already parents-first or
		// dependency-free batch is returned unchanged.
		txs := db.SortTxBatchParentsFirst(params.Transactions)

		for i := range txs {
			err = applyBatchTransaction(ctx, qtx, txs[i])
			if err != nil {
				return fmt.Errorf("create tx %d: %w", i, err)
			}
		}

		return nil
	})
}

// applyBatchTransaction records one transaction from a runtime batch.
func applyBatchTransaction(ctx context.Context, qtx *sqlc.Queries,
	params db.CreateTxParams) error {

	req, err := db.NewCreateTxRequest(params)
	if err != nil {
		return fmt.Errorf("validate tx: %w", err)
	}

	ops := &createTxOps{
		invalidateUnminedTxOps: invalidateUnminedTxOps{
			qtx: qtx,
		},
	}

	// A confirmed tx may reference a block the batch never advanced the
	// sync tip to: SyncedTo is nil for standalone relevant-tx
	// notifications. Ensure that confirming block row exists before
	// CreateTxWithOps validates it during PrepareBlock, otherwise the
	// confirmed insert fails with ErrBlockNotFound. This only inserts the
	// block row; advancing the wallet sync tip stays the sole
	// responsibility of applyBatchSyncTip.
	if params.Block != nil {
		err = ensureBlockExists(ctx, qtx, params.Block)
		if err != nil {
			return fmt.Errorf("ensure tx block: %w", err)
		}
	}

	return db.CreateTxWithOps(ctx, req, ops)
}

// applyBatchSyncTip applies the optional sync-tip update within a batch.
func applyBatchSyncTip(ctx context.Context, qtx *sqlc.Queries,
	params db.TxBatchParams) error {

	if params.SyncedTo == nil {
		return nil
	}

	err := ensureBlockExists(ctx, qtx, params.SyncedTo)
	if err != nil {
		return fmt.Errorf("ensure synced block: %w", err)
	}

	syncParams, err := buildUpdateSyncParams(db.UpdateWalletParams{
		WalletID: params.WalletID,
		SyncedTo: params.SyncedTo,
	})
	if err != nil {
		return err
	}

	rowsAffected, err := qtx.UpdateWalletSyncState(ctx, syncParams)
	if err != nil {
		return fmt.Errorf("update wallet sync state: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("wallet sync state for wallet %d: %w",
			params.WalletID, db.ErrWalletNotFound)
	}

	return nil
}
