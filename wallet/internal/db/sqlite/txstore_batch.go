package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
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

	err = db.CreateTxWithOps(ctx, req, ops)
	if err != nil && !errors.Is(err, db.ErrTxAlreadyExists) {
		return err
	}

	skip, txID, skipErr := canSkipBatchDuplicate(ctx, qtx, req)
	if skipErr != nil {
		return skipErr
	}

	if !skip {
		return err
	}

	return replayBatchDuplicateEdges(ctx, req, txID, ops)
}

// replayBatchDuplicateEdges fills in any credit or wallet-input-spend edges a
// duplicate batch tx is missing.
//
// CreateTxWithOps can return nil for an idempotent duplicate before writing
// credits or marking wallet-input spends, so a matching row shape is not enough
// to skip on its own. The edges are replayed idempotently: InsertCredits skips
// outputs already recorded and MarkInputsSpent treats a spend already attached
// to this same row as a no-op, while either still rejects a genuinely
// conflicting edge.
func replayBatchDuplicateEdges(ctx context.Context, req db.CreateTxRequest,
	txID int64, ops db.CreateTxOps) error {

	err := ops.InsertCredits(ctx, req, txID)
	if err != nil {
		return fmt.Errorf("replay duplicate tx credits: %w", err)
	}

	err = ops.MarkInputsSpent(ctx, req, txID)
	if err != nil {
		return fmt.Errorf("replay duplicate tx spends: %w", err)
	}

	return nil
}

// canSkipBatchDuplicate reports whether an existing transaction row matches the
// duplicate observation closely enough for ApplyTxBatch/ApplyScanBatch to
// replay its edges instead of failing. It also returns the existing row ID so
// the caller can replay the credit and wallet-input-spend writes against it.
func canSkipBatchDuplicate(ctx context.Context, qtx *sqlc.Queries,
	req db.CreateTxRequest) (bool, int64, error) {

	row, err := qtx.GetTransactionByHash(
		ctx, sqlc.GetTransactionByHashParams{
			WalletID: int64(req.Params.WalletID),
			TxHash:   req.TxHash[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, 0, nil
		}

		return false, 0, fmt.Errorf("get duplicate tx: %w", err)
	}

	status, err := db.ParseTxStatus(row.TxStatus)
	if err != nil {
		return false, 0, fmt.Errorf("parse duplicate tx status: %w", err)
	}

	var block *db.Block
	if row.BlockHeight.Valid {
		block, err = buildBlock(
			row.BlockHeight, row.BlockHash, row.BlockTimestamp,
		)
		if err != nil {
			return false, 0, fmt.Errorf("build duplicate tx block: %w",
				err)
		}
	}

	return db.CanSkipCreateTxDuplicate(
		req, status, row.TxLabel, row.IsCoinbase, block,
	), row.ID, nil
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

	syncParams := buildUpdateSyncParams(db.UpdateWalletParams{
		WalletID: params.WalletID,
		SyncedTo: params.SyncedTo,
	})

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
