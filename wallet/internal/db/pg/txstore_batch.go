package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// ApplyTxBatch atomically records transactions and an optional sync-tip update.
func (s *Store) ApplyTxBatch(ctx context.Context,
	params db.TxBatchParams) error {

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		// Advance the sync tip first so the synced-to block row exists
		// before any transaction confirmed in that same block is
		// created. CreateTxWithOps needs the confirming block row during
		// PrepareBlock, so creating transactions first would fail with
		// ErrBlockNotFound.
		err := applyBatchSyncTip(ctx, qtx, params)
		if err != nil {
			return err
		}

		for i := range params.Transactions {
			err = applyBatchTransaction(ctx, qtx, params.Transactions[i])
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

	err = db.CreateTxWithOps(ctx, req, &createTxOps{
		invalidateUnminedTxOps: invalidateUnminedTxOps{
			qtx: qtx,
		},
	})
	if !errors.Is(err, db.ErrTxAlreadyExists) {
		return err
	}

	skip, skipErr := canSkipBatchDuplicate(ctx, qtx, req)
	if skipErr != nil {
		return skipErr
	}

	if skip {
		return nil
	}

	return err
}

// canSkipBatchDuplicate reports whether an existing transaction row matches
// the duplicate observation closely enough for ApplyTxBatch/ApplyScanBatch to
// treat it as an idempotent retry.
func canSkipBatchDuplicate(ctx context.Context, qtx *sqlc.Queries,
	req db.CreateTxRequest) (bool, error) {

	row, err := qtx.GetTransactionByHash(
		ctx, sqlc.GetTransactionByHashParams{
			WalletID: int64(req.Params.WalletID),
			TxHash:   req.TxHash[:],
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}

		return false, fmt.Errorf("get duplicate tx: %w", err)
	}

	status, err := db.ParseTxStatus(int64(row.TxStatus))
	if err != nil {
		return false, fmt.Errorf("parse duplicate tx status: %w", err)
	}

	var block *db.Block
	if row.BlockHeight.Valid {
		block, err = buildBlock(
			row.BlockHeight, row.BlockHash, row.BlockTimestamp,
		)
		if err != nil {
			return false, fmt.Errorf("build duplicate tx block: %w", err)
		}
	}

	return db.CanSkipCreateTxDuplicate(req, status, block), nil
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
