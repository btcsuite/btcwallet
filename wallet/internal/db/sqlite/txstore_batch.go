package sqlite

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
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
			req, err := db.NewCreateTxRequest(params.Transactions[i])
			if err != nil {
				return fmt.Errorf("validate tx %d: %w", i, err)
			}

			err = db.CreateTxWithOps(ctx, req, &createTxOps{
				invalidateUnminedTxOps: invalidateUnminedTxOps{
					qtx: qtx,
				},
			})
			if errors.Is(err, db.ErrTxAlreadyExists) {
				continue
			}

			if err != nil {
				return fmt.Errorf("create tx %d: %w", i, err)
			}
		}

		return nil
	})
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
