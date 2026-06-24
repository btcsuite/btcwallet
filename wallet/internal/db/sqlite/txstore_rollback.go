package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

const maxSQLBlockHeight = int64(1<<31 - 1)

// RewindWallet atomically rewinds one wallet for a manual rescan without
// deleting shared block rows or mutating other wallets' sync states.
func (s *Store) RewindWallet(ctx context.Context,
	params db.RewindWalletParams) error {

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		err := rewindWalletTransactions(ctx, qtx, params)
		if err != nil {
			return err
		}

		err = db.UpdateWalletWithOps(ctx, db.UpdateWalletParams{
			WalletID: params.WalletID,
			SyncedTo: &params.Block,
		}, updateWalletOps{q: qtx})
		if err != nil {
			return fmt.Errorf("update wallet sync tip: %w", err)
		}

		return nil
	})
}

// rewindWalletTransactions detaches one wallet's confirmed transactions above
// the manual-rescan rewind point while preserving shared block rows.
func rewindWalletTransactions(ctx context.Context, qtx *sqlc.Queries,
	params db.RewindWalletParams) error {

	startHeight, err := db.Int64ToInt32(int64(params.Block.Height) + 1)
	if err != nil {
		return fmt.Errorf("rewind start height: %w", err)
	}

	rows, err := qtx.ListTransactionsByHeightRange(
		ctx, sqlc.ListTransactionsByHeightRangeParams{
			WalletID:    int64(params.WalletID),
			StartHeight: int64(startHeight),
			EndHeight:   maxSQLBlockHeight,
		},
	)
	if err != nil {
		return fmt.Errorf("list wallet rewind txs: %w", err)
	}

	coinbaseRoots := make([]chainhash.Hash, 0)
	for _, row := range rows {
		txHash, err := chainhash.NewHash(row.TxHash)
		if err != nil {
			return fmt.Errorf("rewind tx hash: %w", err)
		}

		status := db.TxStatusPublished
		if row.IsCoinbase {
			status = db.TxStatusOrphaned

			coinbaseRoots = append(coinbaseRoots, *txHash)
		}

		updated, err := qtx.UpdateTransactionStateByHash(
			ctx, sqlc.UpdateTransactionStateByHashParams{
				BlockHeight: sql.NullInt64{},
				Status:      int64(status),
				WalletID:    int64(params.WalletID),
				TxHash:      row.TxHash,
			},
		)
		if err != nil {
			return fmt.Errorf("detach rewind tx %s: %w", txHash, err)
		}

		if updated == 0 {
			return fmt.Errorf("rewind tx %s: %w", txHash,
				db.ErrTxNotFound)
		}
	}

	if len(coinbaseRoots) == 0 {
		return nil
	}

	return db.InvalidateRollbackDescendants(
		ctx, map[uint32][]chainhash.Hash{
			params.WalletID: coinbaseRoots,
		}, rollbackToBlockOps{qtx: qtx},
	)
}

// RollbackToBlock atomically removes every block at or above the provided
// height and rewrites wallet sync-state references so the block delete can
// succeed.
func (s *Store) RollbackToBlock(ctx context.Context,
	height uint32) error {

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		return db.RollbackToBlockWithOps(ctx, height,
			rollbackToBlockOps{qtx: qtx})
	})
}

// rollbackToBlockOps adapts sqlite sqlc queries to the shared rollback
// sequence.
type rollbackToBlockOps struct {
	qtx *sqlc.Queries
}

var _ db.RollbackToBlockOps = (*rollbackToBlockOps)(nil)

// ListRollbackRootHashes loads the coinbase roots that a rollback disconnects
// and groups them by wallet.
func (o rollbackToBlockOps) ListRollbackRootHashes(ctx context.Context,
	height uint32) (map[uint32][]chainhash.Hash, error) {

	rows, err := o.qtx.ListRollbackCoinbaseRoots(ctx, int64(height))
	if err != nil {
		return nil, fmt.Errorf("query rollback coinbase roots: %w", err)
	}

	return groupRollbackCoinbaseRoots(rows)
}

// RewindWalletSyncStateHeights clamps wallet sync-state references below the
// rollback boundary before the block rows are deleted.
func (o rollbackToBlockOps) RewindWalletSyncStateHeights(
	ctx context.Context, height uint32) error {

	_, err := o.qtx.RewindWalletSyncStateHeightsForRollback(
		ctx, int64(height),
	)
	if err != nil {
		return fmt.Errorf("rewind wallet sync state heights query: %w", err)
	}

	return nil
}

// DeleteBlocksAtOrAboveHeight removes the shared block rows after sync-state
// references have been rewound.
func (o rollbackToBlockOps) DeleteBlocksAtOrAboveHeight(
	ctx context.Context, height uint32) error {

	_, err := o.qtx.DeleteBlocksAtOrAboveHeight(ctx, int64(height))
	if err != nil {
		return fmt.Errorf("delete blocks at or above height query: %w", err)
	}

	return nil
}

// MarkTxRootsOrphaned rewrites each disconnected coinbase root to the
// orphaned state once its confirming block has been deleted.
func (o rollbackToBlockOps) MarkTxRootsOrphaned(
	ctx context.Context, walletID uint32,
	rootHashes []chainhash.Hash) error {

	for _, txHash := range rootHashes {
		// Rollback already removed the confirming block rows.
		// The remaining coinbase row must therefore clear its
		// block reference and become orphaned in the same
		// row-local state patch.
		rows, err := o.qtx.UpdateTransactionStateByHash(
			ctx, sqlc.UpdateTransactionStateByHashParams{
				BlockHeight: sql.NullInt64{},
				Status:      int64(db.TxStatusOrphaned),
				WalletID:    int64(walletID),
				TxHash:      txHash[:],
			},
		)
		if err != nil {
			return fmt.Errorf("update rollback coinbase state query: %w", err)
		}

		if rows == 0 {
			return fmt.Errorf("tx %s: %w", txHash, db.ErrTxNotFound)
		}
	}

	return nil
}

// ListUnminedTxRecords loads and decodes every unmined transaction row for the
// wallet so the shared helper can inspect raw inputs for descendant edges.
func (o rollbackToBlockOps) ListUnminedTxRecords(
	ctx context.Context, walletID int64) ([]db.UnminedTxRecord, error) {

	rows, err := o.qtx.ListUnminedTransactions(ctx, walletID)
	if err != nil {
		return nil, fmt.Errorf("list unmined txns: %w", err)
	}

	return db.BuildUnminedTxRecords(rows,
		func(row sqlc.ListUnminedTransactionsRow) (
			int64, []byte, []byte) {

			return row.ID, row.TxHash, row.RawTx
		},
	)
}

// ClearDescendantSpends removes any wallet-owned spend edges claimed by one
// invalid descendant transaction before its status is rewritten.
func (o rollbackToBlockOps) ClearDescendantSpends(
	ctx context.Context, walletID int64, descendantID int64) error {

	_, err := o.qtx.ClearUtxosSpentByTxID(
		ctx, sqlc.ClearUtxosSpentByTxIDParams{
			WalletID: walletID,
			SpentByTxID: sql.NullInt64{
				Int64: descendantID,
				Valid: true,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("clear descendant spends: %w", err)
	}

	return nil
}

// MarkDescendantsFailed batch-marks the collected rollback descendants as
// failed once every dependent spend edge has been cleared.
func (o rollbackToBlockOps) MarkDescendantsFailed(
	ctx context.Context, walletID int64, descendantIDs []int64) error {

	_, err := o.qtx.UpdateTransactionStatusByIDs(
		ctx, sqlc.UpdateTransactionStatusByIDsParams{
			WalletID: walletID,
			Status:   int64(db.TxStatusFailed),
			TxIds:    descendantIDs,
		},
	)
	if err != nil {
		return fmt.Errorf("mark descendants failed: %w", err)
	}

	return nil
}

// groupRollbackCoinbaseRoots groups rollback-affected coinbase hashes by
// wallet while preserving the query order inside each wallet bucket.
func groupRollbackCoinbaseRoots(
	rows []sqlc.ListRollbackCoinbaseRootsRow) (
	map[uint32][]chainhash.Hash, error) {

	rootHashesByWallet := make(
		map[uint32][]chainhash.Hash, len(rows),
	)
	for _, row := range rows {
		walletID, err := db.Int64ToUint32(row.WalletID)
		if err != nil {
			return nil, fmt.Errorf("rollback coinbase wallet id: %w", err)
		}

		txHash, err := chainhash.NewHash(row.TxHash)
		if err != nil {
			return nil, fmt.Errorf("rollback coinbase hash: %w", err)
		}

		rootHashesByWallet[walletID] = append(
			rootHashesByWallet[walletID], *txHash,
		)
	}

	return rootHashesByWallet, nil
}
