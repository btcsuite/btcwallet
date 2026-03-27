package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcd/chainhash/v2"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// RollbackToBlock atomically removes every block at or above the provided
// height and rewrites wallet sync-state references so the block delete can
// succeed.
func (s *SqliteStore) RollbackToBlock(ctx context.Context,
	height uint32) error {

	return s.ExecuteTx(ctx, func(qtx *sqlcsqlite.Queries) error {
		return rollbackToBlockWithOps(ctx, height,
			sqliteRollbackToBlockOps{qtx: qtx})
	})
}

// sqliteRollbackToBlockOps adapts sqlite sqlc queries to the shared rollback
// sequence.
type sqliteRollbackToBlockOps struct {
	qtx *sqlcsqlite.Queries
}

var _ rollbackToBlockOps = (*sqliteRollbackToBlockOps)(nil)

// listRollbackRootHashes loads the coinbase roots that a rollback disconnects
// and groups them by wallet.
func (o sqliteRollbackToBlockOps) listRollbackRootHashes(ctx context.Context,
	height uint32) (map[uint32]map[chainhash.Hash]struct{}, error) {

	rows, err := o.qtx.ListRollbackCoinbaseRoots(ctx, int64(height))
	if err != nil {
		return nil, fmt.Errorf("query rollback coinbase roots: %w", err)
	}

	return groupRollbackCoinbaseRootsSqlite(rows)
}

// rewindWalletSyncStateHeights clamps wallet sync-state references below the
// rollback boundary before the block rows are deleted.
func (o sqliteRollbackToBlockOps) rewindWalletSyncStateHeights(
	ctx context.Context, height uint32) error {

	newHeight := sql.NullInt64{}
	if height > 0 {
		newHeight = sql.NullInt64{Int64: int64(height - 1), Valid: true}
	}

	_, err := o.qtx.RewindWalletSyncStateHeightsForRollback(
		ctx, sqlcsqlite.RewindWalletSyncStateHeightsForRollbackParams{
			RollbackHeight: int64(height),
			NewHeight:      newHeight,
		},
	)
	if err != nil {
		return fmt.Errorf("rewind wallet sync state heights query: %w", err)
	}

	return nil
}

// deleteBlocksAtOrAboveHeight removes the shared block rows after sync-state
// references have been rewound.
func (o sqliteRollbackToBlockOps) deleteBlocksAtOrAboveHeight(
	ctx context.Context, height uint32) error {

	_, err := o.qtx.DeleteBlocksAtOrAboveHeight(ctx, int64(height))
	if err != nil {
		return fmt.Errorf("delete blocks at or above height query: %w", err)
	}

	return nil
}

// listUnminedTxRecords loads and decodes every unmined transaction row for the
// wallet so the shared helper can inspect raw inputs for descendant edges.
func (o sqliteRollbackToBlockOps) listUnminedTxRecords(
	ctx context.Context, walletID int64) ([]unminedTxRecord, error) {

	rows, err := o.qtx.ListUnminedTransactions(ctx, walletID)
	if err != nil {
		return nil, fmt.Errorf("list unmined txns: %w", err)
	}

	return buildUnminedTxRecords(rows,
		func(row sqlcsqlite.ListUnminedTransactionsRow) (
			int64, []byte, []byte) {

			return row.ID, row.TxHash, row.RawTx
		},
	)
}

// clearDescendantSpends removes any wallet-owned spend edges claimed by one
// invalid descendant transaction before its status is rewritten.
func (o sqliteRollbackToBlockOps) clearDescendantSpends(
	ctx context.Context, walletID int64, descendantID int64) error {

	_, err := o.qtx.ClearUtxosSpentByTxID(
		ctx, sqlcsqlite.ClearUtxosSpentByTxIDParams{
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

// markDescendantsFailed batch-marks the collected rollback descendants as
// failed once every dependent spend edge has been cleared.
func (o sqliteRollbackToBlockOps) markDescendantsFailed(
	ctx context.Context, walletID int64, descendantIDs []int64) error {

	_, err := o.qtx.UpdateTransactionStatusByIDs(
		ctx, sqlcsqlite.UpdateTransactionStatusByIDsParams{
			WalletID: walletID,
			Status:   int64(TxStatusFailed),
			TxIds:    descendantIDs,
		},
	)
	if err != nil {
		return fmt.Errorf("mark descendants failed: %w", err)
	}

	return nil
}

// groupRollbackCoinbaseRootsSqlite groups rollback-affected coinbase hashes by
// wallet so descendant invalidation can reuse wallet-scoped unmined queries.
func groupRollbackCoinbaseRootsSqlite(
	rows []sqlcsqlite.ListRollbackCoinbaseRootsRow) (
	map[uint32]map[chainhash.Hash]struct{}, error) {

	rootHashesByWallet := make(
		map[uint32]map[chainhash.Hash]struct{}, len(rows),
	)
	for _, row := range rows {
		walletID, err := int64ToUint32(row.WalletID)
		if err != nil {
			return nil, fmt.Errorf("rollback coinbase wallet id: %w", err)
		}

		txHash, err := chainhash.NewHash(row.TxHash)
		if err != nil {
			return nil, fmt.Errorf("rollback coinbase hash: %w", err)
		}

		if _, ok := rootHashesByWallet[walletID]; !ok {
			rootHashesByWallet[walletID] = make(map[chainhash.Hash]struct{})
		}

		rootHashesByWallet[walletID][*txHash] = struct{}{}
	}

	return rootHashesByWallet, nil
}
