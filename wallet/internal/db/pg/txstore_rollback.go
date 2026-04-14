package pg

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

// RollbackToBlock atomically removes every block at or above the provided
// height and rewrites wallet sync-state references so the block delete can
// succeed.
func (s *Store) RollbackToBlock(ctx context.Context,
	height uint32) error {

	return s.ExecuteTx(ctx, func(qtx *sqlc.Queries) error {
		return db.RollbackToBlockWithOps(ctx, height,
			rollbackToBlockOps{qtx: qtx})
	})
}

// rollbackToBlockOps adapts postgres sqlc queries to the shared rollback
// sequence.
type rollbackToBlockOps struct {
	qtx *sqlc.Queries
}

var _ db.RollbackToBlockOps = (*rollbackToBlockOps)(nil)

// ListRollbackRootHashes loads the coinbase roots that a rollback disconnects
// and groups them by wallet.
func (o rollbackToBlockOps) ListRollbackRootHashes(ctx context.Context,
	height uint32) (map[uint32][]chainhash.Hash, error) {

	rollbackHeight, err := db.Uint32ToInt32(height)
	if err != nil {
		return nil, fmt.Errorf("convert rollback height: %w", err)
	}

	rows, err := o.qtx.ListRollbackCoinbaseRoots(ctx, rollbackHeight)
	if err != nil {
		return nil, fmt.Errorf("query rollback coinbase roots: %w", err)
	}

	return groupRollbackCoinbaseRoots(rows)
}

// RewindWalletSyncStateHeights clamps wallet sync-state references below the
// rollback boundary before the block rows are deleted.
func (o rollbackToBlockOps) RewindWalletSyncStateHeights(
	ctx context.Context, height uint32) error {

	// PostgreSQL stores block heights as INTEGER today, so rollback still needs
	// a checked cast into the current int32-backed schema. On networks with
	// Bitcoin's 10-minute target spacing, MaxInt32 would not be reached until
	// around year 42839. Regtest can exceed that sooner because blocks are
	// mined on demand.
	//
	// TODO(yy): Fix it when we are in year 42000, which will give us 800 years
	// before it's reached.
	rollbackHeight, err := db.Uint32ToInt32(height)
	if err != nil {
		return fmt.Errorf("convert rollback height: %w", err)
	}

	newHeight := sql.NullInt32{}
	if height > 0 {
		newHeight, err = db.Uint32ToNullInt32(height - 1)
		if err != nil {
			return fmt.Errorf("convert new height: %w", err)
		}
	}

	_, err = o.qtx.RewindWalletSyncStateHeightsForRollback(
		ctx, sqlc.RewindWalletSyncStateHeightsForRollbackParams{
			RollbackHeight: rollbackHeight,
			NewHeight:      newHeight,
		},
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

	rollbackHeight, err := db.Uint32ToInt32(height)
	if err != nil {
		return fmt.Errorf("convert rollback height: %w", err)
	}

	_, err = o.qtx.DeleteBlocksAtOrAboveHeight(ctx, rollbackHeight)
	if err != nil {
		return fmt.Errorf("delete blocks at or above height query: %w", err)
	}

	return nil
}

// MarkTxRootsOrphaned rewrites each disconnected coinbase root to the
// orphaned state once its confirming block has been deleted.
func (o rollbackToBlockOps) MarkTxRootsOrphaned(ctx context.Context,
	walletID uint32, rootHashes []chainhash.Hash) error {

	for _, txHash := range rootHashes {
		// Rollback already removed the confirming block rows.
		// The remaining coinbase row must therefore clear its
		// block reference and become orphaned in the same
		// row-local state patch.
		rows, err := o.qtx.UpdateTransactionStateByHash(
			ctx, sqlc.UpdateTransactionStateByHashParams{
				BlockHeight: sql.NullInt32{},
				Status:      int16(db.TxStatusOrphaned),
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
		func(row sqlc.ListUnminedTransactionsRow) (int64, []byte, []byte) {
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
			Status:   int16(db.TxStatusFailed),
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
func groupRollbackCoinbaseRoots(rows []sqlc.ListRollbackCoinbaseRootsRow) (
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
