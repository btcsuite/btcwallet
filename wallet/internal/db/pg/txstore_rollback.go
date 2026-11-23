package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
)

const maxSQLBlockHeight = int32(1<<31 - 1)

// RewindWallet atomically rewinds one wallet for a manual rescan without
// deleting shared block rows or mutating other wallets' sync states.
func (s *Store) RewindWallet(ctx context.Context,
	params db.RewindWalletParams) error {

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		// Rewind can orphan coinbases and remove their descendants. Lock
		// before graph reads so concurrent children cannot escape removal.
		err := lockTxGraph(ctx, qtx, int64(params.WalletID))
		if err != nil {
			return err
		}

		err = rewindWalletTransactions(ctx, qtx, params)
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
			StartHeight: startHeight,
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
				BlockHeight: sql.NullInt32{},
				Status:      int16(status),
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
		// Rollback changes all Wallets. Read their IDs in ascending order
		// so concurrent rollbacks take the graph locks in the same order.
		wallets, err := qtx.ListWallets(
			ctx, sqlc.ListWalletsParams{
				PageLimit: math.MaxInt64,
			},
		)
		if err != nil {
			return fmt.Errorf("list rollback wallets: %w", err)
		}

		for _, wallet := range wallets {
			err := lockTxGraph(ctx, qtx, wallet.ID)
			if err != nil {
				return err
			}
		}

		return db.RollbackToBlockWithOps(ctx, height,
			rollbackToBlockOps{qtx: qtx})
	})
}

// rollbackToBlockOps adapts postgres sqlc queries to the shared rollback
// sequence.
type rollbackToBlockOps struct {
	qtx *sqlc.Queries

	// walletID binds the existing sequence to the request's history.
	walletID uint32
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

	_, err = o.qtx.RewindWalletSyncStateHeightsForRollback(
		ctx, rollbackHeight,
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

// MarkDescendantsFailed batch-marks the collected rollback descendants as
// failed while retaining their input facts for history.
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

// GetDisconnectBlock reads one owned identity before applying a native event.
func (o rollbackToBlockOps) GetDisconnectBlock(ctx context.Context,
	height uint32) (*db.Block, error) {

	h, err := db.Uint32ToInt32(height)
	if err != nil {
		return nil, err
	}

	row, err := o.qtx.GetWalletBlockByHeight(
		ctx, sqlc.GetWalletBlockByHeightParams{
			WalletID: int64(o.walletID), BlockHeight: h,
		},
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, db.ErrBlockNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get disconnected block: %w", err)
	}

	return db.BuildBlock(row.HeaderHash, height, row.BlockTimestamp)
}

// GetDisconnectCheckpoint reads progress within the existing atomic write.
// An absent checkpoint does not turn later empty observations into progress.
func (o rollbackToBlockOps) GetDisconnectCheckpoint(ctx context.Context) (
	*uint32, error) {

	wallet, err := o.qtx.GetWalletByID(ctx, int64(o.walletID))
	if err != nil {
		return nil, fmt.Errorf("read disconnect checkpoint: %w", err)
	}

	var checkpoint *uint32
	if wallet.SyncedHeight.Valid {
		height, err := db.NullInt32ToUint32(wallet.SyncedHeight)
		if err != nil {
			return nil, fmt.Errorf("decode disconnect checkpoint: %w", err)
		}

		checkpoint = &height
	}

	return checkpoint, nil
}

// ListDisconnectBlocks reads the shared workflow's selected committed range.
// The current write retains empty rows and gaps for identity classification.
func (o rollbackToBlockOps) ListDisconnectBlocks(ctx context.Context,
	start, end uint32) ([]db.Block, error) {

	// Convert to the query's INTEGER parameters using the same checked
	// conversion as the other disconnect reads.
	startHeight, err := db.Uint32ToInt32(start)
	if err != nil {
		return nil, fmt.Errorf("convert disconnect start height: %w", err)
	}

	endHeight, err := db.Uint32ToInt32(end)
	if err != nil {
		return nil, fmt.Errorf("convert disconnect end height: %w", err)
	}

	rows, err := o.qtx.GetWalletBlocksInRange(
		ctx, sqlc.GetWalletBlocksInRangeParams{
			WalletID:    int64(o.walletID),
			StartHeight: startHeight, EndHeight: endHeight,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("read committed disconnect history: %w", err)
	}

	blocks := make([]db.Block, 0, len(rows))
	for _, row := range rows {
		block, err := buildBlock(
			sql.NullInt32{Int32: row.BlockHeight, Valid: true},
			row.HeaderHash,
			sql.NullInt64{Int64: row.BlockTimestamp, Valid: true},
		)
		if err != nil {
			return nil, err
		}

		blocks = append(blocks, *block)
	}

	return blocks, nil
}

// ListDisconnectTransactions retains only stored classification facts, rather
// than hydrating a public transaction view or decoding its raw payload again.
func (o rollbackToBlockOps) ListDisconnectTransactions(ctx context.Context,
	height uint32) ([]db.DisconnectTx, error) {

	h, err := db.Uint32ToInt32(height)
	if err != nil {
		return nil, err
	}

	rows, err := o.qtx.ListTransactionsByHeightRange(
		ctx, sqlc.ListTransactionsByHeightRangeParams{
			WalletID:    int64(o.walletID),
			StartHeight: h, EndHeight: maxSQLBlockHeight,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("list disconnected history: %w", err)
	}

	history := make([]db.DisconnectTx, 0, len(rows))
	for _, row := range rows {
		h, err := db.NullInt32ToUint32(row.BlockHeight)
		if err != nil {
			return nil, fmt.Errorf("disconnect transaction height: %w", err)
		}

		blockHash, err := chainhash.NewHash(row.BlockHash)
		if err != nil {
			return nil, fmt.Errorf("disconnect block hash: %w", err)
		}

		txHash, err := chainhash.NewHash(row.TxHash)
		if err != nil {
			return nil, fmt.Errorf("disconnect transaction hash: %w", err)
		}

		history = append(history, db.DisconnectTx{
			BlockHeight: h, BlockHash: *blockHash,
			Hash: *txHash, IsCoinbase: row.IsCoinbase,
		})
	}

	return history, nil
}
