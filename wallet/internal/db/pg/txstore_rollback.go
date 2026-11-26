package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

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

// DisconnectBlock atomically reconciles one wallet's persisted block history
// for a disconnected block identity against caller-resolved canonical hashes.
func (s *Store) DisconnectBlock(ctx context.Context, walletID uint32,
	block db.Block, previous *db.Block,
	canonical map[uint32]*chainhash.Hash) error {

	return s.execWrite(ctx, func(qtx *sqlc.Queries) error {
		err := lockTxGraph(ctx, qtx, int64(walletID))
		if err != nil {
			return err
		}

		return db.DisconnectBlockWithOps(
			ctx, walletID, block, previous, canonical,
			rollbackToBlockOps{
				qtx:      qtx,
				walletID: walletID,
			},
		)
	})
}

// rollbackToBlockOps adapts postgres sqlc queries to the shared disconnect
// sequence.
type rollbackToBlockOps struct {
	qtx *sqlc.Queries

	// walletID binds the existing sequence to the request's history.
	walletID uint32
}

var _ db.DisconnectBlockOps = (*rollbackToBlockOps)(nil)

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

// RewindDisconnectReferences applies the shared workflow's selected rewinds.
// Normalize the fork once; SQL rewinds progress across any removed history.
func (o rollbackToBlockOps) RewindDisconnectReferences(ctx context.Context,
	heights []uint32, previous *db.Block) error {

	var fork sql.NullInt32
	if previous != nil {
		height, err := db.Uint32ToInt32(previous.Height)
		if err != nil {
			return err
		}

		fork = sql.NullInt32{Int32: height, Valid: true}
	}

	for _, height := range heights {
		_, err := o.qtx.RewindWalletReferencesForDisconnect(
			ctx, sqlc.RewindWalletReferencesForDisconnectParams{
				WalletID: int64(o.walletID), Height: int64(height),
				PreviousHeight: fork,
			},
		)
		if err != nil {
			return fmt.Errorf("rewind disconnect refs: %w", err)
		}
	}

	return nil
}

// DeleteDisconnectBlocks removes only rows selected by shared recovery policy.
// The shared workflow has already moved every affected reference in this write.
func (o rollbackToBlockOps) DeleteDisconnectBlocks(ctx context.Context,
	heights []uint32) error {

	for _, height := range heights {
		_, err := o.qtx.DeleteWalletBlockByHeight(
			ctx, sqlc.DeleteWalletBlockByHeightParams{
				WalletID: int64(o.walletID), BlockHeight: int64(height),
			},
		)
		if err != nil {
			return fmt.Errorf("delete disconnected block: %w", err)
		}
	}

	return nil
}
