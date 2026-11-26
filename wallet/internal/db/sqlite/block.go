package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// buildBlock constructs a Block from the given SQLite block
// fields.
func buildBlock(height sql.NullInt64, hash []byte,
	timestamp sql.NullInt64) (*db.Block, error) {

	if !height.Valid {
		return nil, fmt.Errorf("block height: %w", db.ErrInvalidNullInt)
	}

	height32, err := db.Int64ToUint32(height.Int64)
	if err != nil {
		return nil, fmt.Errorf("block height: %w", err)
	}

	return db.BuildBlock(hash, height32, timestamp.Int64)
}

// ensureBlockExists ensures that a block exists in the database. If it
// doesn't exist, it inserts it.
func ensureBlockExists(ctx context.Context, qtx *sqlc.Queries,
	walletID uint32, block *db.Block) error {

	height := int64(block.Height)

	blockParams := sqlc.InsertWalletBlockParams{
		WalletID:       int64(walletID),
		BlockHeight:    height,
		HeaderHash:     block.Hash[:],
		BlockTimestamp: block.Timestamp.Unix(),
	}

	err := qtx.InsertWalletBlock(ctx, blockParams)
	if err != nil {
		// wallet_blocks has a single foreign key on wallet_id; map a
		// foreign-key failure back to ErrWalletNotFound so callers
		// updating or writing checkpoints for a missing wallet keep the
		// documented sentinel without inflating SQL constraint metrics.
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) &&
			sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY {

			return fmt.Errorf(
				"wallet %d: %w", walletID, db.ErrWalletNotFound,
			)
		}

		return fmt.Errorf("insert block: %w", err)
	}

	_, err = requireBlockMatches(ctx, qtx, walletID, block)
	if err != nil {
		return err
	}

	return nil
}

// requireBlockMatches loads the owning Wallet's block row and verifies its
// metadata against the supplied confirmation reference.
func requireBlockMatches(ctx context.Context, qtx *sqlc.Queries,
	walletID uint32, block *db.Block) (int64, error) {

	height := int64(block.Height)

	storedBlock, err := qtx.GetWalletBlockByHeight(
		ctx, sqlc.GetWalletBlockByHeightParams{
			WalletID: int64(walletID), BlockHeight: height,
		},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, fmt.Errorf("block %d: %w", block.Height,
				db.ErrBlockNotFound)
		}

		return 0, fmt.Errorf("get block by height: %w", err)
	}

	if !bytes.Equal(storedBlock.HeaderHash, block.Hash[:]) {
		return 0, fmt.Errorf("block %d header hash: %w", block.Height,
			db.ErrBlockMismatch)
	}

	if storedBlock.BlockTimestamp != block.Timestamp.Unix() {
		return 0, fmt.Errorf("block %d timestamp: %w", block.Height,
			db.ErrBlockMismatch)
	}

	return height, nil
}
