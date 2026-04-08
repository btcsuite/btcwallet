package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	db "github.com/btcsuite/btcwallet/wallet/internal/db"

	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
)

// buildBlock constructs a Block from the given SQLite block
// fields.
func buildBlock(height sql.NullInt64, hash []byte,
	timestamp sql.NullInt64) (*db.Block, error) {

	height32, err := db.Int64ToUint32(height.Int64)
	if err != nil {
		return nil, fmt.Errorf("block height: %w", err)
	}

	return db.BuildBlock(hash, height32, timestamp.Int64)
}

// ensureBlockExists ensures that a block exists in the database. If it
// doesn't exist, it inserts it.
func ensureBlockExists(ctx context.Context, qtx *sqlcsqlite.Queries,
	block *db.Block) error {

	height := int64(block.Height)

	blockParams := sqlcsqlite.InsertBlockParams{
		BlockHeight:    height,
		HeaderHash:     block.Hash[:],
		BlockTimestamp: block.Timestamp.Unix(),
	}

	err := qtx.InsertBlock(ctx, blockParams)
	if err != nil {
		return fmt.Errorf("insert block: %w", err)
	}

	return nil
}

// requireBlockMatches loads the shared block row for the provided height
// and verifies that its stored metadata matches the supplied block reference.
func requireBlockMatches(ctx context.Context, qtx *sqlcsqlite.Queries,
	block *db.Block) (int64, error) {

	height := int64(block.Height)

	storedBlock, err := qtx.GetBlockByHeight(ctx, height)
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
