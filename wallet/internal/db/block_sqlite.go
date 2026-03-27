package db

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/sqlite"
)

// buildSqliteBlock constructs a Block from the given SQLite block
// fields.
func buildSqliteBlock(height sql.NullInt64, hash []byte,
	timestamp sql.NullInt64) (*Block, error) {

	height32, err := int64ToUint32(height.Int64)
	if err != nil {
		return nil, fmt.Errorf("block height: %w", err)
	}

	return buildBlock(hash, height32, timestamp.Int64)
}

// ensureBlockExistsSqlite ensures that a block exists in the database. If it
// doesn't exist, it inserts it.
func ensureBlockExistsSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
	block *Block) error {

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

// requireBlockMatchesSqlite loads the shared block row for the provided height
// and verifies that its stored metadata matches the supplied block reference.
func requireBlockMatchesSqlite(ctx context.Context, qtx *sqlcsqlite.Queries,
	block *Block) (int64, error) {

	height := int64(block.Height)

	storedBlock, err := qtx.GetBlockByHeight(ctx, height)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, fmt.Errorf("block %d: %w", block.Height,
				ErrBlockNotFound)
		}

		return 0, fmt.Errorf("get block by height: %w", err)
	}

	if !bytes.Equal(storedBlock.HeaderHash, block.Hash[:]) {
		return 0, fmt.Errorf("block %d header hash: %w", block.Height,
			ErrBlockMismatch)
	}

	if storedBlock.BlockTimestamp != block.Timestamp.Unix() {
		return 0, fmt.Errorf("block %d timestamp: %w", block.Height,
			ErrBlockMismatch)
	}

	return height, nil
}
