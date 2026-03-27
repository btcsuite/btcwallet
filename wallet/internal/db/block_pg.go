package db

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
)

// buildPgBlock constructs a Block from the given PostgreSQL block
// fields.
func buildPgBlock(height sql.NullInt32, hash []byte,
	timestamp sql.NullInt64) (*Block, error) {

	height32, err := nullInt32ToUint32(height)
	if err != nil {
		return nil, fmt.Errorf("block height: %w", err)
	}

	return buildBlock(hash, height32, timestamp.Int64)
}

// ensureBlockExistsPg ensures that a block exists in the database.
func ensureBlockExistsPg(ctx context.Context, qtx *sqlcpg.Queries,
	block *Block) error {

	height, err := uint32ToInt32(block.Height)
	if err != nil {
		return fmt.Errorf("convert block height: %w", err)
	}

	blockParams := sqlcpg.InsertBlockParams{
		BlockHeight:    height,
		HeaderHash:     block.Hash[:],
		BlockTimestamp: block.Timestamp.Unix(),
	}

	err = qtx.InsertBlock(ctx, blockParams)
	if err != nil {
		return fmt.Errorf("insert block: %w", err)
	}

	return nil
}

// requireBlockMatchesPg loads the shared block row for the provided height and
// verifies that its stored metadata matches the supplied block reference.
func requireBlockMatchesPg(ctx context.Context, qtx *sqlcpg.Queries,
	block *Block) (int32, error) {

	height, err := uint32ToInt32(block.Height)
	if err != nil {
		return 0, fmt.Errorf("convert block height: %w", err)
	}

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
