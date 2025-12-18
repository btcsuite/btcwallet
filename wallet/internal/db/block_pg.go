package db

import (
	"context"
	"database/sql"
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
