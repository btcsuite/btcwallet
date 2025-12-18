package db

import (
	"context"
	"database/sql"
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
