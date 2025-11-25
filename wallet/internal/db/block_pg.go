package db

import (
	"database/sql"
	"fmt"
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
