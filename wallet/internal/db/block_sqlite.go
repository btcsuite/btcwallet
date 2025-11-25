package db

import (
	"database/sql"
	"fmt"
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
