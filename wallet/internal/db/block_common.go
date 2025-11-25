package db

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// buildBlock constructs a Block from the provided components that are common
// across different database backends.
func buildBlock(hash []byte, height uint32, timestamp int64) (*Block, error) {
	h, err := chainhash.NewHash(hash)
	if err != nil {
		return nil, fmt.Errorf("block hash: %w", err)
	}

	return &Block{
		Hash:      *h,
		Height:    height,
		Timestamp: time.Unix(timestamp, 0),
	}, nil
}
