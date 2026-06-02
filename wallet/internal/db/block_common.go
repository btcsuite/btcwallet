package db

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// BuildBlock constructs a Block from the provided components that are common
// across different database backends.
func BuildBlock(hash []byte, height uint32, timestamp int64) (*Block, error) {
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

// BlockStampFromBlock converts database block metadata into the legacy
// block-stamp shape used by wallet runtime state.
func BlockStampFromBlock(block *Block) (waddrmgr.BlockStamp, error) {
	height, err := Uint32ToInt32(block.Height)
	if err != nil {
		return waddrmgr.BlockStamp{}, fmt.Errorf("%w: store block "+
			"height %d exceeds max int32", ErrInvalidParam,
			block.Height)
	}

	return waddrmgr.BlockStamp{
		Height:    height,
		Hash:      block.Hash,
		Timestamp: block.Timestamp,
	}, nil
}

// BlockFromBlockStamp converts a legacy block-stamp into the database store
// block shape. The timestamp is normalized to UTC.
func BlockFromBlockStamp(block waddrmgr.BlockStamp) (*Block, error) {
	height, err := Int64ToUint32(int64(block.Height))
	if err != nil {
		return nil, fmt.Errorf("%w: block height %d cannot "+
			"convert to uint32", ErrInvalidParam, block.Height)
	}

	return &Block{
		Hash:      block.Hash,
		Height:    height,
		Timestamp: block.Timestamp.UTC(),
	}, nil
}

// OptionalBlockFromBlockStamp converts a legacy block-stamp into the database
// store block shape, returning nil for missing metadata.
func OptionalBlockFromBlockStamp(block waddrmgr.BlockStamp) *Block {
	if block.Height < 0 {
		return nil
	}

	return &Block{
		Hash:      block.Hash,
		Height:    uint32(block.Height),
		Timestamp: block.Timestamp.UTC(),
	}
}
