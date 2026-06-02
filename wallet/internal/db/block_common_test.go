package db

import (
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// TestBlockStampFromBlock verifies that store block metadata converts to the
// legacy block-stamp shape and rejects heights that do not fit int32.
func TestBlockStampFromBlock(t *testing.T) {
	t.Parallel()

	var hash chainhash.Hash

	hash[0] = 1

	timestamp := time.Unix(123, 0).UTC()
	block := &Block{
		Hash:      hash,
		Height:    42,
		Timestamp: timestamp,
	}

	stamp, err := BlockStampFromBlock(block)
	require.NoError(t, err)
	require.Equal(t, int32(42), stamp.Height)
	require.Equal(t, hash, stamp.Hash)
	require.Equal(t, timestamp, stamp.Timestamp)

	block.Height = uint32(math.MaxInt32) + 1
	_, err = BlockStampFromBlock(block)
	require.ErrorIs(t, err, ErrInvalidParam)
}

// TestBlockFromBlockStamp verifies that legacy block-stamps convert to the
// store block shape with UTC timestamps.
func TestBlockFromBlockStamp(t *testing.T) {
	t.Parallel()

	var hash chainhash.Hash

	hash[0] = 2

	zone := time.FixedZone("offset", 3600)
	timestamp := time.Date(2024, 1, 2, 3, 4, 5, 0, zone)
	stamp := waddrmgr.BlockStamp{
		Hash:      hash,
		Height:    42,
		Timestamp: timestamp,
	}

	block, err := BlockFromBlockStamp(stamp)
	require.NoError(t, err)
	require.Equal(t, hash, block.Hash)
	require.Equal(t, uint32(42), block.Height)
	require.Equal(t, timestamp.UTC(), block.Timestamp)

	stamp.Height = -1
	_, err = BlockFromBlockStamp(stamp)
	require.ErrorIs(t, err, ErrInvalidParam)
}

// TestOptionalBlockFromBlockStamp verifies that optional legacy block-stamps
// map negative heights to nil block metadata.
func TestOptionalBlockFromBlockStamp(t *testing.T) {
	t.Parallel()

	block := OptionalBlockFromBlockStamp(waddrmgr.BlockStamp{
		Height: -1,
	})
	require.Nil(t, block)
}
