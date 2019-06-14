package wallet

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
)

const (
	// defaultBlockInterval is the default time interval between any two
	// blocks in a mocked chain.
	defaultBlockInterval = 10 * time.Minute
)

var (
	// chainParams are the chain parameters used throughout the wallet
	// tests.
	chainParams = chaincfg.MainNetParams
)

// mockChainConn is a mock in-memory implementation of the chainConn interface
// that will be used for the birthday block sanity check tests. The struct is
// capable of being backed by a chain in order to reproduce real-world
// scenarios.
type mockChainConn struct {
	chainTip    uint32
	blockHashes map[uint32]chainhash.Hash
	blocks      map[chainhash.Hash]*wire.MsgBlock
}

var _ chainConn = (*mockChainConn)(nil)

// createMockChainConn creates a new mock chain connection backed by a chain
// with N blocks. Each block has a timestamp that is exactly blockInterval after
// the previous block's timestamp.
func createMockChainConn(genesis *wire.MsgBlock, n uint32,
	blockInterval time.Duration) *mockChainConn {

	c := &mockChainConn{
		chainTip:    n,
		blockHashes: make(map[uint32]chainhash.Hash),
		blocks:      make(map[chainhash.Hash]*wire.MsgBlock),
	}

	genesisHash := genesis.BlockHash()
	c.blockHashes[0] = genesisHash
	c.blocks[genesisHash] = genesis

	for i := uint32(1); i <= n; i++ {
		prevTimestamp := c.blocks[c.blockHashes[i-1]].Header.Timestamp
		block := &wire.MsgBlock{
			Header: wire.BlockHeader{
				Timestamp: prevTimestamp.Add(blockInterval),
			},
		}

		blockHash := block.BlockHash()
		c.blockHashes[i] = blockHash
		c.blocks[blockHash] = block
	}

	return c
}

// GetBestBlock returns the hash and height of the best block known to the
// backend.
func (c *mockChainConn) GetBestBlock() (*chainhash.Hash, int32, error) {
	bestHash, ok := c.blockHashes[c.chainTip]
	if !ok {
		return nil, 0, fmt.Errorf("block with height %d not found",
			c.chainTip)
	}

	return &bestHash, int32(c.chainTip), nil
}

// GetBlockHash returns the hash of the block with the given height.
func (c *mockChainConn) GetBlockHash(height int64) (*chainhash.Hash, error) {
	hash, ok := c.blockHashes[uint32(height)]
	if !ok {
		return nil, fmt.Errorf("block with height %d not found", height)
	}

	return &hash, nil
}

// GetBlockHeader returns the header for the block with the given hash.
func (c *mockChainConn) GetBlockHeader(hash *chainhash.Hash) (*wire.BlockHeader, error) {
	block, ok := c.blocks[*hash]
	if !ok {
		return nil, fmt.Errorf("header for block %v not found", hash)
	}

	return &block.Header, nil
}

// mockBirthdayStore is a mock in-memory implementation of the birthdayStore interface
// that will be used for the birthday block sanity check tests.
type mockBirthdayStore struct {
	birthday              time.Time
	birthdayBlock         *waddrmgr.BlockStamp
	birthdayBlockVerified bool
	syncedTo              waddrmgr.BlockStamp
}

var _ birthdayStore = (*mockBirthdayStore)(nil)

// Birthday returns the birthday timestamp of the wallet.
func (s *mockBirthdayStore) Birthday() time.Time {
	return s.birthday
}

// BirthdayBlock returns the birthday block of the wallet.
func (s *mockBirthdayStore) BirthdayBlock() (waddrmgr.BlockStamp, bool, error) {
	if s.birthdayBlock == nil {
		err := waddrmgr.ManagerError{
			ErrorCode: waddrmgr.ErrBirthdayBlockNotSet,
		}
		return waddrmgr.BlockStamp{}, false, err
	}

	return *s.birthdayBlock, s.birthdayBlockVerified, nil
}

// SetBirthdayBlock updates the birthday block of the wallet to the given block.
// The boolean can be used to signal whether this block should be sanity checked
// the next time the wallet starts.
func (s *mockBirthdayStore) SetBirthdayBlock(block waddrmgr.BlockStamp) error {
	s.birthdayBlock = &block
	s.birthdayBlockVerified = true
	s.syncedTo = block
	return nil
}

// TestBirthdaySanityCheckEmptyBirthdayBlock ensures that a sanity check is not
// done if the birthday block does not exist in the first place.
func TestBirthdaySanityCheckEmptyBirthdayBlock(t *testing.T) {
	t.Parallel()

	chainConn := &mockChainConn{}

	// Our birthday store will reflect that we don't have a birthday block
	// set, so we should not attempt a sanity check.
	birthdayStore := &mockBirthdayStore{}

	birthdayBlock, err := birthdaySanityCheck(chainConn, birthdayStore)
	if !waddrmgr.IsError(err, waddrmgr.ErrBirthdayBlockNotSet) {
		t.Fatalf("expected ErrBirthdayBlockNotSet, got %v", err)
	}

	if birthdayBlock != nil {
		t.Fatalf("expected birthday block to be nil due to not being "+
			"set, got %v", *birthdayBlock)
	}
}

// TestBirthdaySanityCheckVerifiedBirthdayBlock ensures that a sanity check is
// not performed if the birthday block has already been verified.
func TestBirthdaySanityCheckVerifiedBirthdayBlock(t *testing.T) {
	t.Parallel()

	const chainTip = 5000
	chainConn := createMockChainConn(
		chainParams.GenesisBlock, chainTip, defaultBlockInterval,
	)
	expectedBirthdayBlock := waddrmgr.BlockStamp{Height: 1337}

	// Our birthday store reflects that our birthday block has already been
	// verified and should not require a sanity check.
	birthdayStore := &mockBirthdayStore{
		birthdayBlock:         &expectedBirthdayBlock,
		birthdayBlockVerified: true,
		syncedTo: waddrmgr.BlockStamp{
			Height: chainTip,
		},
	}

	// Now, we'll run the sanity check. We should see that the birthday
	// block hasn't changed.
	birthdayBlock, err := birthdaySanityCheck(chainConn, birthdayStore)
	if err != nil {
		t.Fatalf("unable to sanity check birthday block: %v", err)
	}
	if !reflect.DeepEqual(*birthdayBlock, expectedBirthdayBlock) {
		t.Fatalf("expected birthday block %v, got %v",
			expectedBirthdayBlock, birthdayBlock)
	}

	// To ensure the sanity check didn't proceed, we'll check our synced to
	// height, as this value should have been modified if a new candidate
	// was found.
	if birthdayStore.syncedTo.Height != chainTip {
		t.Fatalf("expected synced height remain the same (%d), got %d",
			chainTip, birthdayStore.syncedTo.Height)
	}
}

// TestBirthdaySanityCheckLowerEstimate ensures that we can properly locate a
// better birthday block candidate if our estimate happens to be too far back in
// the chain.
func TestBirthdaySanityCheckLowerEstimate(t *testing.T) {
	t.Parallel()

	// We'll start by defining our birthday timestamp to be around the
	// timestamp of the 1337th block.
	genesisTimestamp := chainParams.GenesisBlock.Header.Timestamp
	birthday := genesisTimestamp.Add(1337 * defaultBlockInterval)

	// We'll establish a connection to a mock chain of 5000 blocks.
	chainConn := createMockChainConn(
		chainParams.GenesisBlock, 5000, defaultBlockInterval,
	)

	// Our birthday store will reflect that our birthday block is currently
	// set as the genesis block. This value is too low and should be
	// adjusted by the sanity check.
	birthdayStore := &mockBirthdayStore{
		birthday: birthday,
		birthdayBlock: &waddrmgr.BlockStamp{
			Hash:      *chainParams.GenesisHash,
			Height:    0,
			Timestamp: genesisTimestamp,
		},
		birthdayBlockVerified: false,
		syncedTo: waddrmgr.BlockStamp{
			Height: 5000,
		},
	}

	// We'll perform the sanity check and determine whether we were able to
	// find a better birthday block candidate.
	birthdayBlock, err := birthdaySanityCheck(chainConn, birthdayStore)
	if err != nil {
		t.Fatalf("unable to sanity check birthday block: %v", err)
	}
	if birthday.Sub(birthdayBlock.Timestamp) >= birthdayBlockDelta {
		t.Fatalf("expected birthday block timestamp=%v to be within "+
			"%v of birthday timestamp=%v", birthdayBlock.Timestamp,
			birthdayBlockDelta, birthday)
	}

	// Finally, our synced to height should now reflect our new birthday
	// block to ensure the wallet doesn't miss any events from this point
	// forward.
	if !reflect.DeepEqual(birthdayStore.syncedTo, *birthdayBlock) {
		t.Fatalf("expected syncedTo and birthday block to match: "+
			"%v vs %v", birthdayStore.syncedTo, birthdayBlock)
	}
}

// TestBirthdaySanityCheckHigherEstimate ensures that we can properly locate a
// better birthday block candidate if our estimate happens to be too far in the
// chain.
func TestBirthdaySanityCheckHigherEstimate(t *testing.T) {
	t.Parallel()

	// We'll start by defining our birthday timestamp to be around the
	// timestamp of the 1337th block.
	genesisTimestamp := chainParams.GenesisBlock.Header.Timestamp
	birthday := genesisTimestamp.Add(1337 * defaultBlockInterval)

	// We'll establish a connection to a mock chain of 5000 blocks.
	chainConn := createMockChainConn(
		chainParams.GenesisBlock, 5000, defaultBlockInterval,
	)

	// Our birthday store will reflect that our birthday block is currently
	// set as the chain tip. This value is too high and should be adjusted
	// by the sanity check.
	bestBlock := chainConn.blocks[chainConn.blockHashes[5000]]
	birthdayStore := &mockBirthdayStore{
		birthday: birthday,
		birthdayBlock: &waddrmgr.BlockStamp{
			Hash:      bestBlock.BlockHash(),
			Height:    5000,
			Timestamp: bestBlock.Header.Timestamp,
		},
		birthdayBlockVerified: false,
		syncedTo: waddrmgr.BlockStamp{
			Height: 5000,
		},
	}

	// We'll perform the sanity check and determine whether we were able to
	// find a better birthday block candidate.
	birthdayBlock, err := birthdaySanityCheck(chainConn, birthdayStore)
	if err != nil {
		t.Fatalf("unable to sanity check birthday block: %v", err)
	}
	if birthday.Sub(birthdayBlock.Timestamp) >= birthdayBlockDelta {
		t.Fatalf("expected birthday block timestamp=%v to be within "+
			"%v of birthday timestamp=%v", birthdayBlock.Timestamp,
			birthdayBlockDelta, birthday)
	}

	// Finally, our synced to height should now reflect our new birthday
	// block to ensure the wallet doesn't miss any events from this point
	// forward.
	if !reflect.DeepEqual(birthdayStore.syncedTo, *birthdayBlock) {
		t.Fatalf("expected syncedTo and birthday block to match: "+
			"%v vs %v", birthdayStore.syncedTo, birthdayBlock)
	}
}
