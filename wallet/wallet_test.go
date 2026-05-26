package wallet

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

var (
	// errBlockNotFound is an error returned when a block is not found.
	errBlockNotFound = errors.New("block not found")

	// errHeaderNotFound is an error returned when a header is not found.
	errHeaderNotFound = errors.New("header not found")
)

var (
	TstSerializedTx, _ = hex.DecodeString("010000000114d9ff358894c486b4ae11c2a8cf7851b1df64c53d2e511278eff17c22fb7373000000008c493046022100995447baec31ee9f6d4ec0e05cb2a44f6b817a99d5f6de167d1c75354a946410022100c9ffc23b64d770b0e01e7ff4d25fbc2f1ca8091053078a247905c39fce3760b601410458b8e267add3c1e374cf40f1de02b59213a82e1d84c2b94096e22e2f09387009c96debe1d0bcb2356ffdcf65d2a83d4b34e72c62eccd8490dbf2110167783b2bffffffff0280969800000000001976a914479ed307831d0ac19ebc5f63de7d5f1a430ddb9d88ac38bfaa00000000001976a914dadf9e3484f28b385ddeaa6c575c0c0d18e9788a88ac00000000")
	TstTx, _           = btcutil.NewTxFromBytes(TstSerializedTx)
	TstTxHash          = TstTx.Hash()

	TstMinedTxBlockHeight        = int32(279143)
	TstMinedSignedTxBlockDetails = &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   *TstTxHash,
			Height: TstMinedTxBlockHeight,
		},
		Time: time.Now(),
	}
)

// TestConfigValidate ensures that the Config.validate method correctly
// identifies missing required parameters.
func TestConfigValidate(t *testing.T) {
	t.Parallel()

	db, cleanup := setupTestDB(t)
	t.Cleanup(cleanup)

	testCases := []struct {
		name        string
		config      Config
		expectedErr string
	}{
		{
			name: "valid config",
			config: Config{
				DB:             db,
				Chain:          &bwmock.Chain{},
				ChainParams:    &chainParams,
				Name:           "test-wallet",
				RecoveryWindow: MinRecoveryWindow,
			},
		},
		{
			name: "invalid RecoveryWindow",
			config: Config{
				DB:             db,
				Chain:          &bwmock.Chain{},
				ChainParams:    &chainParams,
				Name:           "test-wallet",
				RecoveryWindow: MinRecoveryWindow - 1,
			},
			expectedErr: "RecoveryWindow",
		},
		{
			name: "missing DB",
			config: Config{
				Chain:          &bwmock.Chain{},
				ChainParams:    &chainParams,
				Name:           "test-wallet",
				RecoveryWindow: MinRecoveryWindow,
			},
			expectedErr: "DB",
		},
		{
			name: "missing Chain",
			config: Config{
				DB:             db,
				ChainParams:    &chainParams,
				Name:           "test-wallet",
				RecoveryWindow: MinRecoveryWindow,
			},
			expectedErr: "Chain",
		},
		{
			name: "missing ChainParams",
			config: Config{
				DB:             db,
				Chain:          &bwmock.Chain{},
				Name:           "test-wallet",
				RecoveryWindow: MinRecoveryWindow,
			},
			expectedErr: "ChainParams",
		},
		{
			name: "missing Name",
			config: Config{
				DB:             db,
				Chain:          &bwmock.Chain{},
				ChainParams:    &chainParams,
				RecoveryWindow: MinRecoveryWindow,
			},
			expectedErr: "Name",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.config.validate()
			if tc.expectedErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.expectedErr)
			}
		})
	}
}

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
		return nil, 0, fmt.Errorf("%w: height %d",
			errBlockNotFound, c.chainTip)
	}

	return &bestHash, int32(c.chainTip), nil
}

// GetBlockHash returns the hash of the block with the given height.
func (c *mockChainConn) GetBlockHash(height int64) (*chainhash.Hash, error) {
	hash, ok := c.blockHashes[uint32(height)]
	if !ok {
		return nil, fmt.Errorf("%w: height %d", errBlockNotFound, height)
	}

	return &hash, nil
}

// GetBlockHeader returns the header for the block with the given hash.
func (c *mockChainConn) GetBlockHeader(
	hash *chainhash.Hash) (*wire.BlockHeader, error) {

	block, ok := c.blocks[*hash]
	if !ok {
		return nil, fmt.Errorf("%w: hash %v", errHeaderNotFound, hash)
	}

	return &block.Header, nil
}

// TestLocateBirthdayBlock ensures we can properly map a block in the chain to a
// timestamp.
func TestLocateBirthdayBlock(t *testing.T) {
	t.Parallel()

	// We'll use test chains of 30 blocks with a duration between two
	// consecutive blocks being slightly greater than the largest margin
	// allowed by locateBirthdayBlock. Doing so lets us test the method more
	// effectively as there is only one block within the chain that can map
	// to a timestamp (this does not apply to the first and last blocks,
	// which can map to many timestamps beyond either end of chain).
	const (
		numBlocks     = 30
		blockInterval = birthdayBlockDelta + 1
	)

	genesisTimestamp := chainParams.GenesisBlock.Header.Timestamp

	testCases := []struct {
		name           string
		birthday       time.Time
		birthdayHeight int32
	}{
		{
			name:           "left-right-left-left",
			birthday:       genesisTimestamp.Add(8 * blockInterval),
			birthdayHeight: 8,
		},
		{
			name:           "right-right-right-left",
			birthday:       genesisTimestamp.Add(27 * blockInterval),
			birthdayHeight: 27,
		},
		{
			name:           "before start height",
			birthday:       genesisTimestamp.Add(-blockInterval),
			birthdayHeight: 0,
		},
		{
			name:           "start height",
			birthday:       genesisTimestamp,
			birthdayHeight: 0,
		},
		{
			name:           "end height",
			birthday:       genesisTimestamp.Add(numBlocks * blockInterval),
			birthdayHeight: numBlocks - 1,
		},
		{
			name:           "after end height",
			birthday:       genesisTimestamp.Add(2 * numBlocks * blockInterval),
			birthdayHeight: numBlocks - 1,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		success := t.Run(testCase.name, func(t *testing.T) {
			chainConn := createMockChainConn(
				chainParams.GenesisBlock, numBlocks, blockInterval,
			)
			birthdayBlock, err := locateBirthdayBlock(
				chainConn, testCase.birthday,
			)
			if err != nil {
				t.Fatalf("unable to locate birthday block: %v",
					err)
			}
			if birthdayBlock.Height != testCase.birthdayHeight {
				t.Fatalf("expected birthday block with height "+
					"%d, got %d", testCase.birthdayHeight,
					birthdayBlock.Height)
			}
		})
		if !success {
			break
		}
	}
}
