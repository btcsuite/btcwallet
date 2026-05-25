package bwtest

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/bwtest/wait"
	"github.com/stretchr/testify/require"
)

var (
	// ErrMempoolTxNotFound is returned when a transaction is not found in the
	// miner's mempool.
	ErrMempoolTxNotFound = errors.New("transaction not found in mempool")

	// ErrMempoolTxFound is returned when a transaction is found in the miner's
	// mempool.
	ErrMempoolTxFound = errors.New("transaction found in mempool")

	// ErrMempoolNumTxnsMismatch is returned when the number of transactions in
	// the mempool doesn't match the expected value.
	ErrMempoolNumTxnsMismatch = errors.New("mempool txn count mismatch")

	// ErrBlockMissingTx is returned when a transaction is not found in a block.
	ErrBlockMissingTx = errors.New("transaction not found in block")

	// ErrBlockUnexpectedTxns is returned when a block contains unexpected
	// transactions.
	ErrBlockUnexpectedTxns = errors.New("block contains unexpected txns")

	// ErrOutpointNotFound is returned when an outpoint is not found in the
	// miner's mempool.
	ErrOutpointNotFound = errors.New("outpoint not found in mempool")

	// ErrNilBlock is returned when a nil block is provided.
	ErrNilBlock = errors.New("nil block")

	// ErrMinerNotSynced is returned when a temporary miner is not synced to the
	// harness miner.
	ErrMinerNotSynced = errors.New("miner not synced")
)

const (
	// coinbaseAndOneTxn is the number of transactions expected in a block that
	// contains only a coinbase transaction and a single non-coinbase
	// transaction.
	coinbaseAndOneTxn = 2
)

// GenerateBlocks generates the specified number of blocks.
func (h *HarnessTest) GenerateBlocks(num uint32) []*chainhash.Hash {
	h.Helper()

	hashes, err := h.miner.Client.Generate(num)
	require.NoError(h, err, "unable to generate blocks")

	return hashes
}

// AssertTxInMempool asserts a transaction can be found in the miner's mempool.
func (h *HarnessTest) AssertTxInMempool(txid chainhash.Hash) *wire.MsgTx {
	h.Helper()

	var foundTx *wire.MsgTx

	err := wait.NoError(func() error {
		txids, err := h.getRawMempool()
		if err != nil {
			return fmt.Errorf("get raw mempool: %w", err)
		}

		for _, memTxid := range txids {
			if memTxid == txid {
				tx, err := h.miner.Client.GetRawTransaction(&txid)
				if err != nil {
					return fmt.Errorf("get raw transaction: %w", err)
				}

				foundTx = tx.MsgTx()

				return nil
			}
		}

		return fmt.Errorf("%w: txid=%s", ErrMempoolTxNotFound, txid)
	}, defaultTestTimeout)
	require.NoError(h, err, "timeout waiting for txn in mempool")
	require.NotNil(h, foundTx, "found tx is nil")

	return foundTx
}

// AssertTxNotInMempool asserts a transaction cannot be found in the miner's
// mempool.
func (h *HarnessTest) AssertTxNotInMempool(txid chainhash.Hash) {
	h.Helper()

	err := wait.NoError(func() error {
		txids, err := h.getRawMempool()
		if err != nil {
			return fmt.Errorf("get raw mempool: %w", err)
		}

		if slices.Contains(txids, txid) {
			return fmt.Errorf("%w: txid=%s", ErrMempoolTxFound,
				txid)
		}

		return nil
	}, defaultTestTimeout)
	require.NoError(h, err, "timeout waiting for txn to leave mempool")
}

// AssertNumTxnsInMempool polls until finding the expected number of
// transactions in the miner's mempool.
func (h *HarnessTest) AssertNumTxnsInMempool(n int) []chainhash.Hash {
	h.Helper()

	if n < 0 {
		h.Fatalf("invalid mempool size: %d", n)
	}

	var txids []chainhash.Hash

	err := wait.NoError(func() error {
		mempoolTxids, err := h.getRawMempool()
		if err != nil {
			return fmt.Errorf("get raw mempool: %w", err)
		}

		if len(mempoolTxids) != n {
			return fmt.Errorf("%w: want=%d got=%d", ErrMempoolNumTxnsMismatch,
				n, len(mempoolTxids))
		}

		txids = mempoolTxids

		return nil
	}, defaultTestTimeout)
	require.NoError(h, err, "timeout waiting for mempool size")

	return txids
}

// AssertOutpointInMempool asserts an outpoint is spent by a transaction in the
// miner's mempool.
func (h *HarnessTest) AssertOutpointInMempool(op wire.OutPoint) *wire.MsgTx {
	h.Helper()

	var foundTx *wire.MsgTx

	err := wait.NoError(func() error {
		txids, err := h.getRawMempool()
		if err != nil {
			return fmt.Errorf("get raw mempool: %w", err)
		}

		for _, txid := range txids {
			tx, err := h.miner.Client.GetRawTransaction(&txid)
			if err != nil {
				return fmt.Errorf("get raw transaction: %w", err)
			}

			msgTx := tx.MsgTx()
			for _, txIn := range msgTx.TxIn {
				if txIn.PreviousOutPoint == op {
					foundTx = msgTx
					return nil
				}
			}
		}

		return fmt.Errorf("%w: outpoint=%v", ErrOutpointNotFound, op)
	}, defaultTestTimeout)
	require.NoError(h, err, "timeout waiting for outpoint in mempool")
	require.NotNil(h, foundTx, "found tx is nil")

	return foundTx
}

// AssertTxInBlock asserts a transaction can be found in a block.
func (h *HarnessTest) AssertTxInBlock(block *wire.MsgBlock,
	txid chainhash.Hash) {

	h.Helper()

	if block == nil {
		h.Fatalf("nil block")
	}

	for _, tx := range block.Transactions {
		if tx == nil {
			continue
		}

		if tx.TxHash() == txid {
			return
		}
	}

	h.Fatalf("%v: block=%v", fmt.Errorf("%w: txid=%s", ErrBlockMissingTx,
		txid), block.BlockHash())
}

// MineBlocks mines blocks and asserts no transactions are found in the mined
// blocks.
//
// After each block is mined, all registered wallets are required to be synced.
func (h *HarnessTest) MineBlocks(num int) {
	h.Helper()

	err := h.MineBlocksNoTxns(num)
	if err != nil {
		require.Fail(h, "MineBlocks", err.Error())
	}
}

// MineBlocksNoTxns mines blocks and returns an error if any mined block
// contains non-coinbase transactions.
func (h *HarnessTest) MineBlocksNoTxns(num int) error {
	h.Helper()

	blocks := h.generateBlocks(num)
	for _, b := range blocks {
		err := h.blockHasNoTxns(b)
		if err != nil {
			return err
		}
	}

	return nil
}

// MineEmptyBlocks mines blocks and asserts the mempool remains empty.
//
// This differs from MineBlocks in that it explicitly requires the miner's
// mempool to have no transactions before mining begins.
func (h *HarnessTest) MineEmptyBlocks(num int) []*wire.MsgBlock {
	h.Helper()

	// Require the mempool is empty before mining, otherwise these blocks might
	// confirm pending transactions.
	h.AssertNumTxnsInMempool(0)

	blocks := h.generateBlocks(num)
	for _, b := range blocks {
		err := h.blockHasNoTxns(b)
		if err != nil {
			require.Fail(h, "MineEmptyBlocks", err.Error())
		}
	}

	return blocks
}

// MineBlocksAndAssertNumTxns mines blocks and asserts that numTxns
// transactions are included in the first mined block.
func (h *HarnessTest) MineBlocksAndAssertNumTxns(num uint32,
	numTxns int) []*wire.MsgBlock {

	h.Helper()

	if num == 0 {
		h.Fatalf("invalid block count: %d", num)
	}

	txids := h.AssertNumTxnsInMempool(numTxns)
	blocks := h.generateBlocks(int(num))

	for _, txid := range txids {
		h.AssertTxInBlock(blocks[0], txid)
		h.AssertTxNotInMempool(txid)
	}

	return blocks
}

// MineBlockWithTx mines a single block and asserts it contains the given
// transaction.
func (h *HarnessTest) MineBlockWithTx(tx *wire.MsgTx) *wire.MsgBlock {
	h.Helper()

	if tx == nil {
		h.Fatalf("nil tx")
	}

	txid := tx.TxHash()
	h.AssertTxInMempool(txid)

	// Ensure the mempool only contains our transaction so the mined block
	// contains only the coinbase and this transaction.
	mempoolTxids := h.AssertNumTxnsInMempool(1)
	require.Equal(h, txid, mempoolTxids[0], "unexpected txn in mempool")

	blocks := h.MineBlocksAndAssertNumTxns(1, 1)
	require.Len(h, blocks, 1, "expected exactly 1 block")

	block := blocks[0]
	require.NotNil(h, block, "mined block is nil")
	require.Len(h, block.Transactions, coinbaseAndOneTxn,
		"expected coinbase and one txn")
	require.Equal(h, txid, block.Transactions[1].TxHash(),
		"unexpected txn in mined block")

	return block
}

// SpawnTempMiner creates a temporary miner that is synced with the current
// miner.
//
// This is useful for reorg tests where an alternative chain needs to be mined
// in isolation.
func (h *HarnessTest) SpawnTempMiner() *HarnessTest {
	h.Helper()

	minerLogDir := createUniqueLogSubDir(h.T, h.logDir, "miner-temp")
	tempMiner := newMiner(h.T, minerLogDir)
	tempMiner.SetUpNoChain()

	th := &HarnessTest{T: h.T, logDir: h.logDir, miner: tempMiner}
	h.Cleanup(tempMiner.Stop)

	// Connect the miners and wait for the temp miner to sync.
	h.ConnectToMiner(th)

	_, mainHeight := h.GetBestBlock()
	err := wait.NoError(func() error {
		_, tempHeight, err := tempMiner.Client.GetBestBlock()
		if err != nil {
			return fmt.Errorf("get best block: %w", err)
		}

		if tempHeight != mainHeight {
			return fmt.Errorf("%w: main=%d temp=%d", ErrMinerNotSynced,
				mainHeight, tempHeight)
		}

		return nil
	}, defaultTestTimeout)
	require.NoError(h, err, "timeout waiting for temp miner to sync")

	// Disconnect the temp miner so it can mine an alternative chain.
	h.DisconnectFromMiner(th)

	return th
}

// ConnectToMiner connects the harness miner to tempMiner.
func (h *HarnessTest) ConnectToMiner(tempMiner *HarnessTest) {
	h.Helper()

	if tempMiner == nil {
		h.Fatalf("nil temp miner")
	}

	if tempMiner.miner == nil {
		h.Fatalf("nil temp miner harness")
	}

	err := h.miner.Client.AddNode(tempMiner.miner.P2PAddress(), "add")
	require.NoError(h, err, "failed to connect to temp miner")

	err = tempMiner.miner.Client.AddNode(h.miner.P2PAddress(), "add")
	require.NoError(h, err, "failed to connect temp miner")
}

// DisconnectFromMiner disconnects the harness miner from tempMiner.
func (h *HarnessTest) DisconnectFromMiner(tempMiner *HarnessTest) {
	h.Helper()

	if tempMiner == nil {
		h.Fatalf("nil temp miner")
	}

	if tempMiner.miner == nil {
		h.Fatalf("nil temp miner harness")
	}

	err := h.miner.Client.AddNode(tempMiner.miner.P2PAddress(), "remove")
	require.NoError(h, err, "failed to disconnect from temp miner")

	err = tempMiner.miner.Client.AddNode(h.miner.P2PAddress(), "remove")
	require.NoError(h, err, "failed to disconnect temp miner")
}

// generateBlocks mines num blocks and returns the full blocks.
//
// After each block is mined, all registered wallets are required to be synced.
func (h *HarnessTest) generateBlocks(num int) []*wire.MsgBlock {
	h.Helper()

	// Mining 0 blocks is a no-op.
	if num == 0 {
		return nil
	}

	if num < 0 {
		h.Fatalf("invalid block count: %d", num)
	}

	if num > int(^uint32(0)) {
		h.Fatalf("too many blocks requested: %d", num)
	}

	blocks := make([]*wire.MsgBlock, 0, num)
	for range num {
		hashes := h.GenerateBlocks(1)
		require.Len(h, hashes, 1, "expected 1 block hash")

		block, err := h.miner.Client.GetBlock(hashes[0])
		require.NoError(h, err, "failed to get mined block")

		blocks = append(blocks, block)

		// Ensure all wallets we created in this test have caught up.
		for _, w := range h.ActiveWallets() {
			h.AssertWalletSynced(w)
		}
	}

	return blocks
}

// getRawMempool returns the miner's mempool transaction ids.
func (h *HarnessTest) getRawMempool() ([]chainhash.Hash, error) {
	h.Helper()

	txids, err := h.miner.Client.GetRawMempool()
	if err != nil {
		return nil, fmt.Errorf("get raw mempool: %w", err)
	}

	result := make([]chainhash.Hash, 0, len(txids))
	for _, txid := range txids {
		if txid == nil {
			continue
		}

		result = append(result, *txid)
	}

	return result, nil
}

// blockHasNoTxns returns an error if block contains non-coinbase transactions.
func (h *HarnessTest) blockHasNoTxns(block *wire.MsgBlock) error {
	h.Helper()

	if block == nil {
		return ErrNilBlock
	}

	if len(block.Transactions) <= 1 {
		return nil
	}

	var desc strings.Builder
	fmt.Fprintf(&desc, "block %v has %d txns:\n",
		block.BlockHash(), len(block.Transactions)-1)

	for _, tx := range block.Transactions[1:] {
		if tx == nil {
			continue
		}

		fmt.Fprintf(&desc, "%v\n", tx.TxHash())
	}

	desc.WriteString(
		"Consider using `MineBlocksAndAssertNumTxns` if you expect " +
			"txns, or `MineEmptyBlocks` if you want to keep txns " +
			"unconfirmed.",
	)

	return fmt.Errorf("%w: %s", ErrBlockUnexpectedTxns, desc.String())
}

// SendOutput sends funds from the miner.
func (h *HarnessTest) SendOutput(output *wire.TxOut,
	feeRate btcutil.Amount) *chainhash.Hash {

	h.Helper()

	txid, err := h.miner.SendOutputs([]*wire.TxOut{output}, feeRate)
	require.NoError(h, err, "failed to send output")

	return txid
}

// GetBestBlock returns the hash and height of the best block.
func (h *HarnessTest) GetBestBlock() (*chainhash.Hash, int32) {
	h.Helper()

	hash, height, err := h.miner.Client.GetBestBlock()
	require.NoError(h, err, "failed to get best block")

	return hash, height
}
