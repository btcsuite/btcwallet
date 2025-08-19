package chain

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

var (
	// TrickleInterval is the interval at which the miner should trickle
	// transactions to its peers. We'll set it small to ensure the miner
	// propagates transactions quickly in the tests.
	TrickleInterval = 10 * time.Millisecond

	NetParams = &chaincfg.RegressionNetParams
)

// dummyHash is a helper function which creates 32 bytes valid hash as per the
// given hex value.
func dummyHash(value byte) *chainhash.Hash {
	var hash chainhash.Hash
	copy(hash[:], bytes.Repeat([]byte{value}, 32))
	return &hash
}

// NewMiner spawns testing harness backed by a bitcoind node that can serve as a
// miner.
func NewMiner(t *testing.T, extraArgs []string, createChain bool,
	spendableOutputs uint32) (*rpctest.Harness, func()) {

	t.Helper()

	// Add the trickle interval argument to the extra args.
	trickle := fmt.Sprintf("--trickleinterval=%v", TrickleInterval)
	extraArgs = append(extraArgs, trickle)

	node, err := rpctest.New(NetParams, nil, extraArgs, "")
	require.NoError(t, err, "unable to create backend node")
	if err := node.SetUp(createChain, spendableOutputs); err != nil {
		node.TearDown()
		t.Fatalf("unable to set up backend node: %v", err)
	}

	return node, func() { node.TearDown() }
}

// syncBitcoindWithMiner is a helper method that attempts to wait until the
// bitcoind is synced (in terms of the chain) with the miner.
func syncBitcoindWithMiner(t *testing.T, bitcoindClient *BitcoindClient,
	miner *rpctest.Harness) uint32 {

	t.Helper()

	_, minerHeight, err := miner.Client.GetBestBlock()
	require.NoError(t, err, "unable to retrieve miner's current height")

	timeout := time.After(10 * time.Second)
	for {
		_, bitcoindHeight, err := bitcoindClient.GetBestBlock()
		require.NoError(t, err, "unable to retrieve bitcoind's current "+
			"height")

		if bitcoindHeight == minerHeight {
			return uint32(bitcoindHeight)
		}

		select {
		case <-time.After(100 * time.Millisecond):
		case <-timeout:
			t.Fatalf("timed out waiting to sync bitcoind")
		}
	}
}

// TestBitcoindGetBlocksBatch ensures that we correctly retrieve
// rawBlocks details using updated batchClient.
func TestBitcoindGetBlocksBatch(t *testing.T) {
	testBitcoindGetBlocksBatch(t, true)
	testBitcoindGetBlocksBatch(t, false)
}

func testBitcoindGetBlocksBatch(t *testing.T, rpcpolling bool) {
	miner, tearDown := NewMiner(
		t, []string{"--txindex"}, true, 25,
	)
	defer tearDown()

	bitcoindClient := setupBitcoind(t, miner.P2PAddress(), rpcpolling)

	// Blocks shouldn't be retrieved from bitcoind when passing unknown
	// block hashes.
	blockHashes := []*chainhash.Hash{
		dummyHash(0x10),
		dummyHash(0x12),
		dummyHash(0x14),
	}
	broadcastHeight := syncBitcoindWithMiner(t, bitcoindClient, miner)
	_, err := bitcoindClient.GetBlocksBatch(blockHashes)
	require.EqualError(t, err, "-5: Block not found")

	// Here, we'll generate multiple valid testblocks and retrieve it
	// linearly with GetBlock() (store the result for each GetBlock() in a
	// slice) further also try to retrieve blocks in batch with GetBlocksBatch().
	// At last will compare the results from both which should be equal.
	if _, err := miner.Client.Generate(2*15 + 7); err != nil {
		t.Fatalf("unable to generate blocks: %v", err)
	}
	currentHeight := syncBitcoindWithMiner(t, bitcoindClient, miner)

	blockHashes = make([]*chainhash.Hash, 0, currentHeight-broadcastHeight)
	msgBlocksStandard := make([]*wire.MsgBlock, 0, currentHeight-broadcastHeight)
	for i := currentHeight; i >= broadcastHeight; i-- {
		blockHash, err := bitcoindClient.GetBlockHash(int64(i))
		require.NoError(t, err, "unable to retrieve blockhash")
		blockHashes = append(blockHashes, blockHash)

		msgBlock, err := bitcoindClient.GetBlock(blockHash)
		require.NoError(t, err)
		msgBlocksStandard = append(msgBlocksStandard, msgBlock)
	}

	msgBlocksBatchClient, err := bitcoindClient.GetBlocksBatch(blockHashes)
	require.NoError(t, err)
	require.Equal(
		t, msgBlocksStandard, msgBlocksBatchClient, "blocks result mismatch",
	)
}

// TestBitcoindRescanBlocksBatched ensures that we correctly retrieve the required
// details for the watched txn.
func TestBitcoindRescanBlocksBatched(t *testing.T) {
	testBitcoindRescanBlocksBatched(t, true)
	testBitcoindRescanBlocksBatched(t, false)
}

func testBitcoindRescanBlocksBatched(t *testing.T, rpcpolling bool) {
	miner, tearDown := NewMiner(
		t, []string{"--txindex"}, true, 25,
	)
	defer tearDown()

	bitcoindClient := setupBitcoind(t, miner.P2PAddress(), rpcpolling)

	// Here, we'll generate multiple valid testblocks. Moving forward, using
	// bitcoindClient assign a random txn for watchedTxs. Now, we hit
	// RescanBlocksBatched (leveraging updated BatchAPI). Further using its
	// result will try to retrieve blockHash and compare it with actual txn
	// blockHash which should be equal.
	broadcastHeight := syncBitcoindWithMiner(t, bitcoindClient, miner)
	if _, err := miner.Client.Generate(50); err != nil {
		t.Fatalf("unable to generate blocks: %v", err)
	}
	currentHeight := syncBitcoindWithMiner(t, bitcoindClient, miner)
	blockHashes := make([]chainhash.Hash, 0, uint32(currentHeight)-broadcastHeight)

	for i := uint32(currentHeight); i >= broadcastHeight; i-- {
		blockHash, err := bitcoindClient.GetBlockHash(int64(i))
		require.NoError(t, err, "unable to retrieve blockhash")
		blockHashes = append(blockHashes, *blockHash)
	}

	block, err := bitcoindClient.GetBlock(&blockHashes[25])
	require.NoError(t, err, "unable to fetch block")

	txn := block.Transactions[0]
	bitcoindClient.watchedTxs[txn.TxHash()] = struct{}{}

	rescanBlocksBatchAPI, err := bitcoindClient.RescanBlocksBatched(blockHashes)
	require.NoError(t, err)
	require.Equal(t, blockHashes[25].String(), rescanBlocksBatchAPI[0].Hash)

	// We can also compare the results with former implemetation "RescanBlocks"
	// which should be equal.
	rescanBlocksSync, err := bitcoindClient.RescanBlocks(blockHashes)
	require.NoError(t, err)
	require.Equal(t, rescanBlocksSync, rescanBlocksBatchAPI)
}

// TestBitcoindFilterBlocksBatched ensures that we correctly retrieve the required
// FilterBlocksResponse for the requested watchPoints.
func TestBitcoindFilterBlocksBatched(t *testing.T) {
	testBitcoindFilterBlocksBatched(t, true)
	testBitcoindFilterBlocksBatched(t, false)
}

func testBitcoindFilterBlocksBatched(t *testing.T, rpcpolling bool) {
	miner, tearDown := NewMiner(
		t, []string{"--txindex"}, true, 25,
	)
	defer tearDown()

	bitcoindClient := setupBitcoind(t, miner.P2PAddress(), rpcpolling)

	// Now, we'll create a test transaction, confirm it, and attempt to
	// retrieve its relevant txn details. The transaction must be in the
	// chain and not contain any unspent outputs. To ensure this, we'll
	// create a transaction with only one output, which we will manually
	// spend.
	outpoint, output, privKey := CreateSpendableOutput(t, miner)
	heightHint := syncBitcoindWithMiner(t, bitcoindClient, miner)
	spendTx := CreateSpendTx(t, outpoint, output, privKey)
	spendTxHash, err := miner.Client.SendRawTransaction(spendTx, true)
	require.NoError(t, err, "unable to broadcast tx")
	err = WaitForMempoolTx(miner, spendTxHash)
	require.NoError(t, err, "tx not relayed to miner")
	_, err = miner.Client.Generate(50)
	require.NoError(t, err, "unable to generate blocks")
	currentHeight := syncBitcoindWithMiner(t, bitcoindClient, miner)

	blockStore := make([]wtxmgr.BlockMeta, 0, currentHeight-heightHint)
	for i := currentHeight; i >= heightHint; i-- {
		blockHash, err := bitcoindClient.GetBlockHash(int64(i))
		require.NoError(t, err, "unable to retrieve blockhash")
		block, err := bitcoindClient.GetBlock(blockHash)
		require.NoError(t, err, "unable to get raw block")

		blockWtxmgr := wtxmgr.Block{
			Hash:   *blockHash,
			Height: int32(i),
		}
		temp := wtxmgr.BlockMeta{
			Block: blockWtxmgr,
			Time:  block.Header.Timestamp,
		}
		blockStore = append(blockStore, temp)
	}

	watchedOutPoint := make(map[wire.OutPoint]btcutil.Address)
	watchedOutPoint[*outpoint] = &btcutil.AddressWitnessPubKeyHash{}

	// Construct a filter request, watching only for the outpoints above,
	// and hit FilterBlocksBatched with the request created.
	req := FilterBlocksRequest{
		Blocks:           blockStore,
		WatchedOutPoints: watchedOutPoint,
	}

	// Now, we hit FilterBlocksBatched (leveraging updated BatchAPI). Further
	// using its result will reteieve the height, blockHash, txnHash and
	// compare it with actual spendTxn height, blockHash and spendTxHash.
	filterBlockResponseBatchAPI, err := bitcoindClient.FilterBlocksBatched(&req)
	require.NoError(t, err)
	require.Equal(t, heightHint+1, uint32(filterBlockResponseBatchAPI.BlockMeta.Height))
	actualBlockHash, err := bitcoindClient.GetBlockHash(int64(heightHint + 1))
	require.NoError(t, err, "unable to get block hash")
	require.Equal(t, actualBlockHash.String(), filterBlockResponseBatchAPI.BlockMeta.Hash.String())
	txnExist := false
	for _, txn := range filterBlockResponseBatchAPI.RelevantTxns {
		if txn.TxHash().String() == spendTx.TxHash().String() {
			txnExist = true
		}
	}
	require.Equal(t, txnExist, true, "txn mismatch")

	// We can also compare the results with former implemetation "FilterBlocks"
	// which should be equal.
	filterBlockResponseSync, err := bitcoindClient.FilterBlocks(&req)
	require.NoError(t, err)
	require.Equal(t, filterBlockResponseSync, filterBlockResponseBatchAPI)
}
