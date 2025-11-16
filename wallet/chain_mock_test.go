package wallet

import (
	"errors"
	"maps"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

var (
	// errTxnAlreadyInMempool is returned when a transaction already exists
	// in the mempool.
	errTxnAlreadyInMempool = "txn-already-in-mempool"

	// ErrNotImplemented is returned when a mock method is not implemented.
	ErrNotImplemented = errors.New("not implemented")
)

type mockChainClient struct {
	getBestBlockHeight int32
	getBlockHashFunc   func() (*chainhash.Hash, error)
	getBlockHeader     *wire.BlockHeader

	// mempool tracks transactions that have been broadcast to simulate
	// mempool behavior for benchmarks.
	mempool map[chainhash.Hash]*wire.MsgTx

	// mu protects concurrent reads and writes to mempool.
	mu sync.RWMutex
}

var _ chain.Interface = (*mockChainClient)(nil)

func (m *mockChainClient) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.mempool == nil {
		m.mempool = make(map[chainhash.Hash]*wire.MsgTx)
	}

	return nil
}

func (m *mockChainClient) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.mempool = nil
}

func (m *mockChainClient) WaitForShutdown() {}

// ResetMempool clears all transactions from the mock mempool.
func (m *mockChainClient) ResetMempool() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.mempool = make(map[chainhash.Hash]*wire.MsgTx)
}

func (m *mockChainClient) GetBestBlock() (*chainhash.Hash, int32, error) {
	return nil, m.getBestBlockHeight, nil
}

func (m *mockChainClient) GetBlock(*chainhash.Hash) (*wire.MsgBlock, error) {
	return nil, ErrNotImplemented
}

func (m *mockChainClient) GetBlockHash(int64) (*chainhash.Hash, error) {
	if m.getBlockHashFunc != nil {
		return m.getBlockHashFunc()
	}

	return nil, ErrNotImplemented
}

func (m *mockChainClient) GetBlockHeader(*chainhash.Hash) (*wire.BlockHeader,
	error) {

	return m.getBlockHeader, nil
}

func (m *mockChainClient) GetMempool() (map[chainhash.Hash]*wire.MsgTx, error) {
	// Acquire read lock non-exclusively. It allows concurrent readers and
	// blocks writers.
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return a shallow copy of the map to avoid TOCTOU
	// (time-of-check-to-time-of-use) races. Returning m.mempool directly
	// would share the map reference - after RUnlock(), concurrent writes
	// could modify the map structure during caller's iteration causing:
	// "fatal error: concurrent map iteration and map write".
	// Note: This is a shallow copy - the *wire.MsgTx pointers are shared.
	// We assume transactions are not mutated after creation.
	result := make(map[chainhash.Hash]*wire.MsgTx, len(m.mempool))
	maps.Copy(result, m.mempool)

	return result, nil
}

func (m *mockChainClient) IsCurrent() bool {
	return false
}

func (m *mockChainClient) FilterBlocks(*chain.FilterBlocksRequest) (
	*chain.FilterBlocksResponse, error) {

	return nil, ErrNotImplemented
}

func (m *mockChainClient) BlockStamp() (*waddrmgr.BlockStamp, error) {
	return &waddrmgr.BlockStamp{
		Height:    500000,
		Hash:      chainhash.Hash{},
		Timestamp: time.Unix(1234, 0),
	}, nil
}

func (m *mockChainClient) SendRawTransaction(tx *wire.MsgTx,
	allowHighFees bool) (*chainhash.Hash, error) {

	// Acquire write lock exclusively. It blocks all readers and writers.
	m.mu.Lock()
	defer m.mu.Unlock()

	txHash := tx.TxHash()

	// Reject duplicate transactions to isolate the external behavior of
	// real chain backends. This is important for reliable testing and
	// benchmarking handling in broadcast APIs.
	if _, exists := m.mempool[txHash]; exists {
		return nil, chain.ErrTxAlreadyInMempool
	}

	m.mempool[txHash] = tx

	return &txHash, nil
}

func (m *mockChainClient) Rescan(*chainhash.Hash, []btcutil.Address,
	map[wire.OutPoint]btcutil.Address) error {

	return nil
}

func (m *mockChainClient) NotifyReceived([]btcutil.Address) error {
	return nil
}

func (m *mockChainClient) NotifyBlocks() error {
	return nil
}

func (m *mockChainClient) Notifications() <-chan interface{} {
	return nil
}

func (m *mockChainClient) BackEnd() string {
	return "mock"
}

// TestMempoolAcceptCmd returns result of mempool acceptance tests indicating
// if raw transaction(s) would be accepted by mempool.
//
// NOTE: This is part of the chain.Interface interface.
func (m *mockChainClient) TestMempoolAccept(txns []*wire.MsgTx,
	maxFeeRate float64) ([]*btcjson.TestMempoolAcceptResult, error) {

	// Acquire read lock non-exclusively. It allows concurrent readers and
	// blocks writers.
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return acceptance result for each transaction.
	results := make([]*btcjson.TestMempoolAcceptResult, len(txns))
	for i := range txns {
		txHash := txns[i].TxHash()
		result := &btcjson.TestMempoolAcceptResult{
			Txid: txHash.String(),
		}

		// Check if transaction already exists in mempool.
		if _, exists := m.mempool[txHash]; exists {
			result.Allowed = false
			result.RejectReason = errTxnAlreadyInMempool
		} else {
			result.Allowed = true
		}

		results[i] = result
	}

	return results, nil
}

func (m *mockChainClient) MapRPCErr(err error) error {
	if err == nil {
		return nil
	}

	if err.Error() == errTxnAlreadyInMempool {
		return chain.ErrTxAlreadyInMempool
	}

	return err
}
