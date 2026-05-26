// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mock

import (
	"context"
	"maps"
	"sync"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/gcs"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// mempoolAcceptResultReject is the reject reason recorded for a transaction
// that the in-memory MempoolChain has already accepted.
const mempoolAcceptResultReject = "txn-already-in-mempool"

// MempoolChain is a real-style chain.Interface fake that tracks broadcast
// transactions in an in-memory mempool. It is NOT a testify mock: methods
// return deterministic results computed from the in-memory state, so callers
// (typically benchmarks) avoid the per-call overhead of testify expectations.
//
// Methods not relevant to the broadcast path return zero values. Add real
// behavior to a method only when a benchmark or fake-driven test needs it.
type MempoolChain struct {
	mu      sync.RWMutex
	mempool map[chainhash.Hash]*wire.MsgTx
}

// A compile-time assertion to ensure that MempoolChain implements the
// chain.Interface.
var _ chain.Interface = (*MempoolChain)(nil)

// Reset clears all transactions from the in-memory mempool so a benchmark
// loop can establish a clean baseline before measurement.
func (c *MempoolChain) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.mempool = make(map[chainhash.Hash]*wire.MsgTx)
}

// Snapshot returns a shallow copy of the in-memory mempool keyed by tx hash.
func (c *MempoolChain) Snapshot() map[chainhash.Hash]*wire.MsgTx {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[chainhash.Hash]*wire.MsgTx, len(c.mempool))
	maps.Copy(result, c.mempool)

	return result
}

// Start implements the chain.Interface interface. It initializes the
// in-memory mempool so concurrent SendRawTransaction calls observe a
// non-nil map without racing on lazy init.
func (c *MempoolChain) Start(_ context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.mempool == nil {
		c.mempool = make(map[chainhash.Hash]*wire.MsgTx)
	}

	return nil
}

// Stop implements the chain.Interface interface. It clears the in-memory
// mempool so a subsequent Start observes a clean state.
func (c *MempoolChain) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.mempool = nil
}

// WaitForShutdown implements the chain.Interface interface.
func (c *MempoolChain) WaitForShutdown() {}

// GetBestBlock implements the chain.Interface interface. The fake has no
// block state, so it reports height zero with no hash.
func (c *MempoolChain) GetBestBlock() (*chainhash.Hash, int32, error) {
	return nil, 0, nil
}

// GetBlock implements the chain.Interface interface.
func (c *MempoolChain) GetBlock(*chainhash.Hash) (*wire.MsgBlock, error) {
	return nil, nil
}

// GetBlockHash implements the chain.Interface interface.
func (c *MempoolChain) GetBlockHash(int64) (*chainhash.Hash, error) {
	return nil, nil
}

// GetBlockHeader implements the chain.Interface interface.
func (c *MempoolChain) GetBlockHeader(
	*chainhash.Hash) (*wire.BlockHeader, error) {

	return nil, nil
}

// GetBlockHashes implements the chain.Interface interface.
func (c *MempoolChain) GetBlockHashes(int64, int64) ([]chainhash.Hash, error) {
	return nil, nil
}

// GetBlockHeaders implements the chain.Interface interface.
func (c *MempoolChain) GetBlockHeaders(
	[]chainhash.Hash) ([]*wire.BlockHeader, error) {

	return nil, nil
}

// GetCFilters implements the chain.Interface interface.
func (c *MempoolChain) GetCFilters([]chainhash.Hash,
	wire.FilterType) ([]*gcs.Filter, error) {

	return nil, nil
}

// GetBlocks implements the chain.Interface interface.
func (c *MempoolChain) GetBlocks([]chainhash.Hash) ([]*wire.MsgBlock, error) {
	return nil, nil
}

// IsCurrent implements the chain.Interface interface.
func (c *MempoolChain) IsCurrent() bool { return false }

// GetCFilter implements the chain.Interface interface.
func (c *MempoolChain) GetCFilter(*chainhash.Hash,
	wire.FilterType) (*gcs.Filter, error) {

	return nil, nil
}

// FilterBlocks implements the chain.Interface interface.
func (c *MempoolChain) FilterBlocks(*chain.FilterBlocksRequest) (
	*chain.FilterBlocksResponse, error) {

	return nil, nil
}

// BlockStamp implements the chain.Interface interface.
func (c *MempoolChain) BlockStamp() (*waddrmgr.BlockStamp, error) {
	return nil, nil
}

// SendRawTransaction implements the chain.Interface interface. The
// transaction is recorded in the in-memory mempool keyed by its hash; a
// second broadcast of the same tx returns chain.ErrTxAlreadyInMempool, which
// matches the real RPC behavior tx_publisher idempotency checks rely on.
func (c *MempoolChain) SendRawTransaction(tx *wire.MsgTx,
	_ bool) (*chainhash.Hash, error) {

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.mempool == nil {
		c.mempool = make(map[chainhash.Hash]*wire.MsgTx)
	}

	txHash := tx.TxHash()
	if _, exists := c.mempool[txHash]; exists {
		return nil, chain.ErrTxAlreadyInMempool
	}

	c.mempool[txHash] = tx

	return &txHash, nil
}

// Rescan implements the chain.Interface interface.
func (c *MempoolChain) Rescan(*chainhash.Hash, []btcutil.Address,
	map[wire.OutPoint]btcutil.Address) error {

	return nil
}

// NotifyReceived implements the chain.Interface interface.
func (c *MempoolChain) NotifyReceived([]btcutil.Address) error { return nil }

// NotifyBlocks implements the chain.Interface interface.
func (c *MempoolChain) NotifyBlocks() error { return nil }

// Notifications implements the chain.Interface interface.
func (c *MempoolChain) Notifications() <-chan any { return nil }

// BackEnd implements the chain.Interface interface.
func (c *MempoolChain) BackEnd() string { return "mempool-fake" }

// TestMempoolAccept implements the chain.Interface interface. Each input
// transaction reports Allowed=true unless it is already present in the fake
// mempool, in which case it is rejected with mempoolAcceptResultReject so
// MapRPCErr translates the reject into chain.ErrTxAlreadyInMempool.
func (c *MempoolChain) TestMempoolAccept(txns []*wire.MsgTx,
	_ float64) ([]*btcjson.TestMempoolAcceptResult, error) {

	c.mu.RLock()
	defer c.mu.RUnlock()

	results := make([]*btcjson.TestMempoolAcceptResult, len(txns))
	for i := range txns {
		txHash := txns[i].TxHash()
		result := &btcjson.TestMempoolAcceptResult{
			Txid: txHash.String(),
		}
		if _, exists := c.mempool[txHash]; exists {
			result.Allowed = false
			result.RejectReason = mempoolAcceptResultReject
		} else {
			result.Allowed = true
		}

		results[i] = result
	}

	return results, nil
}

// MapRPCErr implements the chain.Interface interface. The fake recognizes
// its own mempool-already-accepted reject reason and translates it to the
// chain package sentinel so callers can use errors.Is.
func (c *MempoolChain) MapRPCErr(err error) error {
	if err == nil {
		return nil
	}

	if err.Error() == mempoolAcceptResultReject {
		return chain.ErrTxAlreadyInMempool
	}

	return err
}
