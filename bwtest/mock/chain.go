// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mock

import (
	"context"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/gcs"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/mock"
)

// Chain is a testify mock implementation of chain.Interface. Every
// method that runs through wallet code paths under test must have an
// expectation configured via .On("Method", args...).Return(...) — calls
// without a matching expectation panic, by design. Use .Maybe() for
// methods whose specific behavior is not under test.
type Chain struct {
	mock.Mock
}

// A compile-time assertion to ensure that Chain implements the
// chain.Interface.
var _ chain.Interface = (*Chain)(nil)

// Start implements the chain.Interface interface.
func (m *Chain) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// Stop implements the chain.Interface interface.
func (m *Chain) Stop() {
	m.Called()
}

// WaitForShutdown implements the chain.Interface interface.
func (m *Chain) WaitForShutdown() {
	m.Called()
}

// GetBestBlock implements the chain.Interface interface.
func (m *Chain) GetBestBlock() (*chainhash.Hash, int32, error) {
	args := m.Called()
	hash, _ := args.Get(0).(*chainhash.Hash)

	return hash, args.Get(1).(int32), args.Error(2)
}

// GetBlock implements the chain.Interface interface.
func (m *Chain) GetBlock(hash *chainhash.Hash) (*wire.MsgBlock, error) {
	args := m.Called(hash)
	block, _ := args.Get(0).(*wire.MsgBlock)

	return block, args.Error(1)
}

// GetBlockHash implements the chain.Interface interface.
func (m *Chain) GetBlockHash(height int64) (*chainhash.Hash, error) {
	args := m.Called(height)
	hash, _ := args.Get(0).(*chainhash.Hash)

	return hash, args.Error(1)
}

// GetBlockHeader implements the chain.Interface interface.
func (m *Chain) GetBlockHeader(
	hash *chainhash.Hash) (*wire.BlockHeader, error) {

	args := m.Called(hash)
	header, _ := args.Get(0).(*wire.BlockHeader)

	return header, args.Error(1)
}

// GetBlockHashes implements the chain.Interface interface.
func (m *Chain) GetBlockHashes(start, end int64) ([]chainhash.Hash, error) {
	args := m.Called(start, end)
	return args.Get(0).([]chainhash.Hash), args.Error(1)
}

// GetBlockHeaders implements the chain.Interface interface.
func (m *Chain) GetBlockHeaders(
	hashes []chainhash.Hash) ([]*wire.BlockHeader, error) {

	args := m.Called(hashes)
	return args.Get(0).([]*wire.BlockHeader), args.Error(1)
}

// GetCFilters implements the chain.Interface interface.
func (m *Chain) GetCFilters(hashes []chainhash.Hash,
	filterType wire.FilterType) ([]*gcs.Filter, error) {

	args := m.Called(hashes, filterType)
	return args.Get(0).([]*gcs.Filter), args.Error(1)
}

// GetBlocks implements the chain.Interface interface.
func (m *Chain) GetBlocks(
	hashes []chainhash.Hash) ([]*wire.MsgBlock, error) {

	args := m.Called(hashes)
	return args.Get(0).([]*wire.MsgBlock), args.Error(1)
}

// IsCurrent implements the chain.Interface interface.
func (m *Chain) IsCurrent() bool {
	args := m.Called()
	return args.Bool(0)
}

// GetCFilter implements the chain.Interface interface.
func (m *Chain) GetCFilter(hash *chainhash.Hash,
	filterType wire.FilterType) (*gcs.Filter, error) {

	args := m.Called(hash, filterType)
	return args.Get(0).(*gcs.Filter), args.Error(1)
}

// FilterBlocks implements the chain.Interface interface.
func (m *Chain) FilterBlocks(req *chain.FilterBlocksRequest) (
	*chain.FilterBlocksResponse, error) {

	args := m.Called(req)
	return args.Get(0).(*chain.FilterBlocksResponse), args.Error(1)
}

// BlockStamp implements the chain.Interface interface.
func (m *Chain) BlockStamp() (*waddrmgr.BlockStamp, error) {
	args := m.Called()
	return args.Get(0).(*waddrmgr.BlockStamp), args.Error(1)
}

// SendRawTransaction implements the chain.Interface interface.
func (m *Chain) SendRawTransaction(tx *wire.MsgTx,
	allowHighFees bool) (*chainhash.Hash, error) {

	args := m.Called(tx, allowHighFees)
	hash, _ := args.Get(0).(*chainhash.Hash)

	return hash, args.Error(1)
}

// Rescan implements the chain.Interface interface.
func (m *Chain) Rescan(hash *chainhash.Hash, addrs []btcutil.Address,
	outpoints map[wire.OutPoint]btcutil.Address) error {

	args := m.Called(hash, addrs, outpoints)
	return args.Error(0)
}

// NotifyReceived implements the chain.Interface interface.
func (m *Chain) NotifyReceived(addrs []btcutil.Address) error {
	args := m.Called(addrs)
	return args.Error(0)
}

// NotifyBlocks implements the chain.Interface interface.
func (m *Chain) NotifyBlocks() error {
	args := m.Called()
	return args.Error(0)
}

// Notifications implements the chain.Interface interface.
func (m *Chain) Notifications() <-chan any {
	args := m.Called()
	return args.Get(0).(<-chan any)
}

// BackEnd implements the chain.Interface interface.
func (m *Chain) BackEnd() string {
	args := m.Called()
	return args.String(0)
}

// TestMempoolAccept implements the chain.Interface interface.
func (m *Chain) TestMempoolAccept(txns []*wire.MsgTx,
	maxFeeRate float64) ([]*btcjson.TestMempoolAcceptResult, error) {

	args := m.Called(txns, maxFeeRate)
	results, _ := args.Get(0).([]*btcjson.TestMempoolAcceptResult)

	return results, args.Error(1)
}

// MapRPCErr implements the chain.Interface interface.
func (m *Chain) MapRPCErr(err error) error {
	args := m.Called(err)
	return args.Error(0)
}
