package wallet

import (
	"context"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

type mockChainClient struct {
	getBestBlockHash   *chainhash.Hash
	getBestBlockHeight int32
	getBestBlockErr    error
	getBlockHashFunc   func() (*chainhash.Hash, error)
	getBlockHashAt     func(int64) (*chainhash.Hash, error)
	getBlockHeader     *wire.BlockHeader
	getBlockHeaderFunc func(*chainhash.Hash) (*wire.BlockHeader, error)
	filterBlocksFunc   func(*chain.FilterBlocksRequest) (
		*chain.FilterBlocksResponse, error)
	notifications chan interface{}
	rpcGuard      func() error
}

var _ chain.Interface = (*mockChainClient)(nil)

// guardRPC rejects a mock RPC when a test marks a Store callback active.
func (m *mockChainClient) guardRPC() error {
	if m.rpcGuard == nil {
		return nil
	}

	return m.rpcGuard()
}

// Start starts the mock chain client.
func (m *mockChainClient) Start(_ context.Context) error {
	return m.guardRPC()
}

// Stop stops the mock chain client.
func (m *mockChainClient) Stop() {
}

// WaitForShutdown waits for the mock chain client to stop.
func (m *mockChainClient) WaitForShutdown() {}

// GetBestBlock returns the configured mock chain tip.
func (m *mockChainClient) GetBestBlock() (*chainhash.Hash, int32, error) {
	if err := m.guardRPC(); err != nil {
		return nil, 0, err
	}

	return m.getBestBlockHash, m.getBestBlockHeight, m.getBestBlockErr
}

// GetBlock returns no block data from the mock chain client.
func (m *mockChainClient) GetBlock(*chainhash.Hash) (*wire.MsgBlock, error) {
	if err := m.guardRPC(); err != nil {
		return nil, err
	}

	return nil, nil
}

// GetBlockHash returns the configured hash for a block height.
func (m *mockChainClient) GetBlockHash(height int64) (*chainhash.Hash, error) {
	if err := m.guardRPC(); err != nil {
		return nil, err
	}
	if m.getBlockHashAt != nil {
		return m.getBlockHashAt(height)
	}
	if m.getBlockHashFunc != nil {
		return m.getBlockHashFunc()
	}
	return nil, nil
}

// GetBlockHeader returns the configured block header.
func (m *mockChainClient) GetBlockHeader(
	hash *chainhash.Hash) (*wire.BlockHeader, error) {

	if err := m.guardRPC(); err != nil {
		return nil, err
	}
	if m.getBlockHeaderFunc != nil {
		return m.getBlockHeaderFunc(hash)
	}

	return m.getBlockHeader, nil
}

// IsCurrent reports that the mock backend is not current.
func (m *mockChainClient) IsCurrent() bool {
	return false
}

// FilterBlocks returns the configured mock filter response.
func (m *mockChainClient) FilterBlocks(request *chain.FilterBlocksRequest) (
	*chain.FilterBlocksResponse, error) {
	if err := m.guardRPC(); err != nil {
		return nil, err
	}
	if m.filterBlocksFunc != nil {
		return m.filterBlocksFunc(request)
	}

	return nil, nil
}

// BlockStamp returns a fixed mock block stamp.
func (m *mockChainClient) BlockStamp() (*waddrmgr.BlockStamp, error) {
	if err := m.guardRPC(); err != nil {
		return nil, err
	}

	return &waddrmgr.BlockStamp{
		Height:    500000,
		Hash:      chainhash.Hash{},
		Timestamp: time.Unix(1234, 0),
	}, nil
}

// SendRawTransaction accepts a transaction without broadcasting it.
func (m *mockChainClient) SendRawTransaction(*wire.MsgTx, bool) (
	*chainhash.Hash, error) {
	if err := m.guardRPC(); err != nil {
		return nil, err
	}

	return nil, nil
}

// Rescan accepts a mock rescan request.
func (m *mockChainClient) Rescan(*chainhash.Hash, []address.Address,
	map[wire.OutPoint]address.Address) error {

	return m.guardRPC()
}

// NotifyReceived accepts a mock address notification request.
func (m *mockChainClient) NotifyReceived([]address.Address) error {
	return m.guardRPC()
}

// NotifyBlocks accepts a mock block notification request.
func (m *mockChainClient) NotifyBlocks() error {
	return m.guardRPC()
}

// Notifications returns the configured mock notification channel.
func (m *mockChainClient) Notifications() <-chan interface{} {
	return m.notifications
}

// BackEnd identifies the mock chain backend.
func (m *mockChainClient) BackEnd() string {
	return "mock"
}

// TestMempoolAccept returns the mempool acceptance result for raw transactions.
//
// NOTE: This is part of the chain.Interface interface.
func (m *mockChainClient) TestMempoolAccept(txns []*wire.MsgTx,
	maxFeeRate float64) ([]*btcjson.TestMempoolAcceptResult, error) {

	if err := m.guardRPC(); err != nil {
		return nil, err
	}

	return nil, nil
}

// SubmitPackage is part of the chain.Interface interface.
func (m *mockChainClient) SubmitPackage(txns []*wire.MsgTx,
	maxFeeRate *float64) (*btcjson.SubmitPackageResult, error) {

	if err := m.guardRPC(); err != nil {
		return nil, err
	}

	return &btcjson.SubmitPackageResult{}, nil
}

// MapRPCErr maps no errors for the mock chain client.
func (m *mockChainClient) MapRPCErr(err error) error {
	if guardErr := m.guardRPC(); guardErr != nil {
		return guardErr
	}

	return nil
}
