package chain

import (
	"container/list"
	"context"
	"errors"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/gcs"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/neutrino"
	"github.com/lightninglabs/neutrino/banman"
	"github.com/lightninglabs/neutrino/headerfs"
	"github.com/stretchr/testify/mock"
)

var (
	errNotImplemented = errors.New("not implemented")
	testBestBlock     = &headerfs.BlockStamp{
		Height: 42,
	}
)

var (
	_ rescanner            = (*mockRescanner)(nil)
	_ NeutrinoChainService = (*mockChainService)(nil)
)

// newMockNeutrinoClient constructs a neutrino client with a mock chain
// service implementation and mock rescanner interface implementation.
func newMockNeutrinoClient() *NeutrinoClient {
	// newRescanFunc returns a mockRescanner
	newRescanFunc := func(ro ...neutrino.RescanOption) rescanner {
		return &mockRescanner{
			updateArgs: list.New(),
		}
	}

	return &NeutrinoClient{
		CS:        &mockChainService{},
		newRescan: newRescanFunc,
	}
}

// mockRescanner is a mock implementation of a rescanner interface for use in
// tests.  Only the Update method is implemented.
type mockRescanner struct {
	updateArgs *list.List
}

func (m *mockRescanner) Update(opts ...neutrino.UpdateOption) error {
	m.updateArgs.PushBack(opts)
	return nil
}

func (m *mockRescanner) Start() <-chan error {
	return nil
}

func (m *mockRescanner) WaitForShutdown() {
	// no-op
}

// mockChainService is a mock implementation of a chain service for use in
// tests.  Only the Start, GetBlockHeader and BestBlock methods are implemented.
type mockChainService struct {
	mock.Mock
}

func (m *mockChainService) Start(_ context.Context) error {
	args := m.Called()
	return args.Error(0)
}

func (m *mockChainService) BestBlock() (*headerfs.BlockStamp, error) {
	args := m.Called()
	return args.Get(0).(*headerfs.BlockStamp), args.Error(1)
}

func (m *mockChainService) GetBlockHeader(
	hash *chainhash.Hash) (*wire.BlockHeader, error) {

	args := m.Called(hash)
	return args.Get(0).(*wire.BlockHeader), args.Error(1)
}

func (m *mockChainService) GetBlock(
	hash chainhash.Hash,
	options ...neutrino.QueryOption) (*btcutil.Block, error) {

	args := m.Called(hash, options)
	return args.Get(0).(*btcutil.Block), args.Error(1)
}

func (m *mockChainService) GetBlockHeight(hash *chainhash.Hash) (int32, error) {
	args := m.Called(hash)
	return args.Get(0).(int32), args.Error(1)
}

func (m *mockChainService) GetBlockHash(height int64) (*chainhash.Hash, error) {
	args := m.Called(height)
	return args.Get(0).(*chainhash.Hash), args.Error(1)
}

func (m *mockChainService) IsCurrent() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *mockChainService) SendTransaction(tx *wire.MsgTx) error {
	args := m.Called(tx)
	return args.Error(0)
}

func (m *mockChainService) GetCFilter(
	hash chainhash.Hash, filterType wire.FilterType,
	options ...neutrino.QueryOption) (*gcs.Filter, error) {

	args := m.Called(hash, filterType, options)
	return args.Get(0).(*gcs.Filter), args.Error(1)
}

func (m *mockChainService) GetUtxo(
	opts ...neutrino.RescanOption) (*neutrino.SpendReport, error) {

	args := m.Called(opts)
	return args.Get(0).(*neutrino.SpendReport), args.Error(1)
}

func (m *mockChainService) BanPeer(addr string, reason banman.Reason) error {
	args := m.Called(addr, reason)
	return args.Error(0)
}

func (m *mockChainService) IsBanned(addr string) bool {
	args := m.Called(addr)
	return args.Bool(0)
}

func (m *mockChainService) AddPeer(peer *neutrino.ServerPeer) {
	m.Called(peer)
}

func (m *mockChainService) AddBytesSent(bytes uint64) {
	m.Called(bytes)
}

func (m *mockChainService) AddBytesReceived(bytes uint64) {
	m.Called(bytes)
}

func (m *mockChainService) NetTotals() (uint64, uint64) {
	args := m.Called()
	return args.Get(0).(uint64), args.Get(1).(uint64)
}

func (m *mockChainService) UpdatePeerHeights(hash *chainhash.Hash,
	height int32, peer *neutrino.ServerPeer) {

	m.Called(hash, height, peer)
}

func (m *mockChainService) ChainParams() chaincfg.Params {
	args := m.Called()
	return args.Get(0).(chaincfg.Params)
}

func (m *mockChainService) Stop() error {
	args := m.Called()
	return args.Error(0)
}

func (m *mockChainService) PeerByAddr(addr string) *neutrino.ServerPeer {
	args := m.Called(addr)
	return args.Get(0).(*neutrino.ServerPeer)
}

// mockRPCClient mocks the rpcClient interface.
type mockRPCClient struct {
	mock.Mock
}

// Compile time assert the implementation.
var _ batchClient = (*mockRPCClient)(nil)

func (m *mockRPCClient) GetRawMempoolAsync() rpcclient.
	FutureGetRawMempoolResult {

	args := m.Called()
	return args.Get(0).(rpcclient.FutureGetRawMempoolResult)
}

func (m *mockRPCClient) GetRawTransactionAsync(
	txHash *chainhash.Hash) rpcclient.FutureGetRawTransactionResult {

	args := m.Called(txHash)

	tx := args.Get(0)
	if tx == nil {
		return nil
	}

	return args.Get(0).(rpcclient.FutureGetRawTransactionResult)
}

func (m *mockRPCClient) Send() error {
	args := m.Called()
	return args.Error(0)
}

// mockGetRawTxReceiver mocks the getRawTxReceiver interface.
type mockGetRawTxReceiver struct {
	*rpcclient.FutureGetRawTransactionResult
	mock.Mock
}

func (m *mockGetRawTxReceiver) Receive() (*btcutil.Tx, error) {
	args := m.Called()

	tx := args.Get(0)
	if tx == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*btcutil.Tx), args.Error(1)
}

// Compile time assert the implementation.
var _ getRawTxReceiver = (*mockGetRawTxReceiver)(nil)
