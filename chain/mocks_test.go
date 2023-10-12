package chain

import (
	"container/list"
	"errors"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/gcs"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
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
}

func (m *mockChainService) Start() error {
	return nil
}

func (m *mockChainService) BestBlock() (*headerfs.BlockStamp, error) {
	return testBestBlock, nil
}

func (m *mockChainService) GetBlockHeader(
	*chainhash.Hash) (*wire.BlockHeader, error) {

	return &wire.BlockHeader{}, nil
}

func (m *mockChainService) GetBlock(chainhash.Hash,
	...neutrino.QueryOption) (*btcutil.Block, error) {

	return nil, errNotImplemented
}

func (m *mockChainService) GetBlockHeight(*chainhash.Hash) (int32, error) {
	return 0, errNotImplemented
}

func (m *mockChainService) GetBlockHash(int64) (*chainhash.Hash, error) {
	return nil, errNotImplemented
}

func (m *mockChainService) IsCurrent() bool {
	return false
}

func (m *mockChainService) SendTransaction(*wire.MsgTx) error {
	return errNotImplemented
}

func (m *mockChainService) GetCFilter(chainhash.Hash,
	wire.FilterType, ...neutrino.QueryOption) (*gcs.Filter, error) {

	return nil, errNotImplemented
}

func (m *mockChainService) GetUtxo(
	_ ...neutrino.RescanOption) (*neutrino.SpendReport, error) {

	return nil, errNotImplemented
}

func (m *mockChainService) BanPeer(string, banman.Reason) error {
	return errNotImplemented
}

func (m *mockChainService) IsBanned(addr string) bool {
	panic(errNotImplemented)
}

func (m *mockChainService) AddPeer(*neutrino.ServerPeer) {
	panic(errNotImplemented)
}

func (m *mockChainService) AddBytesSent(uint64) {
	panic(errNotImplemented)
}

func (m *mockChainService) AddBytesReceived(uint64) {
	panic(errNotImplemented)
}

func (m *mockChainService) NetTotals() (uint64, uint64) {
	panic(errNotImplemented)
}

func (m *mockChainService) UpdatePeerHeights(*chainhash.Hash,
	int32, *neutrino.ServerPeer,
) {
	panic(errNotImplemented)
}

func (m *mockChainService) ChainParams() chaincfg.Params {
	panic(errNotImplemented)
}

func (m *mockChainService) Stop() error {
	panic(errNotImplemented)
}

func (m *mockChainService) PeerByAddr(string) *neutrino.ServerPeer {
	panic(errNotImplemented)
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
