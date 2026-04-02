package chain

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/gcs"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/neutrino"
	"github.com/lightninglabs/neutrino/banman"
	"github.com/lightninglabs/neutrino/blockntfns"
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
func newMockNeutrinoClient(useActorRescan bool) *NeutrinoClient {
	// newRescanFunc returns a mockRescanner
	newRescanFunc := func(ro ...neutrino.RescanOption) rescanner {
		return &mockRescanner{
			updateArgs: list.New(),
		}
	}

	client := &NeutrinoClient{
		CS:        &mockChainService{},
		newRescan: newRescanFunc,
	}

	if useActorRescan {
		client.UseActorRescan = true
		client.newActorChainSource = func() neutrino.ChainSource {
			return newMockActorChainSource(uint32(testBestBlock.Height))
		}
	}

	return client
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

func (m *mockChainService) Start(_ context.Context) error {
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

type mockActorChainSource struct {
	heights map[chainhash.Hash]uint32
	headers map[uint32]*wire.BlockHeader
	best    headerfs.BlockStamp
	params  chaincfg.Params
}

func newMockActorChainSource(bestHeight uint32) *mockActorChainSource {
	headers := make(map[uint32]*wire.BlockHeader, bestHeight+1)
	heights := make(map[chainhash.Hash]uint32, bestHeight+1)

	var prevHash chainhash.Hash
	for height := uint32(0); height <= bestHeight; height++ {
		header := wire.BlockHeader{}
		if height != 0 {
			header = wire.BlockHeader{
				Version:    int32(height + 1),
				PrevBlock:  prevHash,
				Timestamp:  time.Unix(int64(height), 0),
				Bits:       uint32(height + 1),
				Nonce:      height,
				MerkleRoot: chainhash.Hash{byte(height + 1)},
			}
		}

		hash := header.BlockHash()
		headerCopy := header
		headers[height] = &headerCopy
		heights[hash] = height
		prevHash = hash
	}

	bestHeader := headers[bestHeight]

	return &mockActorChainSource{
		heights: heights,
		headers: headers,
		best: headerfs.BlockStamp{
			Hash:      bestHeader.BlockHash(),
			Height:    int32(bestHeight),
			Timestamp: bestHeader.Timestamp,
		},
		params: chaincfg.MainNetParams,
	}
}

func (m *mockActorChainSource) ChainParams() chaincfg.Params {
	return m.params
}

func (m *mockActorChainSource) BestBlock() (*headerfs.BlockStamp, error) {
	best := m.best
	return &best, nil
}

func (m *mockActorChainSource) GetBlockHeaderByHeight(
	height uint32) (*wire.BlockHeader, error) {

	header, ok := m.headers[height]
	if !ok {
		return nil, fmt.Errorf("unknown height %d", height)
	}

	headerCopy := *header
	return &headerCopy, nil
}

func (m *mockActorChainSource) GetBlockHeader(
	hash *chainhash.Hash) (*wire.BlockHeader, uint32, error) {

	height, ok := m.heights[*hash]
	if !ok {
		return nil, 0, fmt.Errorf("unknown hash %v", hash)
	}

	header := m.headers[height]
	headerCopy := *header
	return &headerCopy, height, nil
}

func (m *mockActorChainSource) GetBlock(chainhash.Hash,
	...neutrino.QueryOption) (*btcutil.Block, error) {

	return nil, errNotImplemented
}

func (m *mockActorChainSource) GetFilterHeaderByHeight(
	uint32) (*chainhash.Hash, error) {

	zero := chainhash.Hash{}
	return &zero, nil
}

func (m *mockActorChainSource) GetCFilter(chainhash.Hash,
	wire.FilterType, ...neutrino.QueryOption) (*gcs.Filter, error) {

	return nil, nil
}

func (m *mockActorChainSource) Subscribe(
	uint32) (*blockntfns.Subscription, error) {

	ntfns := make(chan blockntfns.BlockNtfn)
	var once sync.Once

	return &blockntfns.Subscription{
		Notifications: ntfns,
		Cancel: func() {
			once.Do(func() {
				close(ntfns)
			})
		},
	}, nil
}

func (m *mockActorChainSource) IsCurrent() bool {
	return true
}

var _ neutrino.ChainSource = (*mockActorChainSource)(nil)

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
