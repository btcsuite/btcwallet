package chain

import (
	"container/list"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/gcs"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain/internal/rescan"
	"github.com/lightninglabs/neutrino"
	"github.com/lightninglabs/neutrino/banman"
	"github.com/lightninglabs/neutrino/headerfs"
)

// Define variables for mocks
var (
	ErrNotImplemented = errors.New("not implemented")
	testBestBlock     = &headerfs.BlockStamp{
		Height: 42,
	}
)

// Define static type checks
var (
	_ rescan.Interface     = (*mockRescanner)(nil)
	_ NeutrinoChainService = (*mockChainService)(nil)
)

func newMockNeutrinoClient(t *testing.T,
	opts ...func(*mockRescanner)) *NeutrinoClient {
	t.Helper()

	return &NeutrinoClient{
		CS: &mockChainService{},
	}
}

type mockRescanner struct {
	updateArgs *list.List
	errs       []error
	rescanQuit <-chan struct{}
}

func (m *mockRescanner) Start() <-chan error {
	errs := make(chan error)
	return errs
}

func (m *mockRescanner) WaitForShutdown() {
	// no-op
}

func (m *mockRescanner) Update(opts ...neutrino.UpdateOption) error {
	m.updateArgs.PushBack(opts)
	return nil
}

type mockChainService struct{}

func (m *mockChainService) Start() error {
	return nil
}

func (m *mockChainService) GetBlock(chainhash.Hash,
	...neutrino.QueryOption) (*btcutil.Block, error) {
	return nil, ErrNotImplemented
}

func (m *mockChainService) GetBlockHeight(*chainhash.Hash) (int32, error) {
	return 0, ErrNotImplemented
}

func (m *mockChainService) BestBlock() (*headerfs.BlockStamp, error) {
	return m.getBestBlock(), nil
}

func (m *mockChainService) getBestBlock() *headerfs.BlockStamp {
	return testBestBlock
}

func (m *mockChainService) GetBlockHash(int64) (*chainhash.Hash, error) {
	return nil, ErrNotImplemented
}

func (m *mockChainService) GetBlockHeader(
	*chainhash.Hash) (*wire.BlockHeader, error) {
	return &wire.BlockHeader{}, nil
}

func (m *mockChainService) IsCurrent() bool {
	return false
}

func (m *mockChainService) SendTransaction(*wire.MsgTx) error {
	return ErrNotImplemented
}

func (m *mockChainService) GetCFilter(chainhash.Hash,
	wire.FilterType, ...neutrino.QueryOption) (*gcs.Filter, error) {
	return nil, ErrNotImplemented
}

func (m *mockChainService) GetUtxo(
	_ ...neutrino.RescanOption) (*neutrino.SpendReport, error) {
	return nil, ErrNotImplemented
}

func (m *mockChainService) BanPeer(string, banman.Reason) error {
	return ErrNotImplemented
}

func (m *mockChainService) IsBanned(addr string) bool {
	panic(ErrNotImplemented)
}

func (m *mockChainService) AddPeer(*neutrino.ServerPeer) {
	panic(ErrNotImplemented)
}

func (m *mockChainService) AddBytesSent(uint64) {
	panic(ErrNotImplemented)
}

func (m *mockChainService) AddBytesReceived(uint64) {
	panic(ErrNotImplemented)
}

func (m *mockChainService) NetTotals() (uint64, uint64) {
	panic(ErrNotImplemented)
}

func (m *mockChainService) UpdatePeerHeights(*chainhash.Hash,
	int32, *neutrino.ServerPeer,
) {
	panic(ErrNotImplemented)
}

func (m *mockChainService) ChainParams() chaincfg.Params {
	panic(ErrNotImplemented)
}

func (m *mockChainService) Stop() error {
	panic(ErrNotImplemented)
}

func (m *mockChainService) PeerByAddr(string) *neutrino.ServerPeer {
	panic(ErrNotImplemented)
}
