package wallet

import (
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stroomnetwork/btcwallet/chain"
	"github.com/stroomnetwork/btcwallet/waddrmgr"
)

type mockChainClient struct {
	getBestBlockHeight int32
	getBlockHashFunc   func() (*chainhash.Hash, error)
	getBlockHeader     *wire.BlockHeader
}

var _ chain.Interface = (*mockChainClient)(nil)

func (m *mockChainClient) Start() error {
	return nil
}

func (m *mockChainClient) Stop() {
}

func (m *mockChainClient) WaitForShutdown() {}

func (m *mockChainClient) GetBestBlock() (*chainhash.Hash, int32, error) {
	return nil, m.getBestBlockHeight, nil
}

func (m *mockChainClient) GetBlock(*chainhash.Hash) (*wire.MsgBlock, error) {
	return nil, nil
}

func (m *mockChainClient) GetBlockHash(int64) (*chainhash.Hash, error) {
	if m.getBlockHashFunc != nil {
		return m.getBlockHashFunc()
	}
	return nil, nil
}

func (m *mockChainClient) GetBlockHeader(*chainhash.Hash) (*wire.BlockHeader,
	error) {
	return m.getBlockHeader, nil
}

func (m *mockChainClient) IsCurrent() bool {
	return false
}

func (m *mockChainClient) FilterBlocks(*chain.FilterBlocksRequest) (
	*chain.FilterBlocksResponse, error) {
	return nil, nil
}

func (m *mockChainClient) BlockStamp() (*waddrmgr.BlockStamp, error) {
	return &waddrmgr.BlockStamp{
		Height:    500000,
		Hash:      chainhash.Hash{},
		Timestamp: time.Unix(1234, 0),
	}, nil
}

func (m *mockChainClient) SendRawTransaction(*wire.MsgTx, bool) (
	*chainhash.Hash, error) {
	return nil, nil
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

func (m *mockChainClient) PublicNotifications() <-chan interface{} {
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

	return nil, nil
}

func (m *mockChainClient) MapRPCErr(err error) error {
	return nil
}

func (c *mockChainClient) EstimateFee(numBlocks int64) (float64, error) {
	return 0, fmt.Errorf("not implemented")
}
