package spvchain

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// SPVChain is an implementation of the btcwalet chain.Interface interface.
type SPVChain struct {
	cs *ChainService
}

// NewSPVChain creates a new SPVChain struct with a backing ChainService
func NewSPVChain(chainService *ChainService) *SPVChain {
	return &SPVChain{
		cs: chainService,
	}
}

// Start replicates the RPC client's Start method.
func (s *SPVChain) Start() error {
	s.cs.Start()
	return nil
}

// Stop replicates the RPC client's Stop method.
func (s *SPVChain) Stop() {
	s.cs.Stop()
}

// WaitForShutdown replicates the RPC client's WaitForShutdown method.
func (s *SPVChain) WaitForShutdown() {
	s.cs.Stop()
}

// SendRawTransaction replicates the RPC client's SendRawTransaction command.
func (s *SPVChain) SendRawTransaction(tx *wire.MsgTx, allowHighFees bool) (
	*chainhash.Hash, error) {
	err := s.cs.SendTransaction(tx)
	if err != nil {
		return nil, err
	}
	hash := tx.TxHash()
	return &hash, nil
}

// GetBlock replicates the RPC client's GetBlock command.
func (s *SPVChain) GetBlock(hash *chainhash.Hash) (*wire.MsgBlock, error) {
	block, err := s.cs.GetBlockFromNetwork(*hash)
	if err != nil {
		return nil, err
	}
	return block.MsgBlock(), nil
}

// GetBestBlock replicates the RPC client's GetBestBlock command.
func (s *SPVChain) GetBestBlock() (*chainhash.Hash, int32, error) {
	header, height, err := s.cs.LatestBlock()
	if err != nil {
		return nil, 0, err
	}
	hash := header.BlockHash()
	return &hash, int32(height), nil
}

// BlockStamp replicates the RPC client's BlockStamp command.
func (s *SPVChain) BlockStamp() (*waddrmgr.BlockStamp, error) {
	return s.cs.SyncedTo()
}
