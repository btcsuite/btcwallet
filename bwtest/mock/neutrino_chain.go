// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mock

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/gcs"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/lightninglabs/neutrino"
	"github.com/lightninglabs/neutrino/banman"
	"github.com/lightninglabs/neutrino/headerfs"
)

// NeutrinoChain is a mock implementation of the chain.NeutrinoChainService
// interface.
type NeutrinoChain struct {
	Chain
}

// A compile-time assertion to ensure that NeutrinoChain implements the
// chain.NeutrinoChainService.
var _ chain.NeutrinoChainService = (*NeutrinoChain)(nil)

// Stop implements the chain.NeutrinoChainService interface.
func (m *NeutrinoChain) Stop() error {
	args := m.Called()
	return args.Error(0)
}

// GetBlock implements the chain.NeutrinoChainService interface.
func (m *NeutrinoChain) GetBlock(hash chainhash.Hash,
	opts ...neutrino.QueryOption) (*btcutil.Block, error) {

	args := m.Called(hash, opts)
	if args.Get(0) != nil {
		if val, ok := args.Get(0).(*btcutil.Block); ok {
			return val, args.Error(1)
		}
	}

	return nil, args.Error(1)
}

// GetCFilter implements the chain.NeutrinoChainService interface.
func (m *NeutrinoChain) GetCFilter(hash chainhash.Hash,
	filterType wire.FilterType,
	opts ...neutrino.QueryOption) (*gcs.Filter, error) {

	args := m.Called(hash, filterType, opts)
	if args.Get(0) != nil {
		if val, ok := args.Get(0).(*gcs.Filter); ok {
			return val, args.Error(1)
		}
	}

	return nil, args.Error(1)
}

// GetBlockHeight implements the chain.NeutrinoChainService interface.
func (m *NeutrinoChain) GetBlockHeight(
	hash *chainhash.Hash) (int32, error) {

	args := m.Called(hash)
	return args.Get(0).(int32), args.Error(1)
}

// BestBlock implements the chain.NeutrinoChainService interface.
func (m *NeutrinoChain) BestBlock() (*headerfs.BlockStamp, error) {
	args := m.Called()
	if args.Get(0) != nil {
		if val, ok := args.Get(0).(*headerfs.BlockStamp); ok {
			return val, args.Error(1)
		}
	}

	return nil, args.Error(1)
}

// SendTransaction implements the chain.NeutrinoChainService interface.
func (m *NeutrinoChain) SendTransaction(tx *wire.MsgTx) error {
	args := m.Called(tx)
	return args.Error(0)
}

// GetUtxo implements the chain.NeutrinoChainService interface.
func (m *NeutrinoChain) GetUtxo(
	opts ...neutrino.RescanOption) (*neutrino.SpendReport, error) {

	args := m.Called(opts)
	if args.Get(0) != nil {
		if val, ok := args.Get(0).(*neutrino.SpendReport); ok {
			return val, args.Error(1)
		}
	}

	return nil, args.Error(1)
}

// BanPeer implements the chain.NeutrinoChainService interface.
func (m *NeutrinoChain) BanPeer(addr string,
	reason banman.Reason) error {

	args := m.Called(addr, reason)
	return args.Error(0)
}

// IsBanned implements the chain.NeutrinoChainService interface.
func (m *NeutrinoChain) IsBanned(addr string) bool {
	args := m.Called(addr)
	return args.Bool(0)
}

// AddPeer implements the chain.NeutrinoChainService interface.
func (m *NeutrinoChain) AddPeer(peer *neutrino.ServerPeer) {
	m.Called(peer)
}

// AddBytesSent implements the chain.NeutrinoChainService interface.
func (m *NeutrinoChain) AddBytesSent(bytes uint64) {
	m.Called(bytes)
}

// AddBytesReceived implements the chain.NeutrinoChainService interface.
func (m *NeutrinoChain) AddBytesReceived(bytes uint64) {
	m.Called(bytes)
}

// NetTotals implements the chain.NeutrinoChainService interface.
func (m *NeutrinoChain) NetTotals() (uint64, uint64) {
	args := m.Called()

	var a, b uint64
	if args.Get(0) != nil {
		if val, ok := args.Get(0).(uint64); ok {
			a = val
		}
	}

	if args.Get(1) != nil {
		if val, ok := args.Get(1).(uint64); ok {
			b = val
		}
	}

	return a, b
}

// UpdatePeerHeights implements the chain.NeutrinoChainService interface.
func (m *NeutrinoChain) UpdatePeerHeights(hash *chainhash.Hash,
	height int32, peer *neutrino.ServerPeer) {

	m.Called(hash, height, peer)
}

// ChainParams implements the chain.NeutrinoChainService interface.
func (m *NeutrinoChain) ChainParams() chaincfg.Params {
	args := m.Called()
	if args.Get(0) != nil {
		if val, ok := args.Get(0).(chaincfg.Params); ok {
			return val
		}
	}

	return chaincfg.Params{}
}

// PeerByAddr implements the chain.NeutrinoChainService interface.
func (m *NeutrinoChain) PeerByAddr(
	addr string) *neutrino.ServerPeer {

	args := m.Called(addr)
	if args.Get(0) != nil {
		if val, ok := args.Get(0).(*neutrino.ServerPeer); ok {
			return val
		}
	}

	return nil
}
