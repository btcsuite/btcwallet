// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mock

import (
	"context"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil/v2/gcs"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
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

// NewGenesisChain supplies a regression-genesis fixture for Wallet startup.
// An unsynced backend waits for cancellation; a current backend can finish
// syncing at genesis without scanning. Startup calls are optional because
// scheduling and empty/reopened Wallets differ. Cleanup verifies expectations
// once, after callers' later Wallet and container cleanup has completed.
func NewGenesisChain(tb testing.TB, current bool) *Chain {
	tb.Helper()

	params := &chaincfg.RegressionNetParams
	m := &Chain{}

	// Tests can replace these defaults when registration is under test.
	m.On("BackEnd").Return("mock").Maybe()
	m.On("Notifications").Return((<-chan any)(nil)).Maybe()
	m.On("SubscribeChainEvents", mock.Anything).Return(
		func(ctx context.Context) chain.EventSubscription {
			return NewEventSubscription(ctx, m)
		},
	).Maybe()
	m.On("WatchAddrsFromTip", mock.Anything, mock.Anything).
		Return(nil).Maybe()
	m.On("NotifySpent", mock.Anything).Return(nil).Maybe()
	m.On("IsCurrent").Return(current).Maybe()

	// Only a current backend subscribes after completing startup sync.
	if current {
		m.On("NotifyBlocks").Return(nil).Maybe()
	}

	m.On("GetBestBlock").Return(
		params.GenesisHash, int32(0), nil,
	).Maybe()
	m.On("GetBlockHash", int64(0)).Return(
		params.GenesisHash, nil,
	).Maybe()
	m.On("GetBlockHeader", params.GenesisHash).Return(
		&params.GenesisBlock.Header, nil,
	).Maybe()
	tb.Cleanup(func() {
		m.AssertExpectations(tb)
	})

	return m
}

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
func (m *Chain) Rescan(hash *chainhash.Hash, addrs []address.Address,
	outpoints map[wire.OutPoint]address.Address) error {

	args := m.Called(hash, addrs, outpoints)
	return args.Error(0)
}

// NotifyReceived implements the chain.Interface interface.
func (m *Chain) NotifyReceived(addrs []address.Address) error {
	args := m.Called(addrs)
	return args.Error(0)
}

// NotifySpent implements the chain.Interface interface.
func (m *Chain) NotifySpent(points []*wire.OutPoint) error {
	args := m.Called(points)
	return args.Error(0)
}

// WatchAddrsFromTip implements the chain.Interface interface and delegates the
// full contextual call through mock.Mock so tests can assert the live-watch
// delivery boundary explicitly.
func (m *Chain) WatchAddrsFromTip(ctx context.Context,
	addrs []address.Address) error {

	args := m.Called(ctx, addrs)
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

// SubscribeChainEvents returns the stream arranged for the caller. Tests may
// supply either a concrete chain.EventSubscription or a factory function
// func(context.Context) chain.EventSubscription so each enrollment receives a
// distinct subscription bound to its own context.
func (m *Chain) SubscribeChainEvents(
	ctx context.Context) chain.EventSubscription {

	type enrollFunc = func(context.Context) chain.EventSubscription

	args := m.Called(ctx)
	if enroll, ok := args.Get(0).(enrollFunc); ok {
		return enroll(ctx)
	}

	sub, _ := args.Get(0).(chain.EventSubscription)

	return sub
}

// eventSubBufferSize is the bounded in-memory buffer capacity of mock
// EventSubscription channels used in tests and benchmarks.
const eventSubBufferSize = 100

// EventSubscription is an in-memory mock implementation of
// chain.EventSubscription for tests and benchmarks.
type EventSubscription struct {
	mu          sync.Mutex
	client      chain.Interface
	blockEvents chan chain.Event
	mempoolTxns chan *wtxmgr.TxRecord
	done        chan struct{}
	canceled    <-chan struct{}
	stopCtx     func() bool
	closed      bool
	err         error
}

// A compile-time assertion to ensure that EventSubscription implements
// chain.EventSubscription.
var _ chain.EventSubscription = (*EventSubscription)(nil)

// NewEventSubscription creates an in-memory EventSubscription tied to ctx that
// delegates WatchAddrs and WatchOutputs to client.
func NewEventSubscription(ctx context.Context,
	client chain.Interface) *EventSubscription {

	sub := &EventSubscription{
		client:      client,
		blockEvents: make(chan chain.Event, eventSubBufferSize),
		mempoolTxns: make(chan *wtxmgr.TxRecord, eventSubBufferSize),
		done:        make(chan struct{}),
		canceled:    ctx.Done(),
	}
	if ctx.Err() != nil {
		sub.closeLocked(ctx.Err())

		return sub
	}

	sub.stopCtx = context.AfterFunc(ctx, func() {
		sub.Close(ctx.Err())
	})

	return sub
}

// BlockEvents returns the buffered block event channel for this mock
// subscription.
func (s *EventSubscription) BlockEvents() <-chan chain.Event {
	return s.blockEvents
}

// MempoolTxns returns the buffered best-effort mempool tx channel for this
// mock subscription.
func (s *EventSubscription) MempoolTxns() <-chan *wtxmgr.TxRecord {
	return s.mempoolTxns
}

// Done returns the completion channel for this mock subscription.
func (s *EventSubscription) Done() <-chan struct{} {
	return s.done
}

// Err returns the terminal error after Done closes.
func (s *EventSubscription) Err() error {
	select {
	case <-s.done:
		return s.err
	default:
		return nil
	}
}

// Cancel immediately unsubscribes this mock handle and publishes
// context.Canceled via Err if it has not already terminated.
func (s *EventSubscription) Cancel() {
	s.Close(context.Canceled)
}

// SendBlock enqueues a block event on this subscription or retires it with
// chain.ErrEventSubscriptionBufferFull if BlockEvents is full.
func (s *EventSubscription) SendBlock(event chain.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}

	select {
	case s.blockEvents <- event:
	default:
		s.closeLocked(chain.ErrEventSubscriptionBufferFull)
	}
}

// SendMempoolTx enqueues a matching mempool tx on MempoolTxns, dropping it
// without retiring the subscription if the mempool buffer is full.
func (s *EventSubscription) SendMempoolTx(rec *wtxmgr.TxRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}

	select {
	case s.mempoolTxns <- rec:
	default:
	}
}

// Close retires this subscription once with err.
func (s *EventSubscription) Close(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closeLocked(err)
}

// closeLocked retires the subscription while s.mu is held.
func (s *EventSubscription) closeLocked(err error) {
	if s.closed {
		return
	}

	s.closed = true
	s.err = err

	if s.stopCtx != nil {
		s.stopCtx()
	}

	close(s.blockEvents)
	close(s.mempoolTxns)
	close(s.done)
}

// checkWatchable verifies ctx and subscription liveness before forwarding
// watch registration to the mock client.
func (s *EventSubscription) checkWatchable(ctx context.Context) error {
	err := ctx.Err()
	if err != nil {
		return err
	}

	select {
	case <-s.canceled:
		return context.Canceled
	default:
	}

	s.mu.Lock()
	closed := s.closed
	termErr := s.err
	s.mu.Unlock()

	if closed {
		if termErr != nil {
			return termErr
		}

		return context.Canceled
	}

	return nil
}

// WatchAddrs forwards address watch registration to the backing mock client.
func (s *EventSubscription) WatchAddrs(ctx context.Context,
	addrs []address.Address) error {

	err := s.checkWatchable(ctx)
	if err != nil {
		return err
	}

	return s.client.WatchAddrsFromTip(ctx, addrs)
}

// WatchOutputs forwards output watch registration to the backing mock client.
func (s *EventSubscription) WatchOutputs(ctx context.Context,
	outpoints []*wire.OutPoint) error {

	err := s.checkWatchable(ctx)
	if err != nil {
		return err
	}

	if len(outpoints) == 0 {
		return nil
	}

	return s.client.NotifySpent(outpoints)
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

// SubmitPackage implements the chain.Interface interface.
func (m *Chain) SubmitPackage(txns []*wire.MsgTx,
	maxFeeRate *float64) (*btcjson.SubmitPackageResult, error) {

	args := m.Called(txns, maxFeeRate)
	result, _ := args.Get(0).(*btcjson.SubmitPackageResult)

	return result, args.Error(1)
}

// MapRPCErr implements the chain.Interface interface.
func (m *Chain) MapRPCErr(err error) error {
	args := m.Called(err)
	return args.Error(0)
}
