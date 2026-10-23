// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
)

// mockCoinSelectionStrategy is a mock implementation of CoinSelectionStrategy.
type mockCoinSelectionStrategy struct {
	mock.Mock
}

var _ CoinSelectionStrategy = (*mockCoinSelectionStrategy)(nil)

// ArrangeCoins implements the CoinSelectionStrategy interface.
func (m *mockCoinSelectionStrategy) ArrangeCoins(coins []Coin,
	feeRate btcutil.Amount) ([]Coin, error) {

	args := m.Called(coins, feeRate)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]Coin), args.Error(1)
}

// mockSpendDetails is a mock implementation of the SpendDetails interface.
type mockSpendDetails struct {
	mock.Mock
}

// A compile-time assertion to ensure that mockSpendDetails implements the
// SpendDetails interface.
var _ SpendDetails = (*mockSpendDetails)(nil)

// Sign implements the SpendDetails interface.
func (m *mockSpendDetails) Sign(params *RawSigParams,
	privKey *btcec.PrivateKey) (RawSignature, error) {

	args := m.Called(params, privKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(RawSignature), args.Error(1)
}

// isSpendDetails implements the SpendDetails interface.
func (m *mockSpendDetails) isSpendDetails() {}

// mockController is a mock implementation of the Controller interface.
type mockController struct {
	mock.Mock
}

// Compile-time check to ensure mockController implements Controller.
var _ Controller = (*mockController)(nil)

// Unlock implements the Controller interface.
func (m *mockController) Unlock(ctx context.Context, req UnlockRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

// Lock implements the Controller interface.
func (m *mockController) Lock(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// ChangePassphrase implements the Controller interface.
func (m *mockController) ChangePassphrase(ctx context.Context,
	req ChangePassphraseRequest) error {

	args := m.Called(ctx, req)
	return args.Error(0)
}

// Info implements the Controller interface.
func (m *mockController) Info(ctx context.Context) (*Info, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*Info), args.Error(1)
}

// Resync implements the Controller interface.
func (m *mockController) Resync(ctx context.Context, startHeight uint32) error {
	args := m.Called(ctx, startHeight)
	return args.Error(0)
}

// Rescan implements the Controller interface.
func (m *mockController) Rescan(ctx context.Context, startHeight uint32,
	targets []waddrmgr.AccountScope) error {

	args := m.Called(ctx, startHeight, targets)
	return args.Error(0)
}

// mockChainSyncer is a mock implementation of the chainSyncer interface.
type mockChainSyncer struct {
	mock.Mock
}

// A compile-time assertion to ensure that mockChainSyncer implements the
// chainSyncer interface.
var _ chainSyncer = (*mockChainSyncer)(nil)

// run implements the chainSyncer interface.
func (m *mockChainSyncer) run(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// requestScan implements the chainSyncer interface.
func (m *mockChainSyncer) requestScan(ctx context.Context, req *scanReq) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

// syncState implements the chainSyncer interface.
func (m *mockChainSyncer) syncState() syncState {
	args := m.Called()
	return args.Get(0).(syncState)
}

// syncedTo exposes the processed tip and errors expected by wallet callers.
func (m *mockChainSyncer) syncedTo(ctx context.Context) (waddrmgr.BlockStamp,
	error) {

	args := m.Called(ctx)
	return args.Get(0).(waddrmgr.BlockStamp), args.Error(1)
}

// mockTxPublisher is a mock implementation of the TxPublisher interface.
type mockTxPublisher struct {
	mock.Mock
}

// A compile-time check to ensure that mockTxPublisher implements the
// TxPublisher interface.
var _ TxPublisher = (*mockTxPublisher)(nil)

// CheckMempoolAcceptance implements the TxPublisher interface.
func (m *mockTxPublisher) CheckMempoolAcceptance(ctx context.Context,
	tx *wire.MsgTx) error {

	args := m.Called(ctx, tx)
	return args.Error(0)
}

// Broadcast implements the TxPublisher interface.
func (m *mockTxPublisher) Broadcast(ctx context.Context, tx *wire.MsgTx,
	label string) error {

	args := m.Called(ctx, tx, label)
	return args.Error(0)
}

// The existing publisher mock also supplies strict syncer notification and
// ownership expectations, without a partial real-Wallet implementation.
var _ txManager = (*mockTxPublisher)(nil)

// notifyTx records each post-commit observation expected by the current test.
func (m *mockTxPublisher) notifyTx(ctx context.Context, hash chainhash.Hash) {
	m.Called(ctx, hash)
}

// filterRelevantTxs returns the Wallet selection arranged by a syncer unit
// test; real ownership behavior is covered with actual Wallet processors.
func (m *mockTxPublisher) filterRelevantTxs(ctx context.Context,
	records []*wtxmgr.TxRecord) ([]*wtxmgr.TxRecord, error) {

	args := m.Called(ctx, records)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]*wtxmgr.TxRecord), args.Error(1)
}
