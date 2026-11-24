// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
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

// mockChainProcessor is a mock implementation of the chainProcessor interface.
type mockChainProcessor struct {
	mock.Mock
}

// A compile-time assertion to ensure that mockChainProcessor implements the
// chainProcessor interface.
var _ chainProcessor = (*mockChainProcessor)(nil)

// run implements the chainProcessor interface.
func (m *mockChainProcessor) run(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// processChainEventBeforeSync records ordered mailbox work during startup or
// retry so controller tests can require its exact acceptance and result.
func (m *mockChainProcessor) processChainEventBeforeSync(ctx context.Context,
	event chainEvent) error {

	args := m.Called(ctx, event)
	return args.Error(0)
}

// requestScan implements the chainProcessor interface.
func (m *mockChainProcessor) requestScan(ctx context.Context,
	req *scanReq) error {

	args := m.Called(ctx, req)
	return args.Error(0)
}

// syncState implements the chainProcessor interface.
func (m *mockChainProcessor) syncState() syncState {
	args := m.Called()
	return args.Get(0).(syncState)
}

// syncedTo exposes the processed tip and errors expected by wallet callers.
func (m *mockChainProcessor) syncedTo(ctx context.Context) (waddrmgr.BlockStamp,
	error) {

	args := m.Called(ctx)
	return args.Get(0).(waddrmgr.BlockStamp), args.Error(1)
}

// mockTxPublisher mocks only the syncer's non-creating retry capability.
type mockTxPublisher struct {
	mock.Mock
}

// mockTxPublisher implements the private capability used by syncer fixtures.
var _ txRebroadcaster = (*mockTxPublisher)(nil)

// rebroadcast exposes each background retry to the test's declared expectation.
func (m *mockTxPublisher) rebroadcast(ctx context.Context,
	tx *wire.MsgTx) error {

	args := m.Called(ctx, tx)
	return args.Error(0)
}
