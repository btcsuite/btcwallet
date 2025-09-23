// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	errDummy           = errors.New("dummy")
	errInsufficientFee = errors.New("insufficient fee")
	errRpc             = errors.New("rpc error")
	errPublish         = errors.New("publish error")
	errRemove          = errors.New("remove error")
)

const testTxLabel = "test-tx"

// TestCheckMempoolAcceptance tests the CheckMempoolAcceptance method.
func TestCheckMempoolAcceptance(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tx := &wire.MsgTx{}

	mempoolAcceptResultAllowed := []*btcjson.TestMempoolAcceptResult{
		{Allowed: true},
	}
	mempoolAcceptResultRejected := []*btcjson.TestMempoolAcceptResult{
		{
			Allowed:      false,
			RejectReason: errInsufficientFee.Error(),
		},
	}

	testCases := []struct {
		name        string
		rpcResult   []*btcjson.TestMempoolAcceptResult
		rpcErr      error
		expectedErr error
	}{
		{
			name:        "accepted",
			rpcResult:   mempoolAcceptResultAllowed,
			rpcErr:      nil,
			expectedErr: nil,
		},
		{
			name:        "rejected",
			rpcResult:   mempoolAcceptResultRejected,
			rpcErr:      nil,
			expectedErr: errInsufficientFee,
		},
		{
			name:        "rpc error",
			rpcResult:   nil,
			rpcErr:      errRpc,
			expectedErr: errRpc,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w, m := testWalletWithMocks(t)

			m.chain.On("TestMempoolAccept",
				mock.Anything, mock.Anything,
			).Return(tc.rpcResult, tc.rpcErr)

			// We only need to mock the MapRPCErr function if the
			// RPC call is expected to succeed but the tx is
			// rejected.
			if tc.rpcErr == nil && !tc.rpcResult[0].Allowed {
				m.chain.On("MapRPCErr",
					mock.Anything,
				).Return(errInsufficientFee)
			}

			err := w.CheckMempoolAcceptance(ctx, tx)
			require.ErrorIs(t, err, tc.expectedErr)
		})
	}
}

// TestCheckMempool tests the checkMempool helper function.
func TestCheckMempool(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tx := &wire.MsgTx{}

	testCases := []struct {
		name             string
		mempoolAcceptErr error
		expectedErr      error
		expectWrappedErr bool
		rejectionReason  string
		mapRPCErr        func(error) error
	}{
		{
			name:             "accepted",
			mempoolAcceptErr: nil,
			expectedErr:      nil,
		},
		{
			name:             "already in mempool",
			mempoolAcceptErr: chain.ErrTxAlreadyInMempool,
			expectedErr:      errAlreadyBroadcasted,
		},
		{
			name:             "already known",
			mempoolAcceptErr: chain.ErrTxAlreadyKnown,
			expectedErr:      errAlreadyBroadcasted,
		},
		{
			name:             "already confirmed",
			mempoolAcceptErr: chain.ErrTxAlreadyConfirmed,
			expectedErr:      errAlreadyBroadcasted,
		},
		{
			name:             "backend version",
			mempoolAcceptErr: rpcclient.ErrBackendVersion,
			expectedErr:      nil,
		},
		{
			name:             "unimplemented",
			mempoolAcceptErr: chain.ErrUnimplemented,
			expectedErr:      nil,
		},
		{
			name:             "rejected",
			mempoolAcceptErr: errDummy,
			expectedErr:      errDummy,
			expectWrappedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w, m := testWalletWithMocks(t)

			// Setup the mock for TestMempoolAccept.
			if tc.mempoolAcceptErr == nil {
				m.chain.On("TestMempoolAccept",
					mock.Anything, mock.Anything,
				).Return([]*btcjson.TestMempoolAcceptResult{
					{Allowed: true},
				}, nil)
			} else {
				m.chain.On("TestMempoolAccept",
					mock.Anything, mock.Anything,
				).Return(nil, tc.mempoolAcceptErr)
			}

			err := w.checkMempool(ctx, tx)
			require.ErrorIs(t, err, tc.expectedErr)
		})
	}
}
