// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package wallet provides a bitcoin wallet implementation that is ready for
// use.
//
// TODO(yy): bring wrapcheck back when implementing the `Store` interface.
//
//nolint:wrapcheck
package wallet

import (
	"context"
	"errors"

	"github.com/btcsuite/btcd/wire"
)

var (
	// ErrMempoolAccept is a sentinel error used to indicate that the
	// mempool acceptance test returned an unexpected number of results.
	ErrMempoolAccept = errors.New(
		"expected 1 result from TestMempoolAccept",
	)
)

// TxPublisher provides an interface for publishing transactions.
type TxPublisher interface {
	// CheckMempoolAcceptance checks if a transaction would be accepted by
	// the mempool without broadcasting.
	CheckMempoolAcceptance(ctx context.Context, tx *wire.MsgTx) error

	// Broadcast broadcasts a transaction to the network.
	Broadcast(ctx context.Context, tx *wire.MsgTx, label string) error
}

// CheckMempoolAcceptance checks if a transaction would be accepted by the
// mempool without broadcasting.
func (w *Wallet) CheckMempoolAcceptance(_ context.Context,
	tx *wire.MsgTx) error {

	// TODO(yy): thread context through.
	chainClient, err := w.requireChainClient()
	if err != nil {
		return err
	}

	// The TestMempoolAccept rpc expects a slice of transactions.
	txns := []*wire.MsgTx{tx}

	// Use a max feerate of 0 means the default value will be used when
	// testing mempool acceptance. The default max feerate is 0.10 BTC/kvb,
	// or 10,000 sat/vb.
	maxFeeRate := float64(0)

	results, err := chainClient.TestMempoolAccept(txns, maxFeeRate)
	if err != nil {
		return err
	}

	// Sanity check that the expected single result is returned.
	if len(results) != 1 {
		return ErrMempoolAccept
	}

	result := results[0]

	// If the transaction is allowed, we can return early.
	if result.Allowed {
		return nil
	}

	// Otherwise, we'll map the reason to a concrete error type and return
	// it.
	//
	//nolint:err113
	err = errors.New(result.RejectReason)

	return chainClient.MapRPCErr(err)
}
