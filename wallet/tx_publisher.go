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
	"fmt"

	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/chain"
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

var (
	// errAlreadyBroadcasted is a sentinel error used to indicate that a tx
	// has already been broadcast.
	errAlreadyBroadcasted = errors.New("tx already broadcasted")
)

// checkMempool is a helper function that checks if a tx is acceptable to the
// mempool before broadcasting.
func (w *Wallet) checkMempool(ctx context.Context,
	tx *wire.MsgTx) error {

	// We'll start by checking if the tx is acceptable to the mempool.
	err := w.CheckMempoolAcceptance(ctx, tx)

	switch {
	// If the tx is already in the mempool or confirmed, we can return
	// early.
	case errors.Is(err, chain.ErrTxAlreadyInMempool),
		errors.Is(err, chain.ErrTxAlreadyKnown),
		errors.Is(err, chain.ErrTxAlreadyConfirmed):

		log.Infof("Tx %v already broadcasted", tx.TxHash())

		// TODO(yy): Add a new method UpdateTxLabel to allow updating
		// the label of a tx. With this change, the label passed in
		// will be ignored if the tx is already known.
		return errAlreadyBroadcasted

	// If the backend does not support the mempool acceptance test, we'll
	// just attempt to publish the tx.
	case errors.Is(err, rpcclient.ErrBackendVersion),
		errors.Is(err, chain.ErrUnimplemented):

		log.Warnf("Backend does not support mempool acceptance test, "+
			"broadcasting directly: %v", err)

		return nil

	// If the tx was rejected for any other reason, we'll return the error
	// directly.
	case err != nil:
		return fmt.Errorf("tx rejected by mempool: %w", err)

	// Otherwise, the tx is valid and we can publish it.
	default:
		return nil
	}
}
