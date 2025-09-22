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
	// errMempoolAccept is a sentinel error used to indicate that the
	// mempool acceptance test returned an unexpected number of results.
	errMempoolAccept = errors.New(
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
