// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package wallet provides a bitcoin wallet implementation that is centered
// around the concept of a UtxoManager, which is responsible for managing the
// wallet's UTXO set.
//
// TODO(yy): bring wrapcheck back when implementing the `Store` interface.
//
//nolint:wrapcheck
package wallet

import (
	"context"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// Utxo provides a detailed overview of an unspent transaction output.
type Utxo struct {
	// OutPoint is the transaction output identifier.
	OutPoint wire.OutPoint

	// Amount is the value of the output.
	Amount btcutil.Amount

	// PkScript is the public key script for the output.
	PkScript []byte

	// Confirmations is the number of confirmations the output has.
	Confirmations int32

	// Spendable indicates whether the output is considered spendable.
	Spendable bool

	// Address is the address associated with the output.
	Address btcutil.Address

	// Account is the name of the account that owns the output.
	Account string

	// AddressType is the type of the address.
	AddressType waddrmgr.AddressType

	// Locked indicates whether the output is locked.
	Locked bool
}

// UtxoQuery holds the set of options for a ListUnspent query.
type UtxoQuery struct {
	// Account specifies the account to query UTXOs for. If empty,
	// UTXOs from all accounts are returned.
	Account string

	// MinConfs is the minimum number of confirmations a UTXO must have.
	MinConfs int32

	// MaxConfs is the maximum number of confirmations a UTXO can have.
	MaxConfs int32
}

// UtxoManager provides an interface for querying and managing the wallet's
// UTXO set.
type UtxoManager interface {
	// ListUnspent returns a slice of all unspent transaction outputs that
	// match the query.
	ListUnspent(ctx context.Context, query UtxoQuery) ([]*Utxo, error)

	// GetUtxoInfo returns the output information for a given outpoint.
	GetUtxoInfo(ctx context.Context, prevOut *wire.OutPoint) (*Utxo, error)

	// LeaseOutput locks an output for a given duration, preventing it from
	// being used in transactions.
	LeaseOutput(ctx context.Context, id wtxmgr.LockID,
		op wire.OutPoint, duration time.Duration) (time.Time, error)

	// ReleaseOutput unlocks a previously leased output, making it available
	// for use.
	ReleaseOutput(ctx context.Context, id wtxmgr.LockID,
		op wire.OutPoint) error

	// ListLeasedOutputs returns a list of all currently leased outputs.
	ListLeasedOutputs(ctx context.Context) ([]*ListLeasedOutputResult, error)
}

