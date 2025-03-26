// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package txrules provides transaction rules that should be followed by
// transaction authors for wide mempool acceptance and quick mining.
package txrules

import (
	"errors"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// DefaultRelayFeePerKb is the default minimum relay fee policy for a mempool.
const DefaultRelayFeePerKb btcutil.Amount = 1e3

// IsDustOutput determines whether a transaction output is considered dust.
// Transactions with dust outputs are not standard and are rejected by mempools
// with default policies.
func IsDustOutput(output *wire.TxOut, relayFeePerKb btcutil.Amount) bool {
	// Unspendable outputs which solely carry data are not checked for dust.
	if txscript.GetScriptClass(output.PkScript) == txscript.NullDataTy {
		return false
	}

	return mempool.IsDust(output, relayFeePerKb)
}

// Transaction rule violations
var (
	ErrAmountNegative   = errors.New("transaction output amount is negative")
	ErrAmountExceedsMax = errors.New("transaction output amount exceeds maximum value")
	ErrOutputIsDust     = errors.New("transaction output is dust")
)

// CheckOutput performs simple consensus and policy tests on a transaction
// output.
func CheckOutput(output *wire.TxOut, relayFeePerKb btcutil.Amount, allowDust bool) error {
	if output.Value < 0 {
		return ErrAmountNegative
	}
	if output.Value > btcutil.MaxSatoshi {
		return ErrAmountExceedsMax
	}
	if !allowDust && IsDustOutput(output, relayFeePerKb) {
		return ErrOutputIsDust
	}
	return nil
}

// FeeForSerializeSize calculates the required fee for a transaction of some
// arbitrary size given a mempool's relay fee policy.
func FeeForSerializeSize(relayFeePerKb btcutil.Amount, txSerializeSize int) btcutil.Amount {
	fee := relayFeePerKb * btcutil.Amount(txSerializeSize) / 1000

	if fee == 0 && relayFeePerKb > 0 {
		fee = relayFeePerKb
	}

	if fee < 0 || fee > btcutil.MaxSatoshi {
		fee = btcutil.MaxSatoshi
	}

	return fee
}
