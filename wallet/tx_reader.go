// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"errors"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/pkg/unit"
)

var (
	// ErrTxNotFound is returned when a transaction is not found in the
	// store.
	ErrTxNotFound = errors.New("tx not found")
)

// TxReader provides an interface for querying tx history.
type TxReader interface {
	// GetTx returns a detailed description of a tx given its tx hash.
	GetTx(ctx context.Context, txHash chainhash.Hash) (*TxDetail, error)

	// ListTxns returns a list of all txns which are relevant to the wallet
	// over a given block range.
	ListTxns(ctx context.Context, startHeight, endHeight int32) (
		[]*TxDetail, error)
}

// Output contains details for a tx output.
type Output struct {
	// Addresses are the addresses associated with the output script.
	Addresses []btcutil.Address

	// PkScript is the raw output script.
	PkScript []byte

	// Index is the index of the output in the tx.
	Index int

	// Amount is the value of the output.
	Amount btcutil.Amount

	// Type is the script class of the output.
	Type txscript.ScriptClass

	// IsOurs is true if the output is controlled by the wallet.
	IsOurs bool
}

// PrevOut describes a tx input.
type PrevOut struct {
	// OutPoint is the unique reference to the output being spent.
	OutPoint wire.OutPoint

	// IsOurs is true if the input spends an output controlled by the
	// wallet.
	IsOurs bool
}

// BlockDetails contains details about the block that includes a tx.
type BlockDetails struct {
	// Hash is the hash of the block.
	Hash chainhash.Hash

	// Height is the height of the block.
	Height int32

	// Timestamp is the unix timestamp of the block.
	Timestamp int64
}

// TxDetail describes a tx relevant to a wallet. This is a flattened
// and information-dense structure designed to be returned by the TxReader
// interface.
type TxDetail struct {
	// Hash is the tx hash.
	Hash chainhash.Hash

	// RawTx is the serialized tx.
	RawTx []byte

	// Value is the net value of this tx (in satoshis) from the
	// POV of the wallet.
	Value btcutil.Amount

	// Fee is the total fee in satoshis paid by this tx.
	//
	// NOTE: This is only calculated if all inputs are known to the wallet.
	// Otherwise, it will be zero.
	//
	// TODO(yy): This should also be calculated for txns with external
	// inputs. This requires adding a `GetRawTransaction` method to the
	// `chain.Interface`.
	Fee btcutil.Amount

	// FeeRate is the fee rate of the tx in sat/vbyte.
	//
	// NOTE: This is only calculated if all inputs are known to the wallet.
	// Otherwise, it will be zero.
	FeeRate unit.SatPerVByte

	// Weight is the tx's weight.
	Weight unit.WeightUnit

	// Confirmations is the number of confirmations this tx has.
	// This will be 0 for unconfirmed txns.
	Confirmations int32

	// Block contains details of the block that includes this tx.
	Block *BlockDetails

	// ReceivedTime is the time the tx was received by the wallet.
	ReceivedTime time.Time

	// Outputs contains data for each tx output.
	Outputs []Output

	// PrevOuts are the inputs for the tx.
	PrevOuts []PrevOut

	// Label is an optional tx label.
	Label string
}
