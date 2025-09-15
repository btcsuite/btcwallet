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

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
)

var (
	// ErrManualInputsEmpty is returned when manual inputs are specified but
	// the list is empty.
	ErrManualInputsEmpty = errors.New("manual inputs cannot be empty")

	// ErrDuplicatedUtxo is returned when a UTXO is specified multiple
	// times.
	ErrDuplicatedUtxo = errors.New("duplicated utxo")
)

// TxCreator provides an interface for creating transactions. Its primary
// role is to produce a fully-formed, unsigned transaction that can be passed
// to the Signer interface.
type TxCreator interface {
	// CreateTransaction creates a new, unsigned transaction based on the
	// provided intent. The resulting AuthoredTx will contain the unsigned
	// transaction and all the necessary metadata to sign it.
	CreateTransaction(ctx context.Context, intent *TxIntent) (
		*txauthor.AuthoredTx, error)
}

// SatPerKVByte is a type that represents a fee rate in satoshis per
// kilo-virtual-byte. This is the standard unit for fee estimation in modern
// Bitcoin transactions that use SegWit.
type SatPerKVByte btcutil.Amount

// TxIntent represents the user's intent to create a transaction. It serves as
// a blueprint for the TxCreator, bundling all the parameters required to
// construct a transaction into a single, coherent structure.
//
// A TxIntent can be used to create a transaction in four main ways:
//
// 1. Automatic Coin Selection from the Default Account:
// The simplest way to create a transaction is to specify only the outputs
// and the fee rate. By leaving the `Inputs` field as nil, the wallet will
// automatically select coins from the default account to fund the
// transaction.
//
// Example:
//
//	intent := &TxIntent{
//		Outputs: outputs,
//		FeeRate: feeRate,
//	}
//
// 2. Manual Input Selection:
// To have direct control over the inputs used, the caller can specify the
// exact UTXOs to spend. This is achieved by setting the `Inputs` field to
// an `InputsManual` struct, which contains a slice of the desired
// `wire.OutPoint`s. In this mode, all coin selection logic is bypassed; the
// wallet simply uses the provided inputs.
//
// Example:
//
//	intent := &TxIntent{
//		Outputs:      outputs,
//		Inputs:       &InputsManual{UTXOs: []wire.OutPoint{...}},
//		FeeRate:      feeRate,
//		ChangeSource: changeSource,
//	}
//
// 3. Policy-Based Coin Selection from an Account:
// To have the wallet select inputs from a specific account, the caller can
// specify a policy. This is achieved by setting the `Inputs` field to an
// `InputsPolicy` struct. This struct defines the strategy (e.g.,
// largest-first), the minimum number of confirmations, and the source of
// the coins. If the `Source` is a `ScopedAccount`, the wallet will select
// coins from that account. If the `Source` field is nil, the wallet will
// use a default source, typically the default account.
//
// Example:
//
//	intent := &TxIntent{
//		Outputs: outputs,
//		Inputs: &InputsPolicy{
//			Strategy: CoinSelectionLargest,
//			MinConfs: 1,
//			Source:   &ScopedAccount{AccountName: "default", ...},
//		},
//		FeeRate:      feeRate,
//		ChangeSource: changeSource,
//	}
//
// 4. Policy-Based Coin Selection from a specific set of UTXOs:
// For more advanced control, the caller can provide a specific list of UTXOs
// and have the coin selection algorithm choose the best subset from that
// list. This is useful for scenarios like coin control where the user wants
// to limit the potential inputs for a transaction. This is achieved by
// setting the `Source` of an `InputsPolicy` to a `CoinSourceUTXOs` struct.
//
// Example:
//
//	intent := &TxIntent{
//		Outputs: outputs,
//		Inputs: &InputsPolicy{
//			Strategy: CoinSelectionLargest,
//			MinConfs: 1,
//			Source: &CoinSourceUTXOs{
//				UTXOs: []wire.OutPoint{...},
//			},
//		},
//		FeeRate:      feeRate,
//		ChangeSource: changeSource,
//	}
type TxIntent struct {
	// Outputs specifies the recipients and amounts for the transaction.
	// This field is required.
	Outputs []wire.TxOut

	// Inputs defines the source of the inputs for the transaction. This
	// must be one of the Inputs implementations (InputsManual or
	// InputsPolicy). This field is required.
	Inputs Inputs

	// ChangeSource specifies the destination for the transaction's change
	// output. If this field is nil, the wallet will use a default change
	// source based on the account and scope of the inputs.
	ChangeSource *ScopedAccount

	// FeeRate specifies the desired fee rate for the transaction,
	// expressed in satoshis per kilo-virtual-byte (sat/kvb). This field is
	// required.
	FeeRate SatPerKVByte

	// Label is an optional, human-readable label for the transaction. This
	// can be used to associate a memo with the transaction for later
	// reference.
	Label string
}

// Inputs is a sealed interface that defines the source of inputs for a
// transaction. It can either be a manually specified set of UTXOs or a policy
// for coin selection. The sealed interface pattern is used here to
// provide compile-time safety, ensuring that only the intended implementations
// can be used.
type Inputs interface {
	// isInputs is a marker method that is part of the sealed interface
	// pattern. It is unexported, so it can only be implemented by types
	// within this package. This ensures that only the intended types
	// can be used as an Inputs implementation.
	isInputs()
}

// InputsManual implements the Inputs interface and specifies the exact UTXOs
// to be used as transaction inputs. When this is used, all automatic coin
// selection logic is bypassed.
type InputsManual struct {
	// UTXOs is a slice of outpoints to be used as the exact inputs for the
	// transaction. The wallet will validate that these UTXOs are known and
	// spendable but will not perform any further coin selection.
	UTXOs []wire.OutPoint
}

// InputsPolicy implements the Inputs interface and specifies the policy
// for coin selection by the wallet.
type InputsPolicy struct {
	// Strategy is the algorithm to use for selecting coins (e.g., largest
	// first, random). If this is nil, the wallet's default coin selection
	// strategy will be used.
	Strategy CoinSelectionStrategy

	// MinConfs is the minimum number of confirmations a UTXO must have to
	// be considered eligible for coin selection.
	MinConfs uint32

	// Source specifies the pool of UTXOs to select from. If this is nil,
	// the wallet will use a default source (e.g., the default account).
	// Otherwise, this must be one of the CoinSource implementations.
	Source CoinSource
}

// isInputs marks InputsManual as an implementation of the Inputs interface.
func (*InputsManual) isInputs() {}

// isInputs marks InputsPolicy as an implementation of the Inputs
// interface.
func (*InputsPolicy) isInputs() {}

// A compile-time assertion to ensure that all types implementing the Inputs
// interface adhere to it.
var _ Inputs = (*InputsManual)(nil)
var _ Inputs = (*InputsPolicy)(nil)

// CoinSource is a sealed interface that defines the pool of UTXOs available
// for coin selection. The sealed interface pattern ensures that only
// the intended implementations can be used.
type CoinSource interface {
	// isCoinSource is a marker method that is part of the sealed interface
	// pattern. It is unexported, so it can only be implemented by types
	// within this package. This ensures that only the intended types
	// can be used as a CoinSource implementation.
	isCoinSource()
}

// ScopedAccount defines a wallet account within a particular key scope. It is
// used to specify the source of funds for coin selection and the
// destination for change outputs.
type ScopedAccount struct {
	// AccountName specifies the name of the account. This must be a
	// non-empty string.
	AccountName string

	// KeyScope specifies the key scope (e.g., P2WKH, P2TR).
	KeyScope waddrmgr.KeyScope
}

// CoinSourceUTXOs specifies that the wallet should select coins from a
// specific, predefined list of candidate UTXOs.
type CoinSourceUTXOs struct {
	// UTXOs is a slice of outpoints from which the coin selection
	// algorithm will choose. This list must not be empty.
	UTXOs []wire.OutPoint
}

// isCoinSource marks ScopedAccount as an implementation of the CoinSource
// interface.
func (ScopedAccount) isCoinSource() {}

// isCoinSource marks CoinSourceUTXOs as an implementation of the CoinSource
// interface.
func (CoinSourceUTXOs) isCoinSource() {}

// validateOutPoints checks a slice of `wire.OutPoint`s for emptiness and
// duplicate entries. It returns `ErrManualInputsEmpty` if the slice is empty
// and `ErrDuplicatedUtxo` if any duplicates are found.
func validateOutPoints(outpoints []wire.OutPoint) error {
	if len(outpoints) == 0 {
		return ErrManualInputsEmpty
	}

	seenUTXOs := make(map[wire.OutPoint]struct{})
	for _, utxo := range outpoints {
		if _, ok := seenUTXOs[utxo]; ok {
			return ErrDuplicatedUtxo
		}

		seenUTXOs[utxo] = struct{}{}
	}

	return nil
}

// A compile-time assertion to ensure that all types implementing the CoinSource
// interface adhere to it.
var _ CoinSource = (*ScopedAccount)(nil)
var _ CoinSource = (*CoinSourceUTXOs)(nil)
