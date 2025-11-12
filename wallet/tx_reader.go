// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/pkg/btcunit"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
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

// A compile-time assertion to ensure that Wallet implements the TxReader
// interface.
var _ TxReader = (*Wallet)(nil)

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
	FeeRate btcunit.SatPerVByte

	// Weight is the tx's weight.
	Weight btcunit.WeightUnit

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

// GetTx returns a detailed description of a tx given its tx hash.
//
// NOTE: This method is part of the TxReader interface.
//
// Time complexity: O(log n + I + O), where n is the number of
// transactions in the database, I is the number of inputs, and O is the
// number of outputs. The lookup is dominated by a key-based B-tree lookup
// in the database and the processing of the transaction's inputs and
// outputs.
func (w *Wallet) GetTx(_ context.Context, txHash chainhash.Hash) (
	*TxDetail, error) {

	txDetails, err := w.fetchTxDetails(&txHash)
	if err != nil {
		return nil, err
	}

	bestBlock := w.SyncedTo()
	currentHeight := bestBlock.Height

	return w.buildTxDetail(txDetails, currentHeight), nil
}

// ListTxns returns a list of all txns which are relevant to the
// wallet over a given block range. The block range is inclusive of the
// start and end heights.
//
// The underlying transaction store allows for reverse iteration, so if
// startHeight > endHeight, the transactions will be returned in reverse
// order.
//
// The special height -1 may be used to include unmined transactions. For
// example, to get all transactions from block 100 to the current tip including
// unmined, use a startHeight of 100 and an endHeight of -1. To get all
// transactions in the wallet, use a startHeight of 0 and an endHeight of -1.
//
// NOTE: This method is part of the TxReader interface.
//
// Time complexity: O(B + N), where B is the number of blocks in the
// range and N is the total number of inputs and outputs across all
// transactions in the range.
func (w *Wallet) ListTxns(_ context.Context, startHeight,
	endHeight int32) ([]*TxDetail, error) {

	bestBlock := w.SyncedTo()
	currentHeight := bestBlock.Height

	// We'll first fetch all the transaction records from the database
	// within a single database transaction. This is done to minimize the
	// time we hold the database lock.
	var records []wtxmgr.TxDetails

	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

		err := w.txStore.RangeTransactions(
			txmgrNs, startHeight, endHeight,
			func(d []wtxmgr.TxDetails) (bool, error) {
				records = append(records, d...)

				return false, nil
			},
		)
		if err != nil {
			return fmt.Errorf("tx range failed: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to view wallet db: %w", err)
	}

	// Now that we have all the records, we can build the detailed
	// response without holding the database lock.
	details := make([]*TxDetail, 0, len(records))
	for _, detail := range records {
		txDetail := w.buildTxDetail(&detail, currentHeight)
		details = append(details, txDetail)
	}

	return details, nil
}

// fetchTxDetails fetches the tx details for the given tx hash
// from the wallet's tx store.
func (w *Wallet) fetchTxDetails(txHash *chainhash.Hash) (
	*wtxmgr.TxDetails, error) {

	var txDetails *wtxmgr.TxDetails

	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

		var err error

		txDetails, err = w.txStore.TxDetails(txmgrNs, txHash)
		if err != nil {
			return fmt.Errorf("failed to fetch tx details: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to view wallet db: %w", err)
	}

	// TxDetails will return nil when the tx is not found.
	//
	// TODO(yy): We should instead return an error when the tx cannot be
	// found in the db.
	if txDetails == nil {
		return nil, ErrTxNotFound
	}

	return txDetails, nil
}

// buildTxDetail builds a TxDetail from the given wtxmgr.TxDetails.
func (w *Wallet) buildTxDetail(txDetails *wtxmgr.TxDetails,
	currentHeight int32) *TxDetail {

	details := w.buildBasicTxDetail(txDetails)

	w.populateBlockDetails(details, txDetails, currentHeight)
	w.calculateValueAndFee(details, txDetails)
	w.populateOutputs(details, txDetails)
	w.populatePrevOuts(details, txDetails)

	return details
}

// buildBasicTxDetail builds the basic TxDetail from the given wtxmgr.TxDetails.
func (w *Wallet) buildBasicTxDetail(txDetails *wtxmgr.TxDetails) *TxDetail {
	txWeight := blockchain.GetTransactionWeight(
		btcutil.NewTx(&txDetails.MsgTx),
	)

	return &TxDetail{
		Hash:         txDetails.Hash,
		RawTx:        txDetails.SerializedTx,
		Label:        txDetails.Label,
		ReceivedTime: txDetails.Received,
		Weight:       safeInt64ToWeightUnit(txWeight),
		FeeRate:      btcunit.SatPerVByte{Rat: big.NewRat(0, 1)},
	}
}

// populateBlockDetails populates the block details for the given TxDetail.
func (w *Wallet) populateBlockDetails(details *TxDetail,
	txDetails *wtxmgr.TxDetails, currentHeight int32) {

	height := txDetails.Block.Height
	if height == -1 {
		return
	}

	details.Block = &BlockDetails{
		Hash:      txDetails.Block.Hash,
		Height:    txDetails.Block.Height,
		Timestamp: txDetails.Block.Time.Unix(),
	}

	details.Confirmations = calcConf(height, currentHeight)
}

// calculateValueAndFee calculates the value and fee for the given TxDetail.
func (w *Wallet) calculateValueAndFee(details *TxDetail,
	txDetails *wtxmgr.TxDetails) {

	var balanceDelta btcutil.Amount
	for _, debit := range txDetails.Debits {
		balanceDelta -= debit.Amount
	}

	for _, credit := range txDetails.Credits {
		balanceDelta += credit.Amount
	}

	details.Value = balanceDelta

	// If not all inputs are ours, we can't calculate the total fee.
	// txDetails.Debits contains only our inputs, while
	// txDetails.MsgTx.TxIn contains all inputs. If they differ, some
	// inputs belong to external wallets and we don't know their input
	// values.
	if len(txDetails.Debits) != len(txDetails.MsgTx.TxIn) {
		return
	}

	var totalInput btcutil.Amount
	for _, debit := range txDetails.Debits {
		totalInput += debit.Amount
	}

	var totalOutput btcutil.Amount
	for _, txOut := range txDetails.MsgTx.TxOut {
		totalOutput += btcutil.Amount(txOut.Value)
	}

	details.Fee = totalInput - totalOutput
	details.FeeRate = btcunit.NewSatPerVByte(
		details.Fee, details.Weight.ToVB(),
	)
}

// populateOutputs populates the outputs for the given TxDetail.
func (w *Wallet) populateOutputs(details *TxDetail,
	txDetails *wtxmgr.TxDetails) {

	isOurAddress := make(map[uint32]bool)
	for _, credit := range txDetails.Credits {
		isOurAddress[credit.Index] = true
	}

	for i, txOut := range txDetails.MsgTx.TxOut {
		sc, outAddresses, _, err := txscript.ExtractPkScriptAddrs(
			txOut.PkScript, w.chainParams,
		)

		var addresses []btcutil.Address
		if err != nil {
			log.Warnf("Cannot extract addresses from pkScript for "+
				"tx %v, output %d: %v", details.Hash, i, err)
		} else {
			addresses = outAddresses
		}

		idx, ok := safeIntToUint32(i)
		if !ok {
			log.Warnf("Output index %d out of uint32 range", i)
			continue
		}

		details.Outputs = append(
			details.Outputs, Output{
				Type:      sc,
				Addresses: addresses,
				PkScript:  txOut.PkScript,
				Index:     i,
				Amount:    btcutil.Amount(txOut.Value),
				IsOurs:    isOurAddress[idx],
			},
		)
	}
}

// populatePrevOuts populates the previous outputs for the given TxDetail.
func (w *Wallet) populatePrevOuts(details *TxDetail,
	txDetails *wtxmgr.TxDetails) {

	isOurOutput := make(map[uint32]bool)
	for _, debit := range txDetails.Debits {
		isOurOutput[debit.Index] = true
	}

	for i, txIn := range txDetails.MsgTx.TxIn {
		idx, ok := safeIntToUint32(i)
		if !ok {
			log.Warnf("Input index %d out of uint32 range", i)
			continue
		}

		details.PrevOuts = append(
			details.PrevOuts, PrevOut{
				OutPoint: txIn.PreviousOutPoint,
				IsOurs:   isOurOutput[idx],
			},
		)
	}
}

// safeInt64ToWeightUnit converts an int64 to a unit.WeightUnit, ensuring the
// value is non-negative.
func safeInt64ToWeightUnit(w int64) btcunit.WeightUnit {
	if w < 0 {
		return btcunit.NewWeightUnit(0)
	}

	return btcunit.NewWeightUnit(uint64(w))
}

// safeIntToUint32 converts an int to a uint32, returning false if the
// conversion would overflow.
func safeIntToUint32(i int) (uint32, bool) {
	if i < 0 || i > math.MaxUint32 {
		return 0, false
	}

	return uint32(i), true
}
