// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"errors"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/unit"
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
	GetTx(ctx context.Context, txHash chainhash.Hash) (
		*TxDetail, error)

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
	// Type is the script class of the output.
	Type txscript.ScriptClass

	// Addresses are the addresses associated with the output script.
	Addresses []btcutil.Address

	// PkScript is the raw output script.
	PkScript []byte

	// Index is the index of the output in the tx.
	Index int

	// Amount is the value of the output.
	Amount btcutil.Amount

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

// FeeRate returns the fee rate of the tx in satoshis per virtual byte.
func (d *TxDetail) FeeRate() unit.SatPerVByte {
	return unit.NewSatPerVByte(d.Fee, d.Weight.ToVB())
}

// GetTx returns a detailed description of a tx given its tx hash.
//
// NOTE: This method is part of the TxReader interface.
//
// Time complexity: O(1) amortized. The lookup is dominated by a key-based
// B-tree lookup in the database, which is effectively constant time for any
// realistic number of transactions.
func (w *Wallet) GetTx(ctx context.Context, txHash chainhash.Hash) (
	*TxDetail, error) {

	txDetails, err := w.fetchTxDetails(&txHash)
	if err != nil {
		return nil, err
	}

	if txDetails == nil {
		return nil, ErrTxNotFound
	}

	bestBlock := w.SyncedTo()
	currentHeight := bestBlock.Height

	return w.buildTxDetail(txDetails, currentHeight), nil
}

// ListTxns returns a list of all txns which are relevant to the
// wallet over a given block range.
//
// NOTE: This method is part of the TxReader interface.
//
// Time complexity: O(B + T), where B is the number of blocks in the range and T
// is the number of transactions in those blocks.
func (w *Wallet) ListTxns(ctx context.Context, startHeight,
	endHeight int32) ([]*TxDetail, error) {

	bestBlock := w.SyncedTo()
	currentHeight := bestBlock.Height

	var details []*TxDetail
	err := walletdb.View(w.db, func(dbtx walletdb.ReadTx) error {
		txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

		err := w.txStore.RangeTransactions(
			txmgrNs, startHeight, endHeight,
			func(d []wtxmgr.TxDetails) (bool, error) {
				for i := range d {
					detail := &d[i]

					txDetail := w.buildTxDetail(
						detail, currentHeight,
					)
					details = append(details, txDetail)
				}
				return false, nil
			},
		)
		return err
	})
	if err != nil {
		return nil, err
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
		return err
	})

	return txDetails, err
}

// buildTxDetail builds a TxDetail from the given wtxmgr.TxDetails.
func (w *Wallet) buildTxDetail(txDetails *wtxmgr.TxDetails,
	currentHeight int32) *TxDetail {

	// Populate the details.
	details := &TxDetail{
		Hash:         txDetails.Hash,
		RawTx:        txDetails.SerializedTx,
		Label:        txDetails.Label,
		ReceivedTime: txDetails.Received,
		Weight: unit.WeightUnit(blockchain.GetTransactionWeight(
			btcutil.NewTx(&txDetails.MsgTx),
		)),
	}

	// If the tx is mined, we can calculate the confirmations and fill in
	// the block details.
	height := txDetails.Block.Height
	if height != -1 {
		details.Block = &BlockDetails{
			Hash:      txDetails.Block.Hash,
			Height:    txDetails.Block.Height,
			Timestamp: txDetails.Block.Time.Unix(),
		}

		// Confirmations are calculated as the current height minus the
		// block height, plus one. A tx in the current block has one
		// confirmation.
		details.Confirmations = currentHeight - height + 1
	}

	// Calculate the balance delta (value). This is the net amount of the
	// tx from the wallet's perspective. It is calculated as the sum of all
	// credits minus the sum of all debits.
	var balanceDelta btcutil.Amount
	for _, debit := range txDetails.Debits {
		balanceDelta -= debit.Amount
	}
	for _, credit := range txDetails.Credits {
		balanceDelta += credit.Amount
	}
	details.Value = balanceDelta

	// Calculate the fee. This is only possible if all inputs are ours, as
	// we don't know the value of external inputs.
	if len(txDetails.Debits) == len(txDetails.MsgTx.TxIn) {
		var totalInput btcutil.Amount
		for _, debit := range txDetails.Debits {
			totalInput += debit.Amount
		}

		var totalOutput btcutil.Amount
		for _, txOut := range txDetails.MsgTx.TxOut {
			totalOutput += btcutil.Amount(txOut.Value)
		}
		details.Fee = totalInput - totalOutput
	}

	// Create a map of output indices to booleans to efficiently check if an
	// output is ours.
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

		details.Outputs = append(
			details.Outputs, Output{
				Type:      sc,
				Addresses: addresses,
				PkScript:  txOut.PkScript,
				Index:     i,
				Amount:    btcutil.Amount(txOut.Value),
				IsOurs:    isOurAddress[uint32(i)],
			},
		)
	}

	// Create a map of input indices to booleans to efficiently check if an
	// input is ours.
	isOurOutput := make(map[uint32]bool)
	for _, debit := range txDetails.Debits {
		isOurOutput[debit.Index] = true
	}

	for idx, txIn := range txDetails.MsgTx.TxIn {
		details.PrevOuts = append(
			details.PrevOuts, PrevOut{
				OutPoint: txIn.PreviousOutPoint,
				IsOurs:   isOurOutput[uint32(idx)],
			},
		)
	}

	return details
}
