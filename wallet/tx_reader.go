// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/pkg/btcunit"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

var (
	// ErrTxNotFound is returned when a transaction is not found in the
	// store.
	ErrTxNotFound = errors.New("tx not found")

	// errNilTxDetailMsgTx is returned when a store detail row violates the
	// TxDetailInfo contract and omits the parsed transaction.
	errNilTxDetailMsgTx = errors.New("tx detail MsgTx is nil")
)

// TxReader provides an interface for querying tx history.
type TxReader interface {
	// GetTx returns a detailed description of a tx given its tx hash.
	GetTx(ctx context.Context, txHash chainhash.Hash) (*TxDetail, error)

	// ListTxns returns detailed transaction views over a block range.
	ListTxns(ctx context.Context, startHeight, endHeight int32) (
		[]*TxDetail, error)
}

// A compile-time assertion to ensure that Wallet implements the TxReader
// interface.
var _ TxReader = (*Wallet)(nil)

// Output contains details for a tx output.
type Output struct {
	// Addresses are the addresses associated with the output script.
	Addresses []address.Address

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

	// Status is the wallet-relative validity state of the transaction
	// (published, pending, failed, replaced, or orphaned). Retained
	// invalid transactions surface their state here so callers can
	// distinguish them from ordinary unconfirmed transactions.
	Status db.TxStatus
}

// GetTx returns a detailed description of a tx given its tx hash.
//
// NOTE: This method is part of the TxReader interface.
func (w *Wallet) GetTx(ctx context.Context, txHash chainhash.Hash) (
	*TxDetail, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	//nolint:contextcheck // SyncedTo takes no context.
	currentHeight := w.SyncedTo().Height

	return w.getTxDetail(ctx, txHash, currentHeight)
}

// ListTxns returns detailed transaction views over a block range.
//
// NOTE: This method is part of the TxReader interface.
func (w *Wallet) ListTxns(ctx context.Context, startHeight, endHeight int32) (
	[]*TxDetail, error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	//nolint:contextcheck // SyncedTo takes no context.
	currentHeight := w.SyncedTo().Height

	return w.listTxDetails(ctx, startHeight, endHeight, currentHeight)
}

// getTxDetail loads one transaction through the detailed store path and builds
// the full wallet response.
func (w *Wallet) getTxDetail(ctx context.Context, txHash chainhash.Hash,
	currentHeight int32) (*TxDetail, error) {

	txDetails, err := w.store.GetTxDetail(ctx, db.GetTxDetailQuery{
		WalletID: w.id,
		Txid:     txHash,
	})
	if err != nil {
		if errors.Is(err, db.ErrTxNotFound) {
			return nil, ErrTxNotFound
		}

		return nil, fmt.Errorf("get tx detail: %w", err)
	}

	return w.buildTxDetailFromStore(txDetails, currentHeight)
}

// listTxDetails loads detailed transactions over the requested wallet range and
// builds full wallet responses.
func (w *Wallet) listTxDetails(ctx context.Context, startHeight,
	endHeight int32, currentHeight int32) ([]*TxDetail, error) {

	records, err := w.store.ListTxDetails(ctx, db.ListTxDetailsQuery{
		WalletID:    w.id,
		StartHeight: startHeight,
		EndHeight:   endHeight,
	})
	if err != nil {
		return nil, fmt.Errorf("list tx details: %w", err)
	}

	details := make([]*TxDetail, 0, len(records))
	for i := range records {
		txDetail, err := w.buildTxDetailFromStore(&records[i], currentHeight)
		if err != nil {
			return nil, err
		}

		details = append(details, txDetail)
	}

	return details, nil
}

// buildTxDetailFromStore builds a wallet tx response from the db-native detail
// shape returned by db.Store.
func (w *Wallet) buildTxDetailFromStore(txDetails *db.TxDetailInfo,
	currentHeight int32) (*TxDetail, error) {

	if txDetails.MsgTx == nil {
		return nil, errNilTxDetailMsgTx
	}

	msgTx := txDetails.MsgTx

	details := buildBasicTxDetail(
		txDetails.Hash, txDetails.SerializedTx, txDetails.Label,
		txDetails.Received, msgTx,
	)

	// Carry the wallet-relative validity state through so retained
	// failed/replaced/orphaned transactions are not surfaced as ordinary
	// unconfirmed transactions.
	details.Status = txDetails.Status

	w.populateBlockDetails(details, txDetails.Block, currentHeight)
	w.calculateValueAndFeeFromStore(details, txDetails, msgTx)
	w.populateOutputs(details, msgTx, txDetails.OwnedOutputs)
	w.populatePrevOuts(details, msgTx, txDetails.OwnedInputs)

	return details, nil
}

// buildBasicTxDetail builds the common non-wallet-relative fields for one tx
// response.
func buildBasicTxDetail(hash chainhash.Hash, rawTx []byte, label string,
	received time.Time, msgTx *wire.MsgTx) *TxDetail {

	txWeight := blockchain.GetTransactionWeight(
		btcutil.NewTx(msgTx),
	)

	return &TxDetail{
		Hash:         hash,
		RawTx:        rawTx,
		Label:        label,
		ReceivedTime: received,
		Weight:       safeInt64ToWeightUnit(txWeight),
		FeeRate:      btcunit.ZeroSatPerVByte,
	}
}

// populateBlockDetails populates the block details for the given TxDetail.
func (w *Wallet) populateBlockDetails(details *TxDetail, block *db.Block,
	currentHeight int32) {

	if block == nil {
		return
	}

	height, ok := safeUint32ToInt32(block.Height)
	if !ok {
		log.Warnf("Block height %d out of int32 range", block.Height)

		return
	}

	details.Block = &BlockDetails{
		Hash:      block.Hash,
		Height:    height,
		Timestamp: block.Timestamp.Unix(),
	}

	details.Confirmations = calcConf(height, currentHeight)
}

// calculateValueAndFeeFromStore calculates the value and fee for the given
// store-backed TxDetail.
func (w *Wallet) calculateValueAndFeeFromStore(details *TxDetail,
	txDetails *db.TxDetailInfo, msgTx *wire.MsgTx) {

	var balanceDelta btcutil.Amount
	for _, debit := range txDetails.OwnedInputs {
		balanceDelta -= debit.Amount
	}

	for _, credit := range txDetails.OwnedOutputs {
		balanceDelta += credit.Amount
	}

	details.Value = balanceDelta

	// If not all inputs are ours, we can't calculate the total fee because
	// external input values are unknown.
	if len(txDetails.OwnedInputs) != len(msgTx.TxIn) {
		return
	}

	var totalInput btcutil.Amount
	for _, debit := range txDetails.OwnedInputs {
		totalInput += debit.Amount
	}

	var totalOutput btcutil.Amount
	for _, txOut := range msgTx.TxOut {
		totalOutput += btcutil.Amount(txOut.Value)
	}

	details.Fee = totalInput - totalOutput
	details.FeeRate = btcunit.CalcSatPerVByte(
		details.Fee, details.Weight.ToVB(),
	)
}

// populateOutputs populates outputs for a store-backed TxDetail.
func (w *Wallet) populateOutputs(details *TxDetail, msgTx *wire.MsgTx,
	ownedOutputs []db.TxOwnedOutput) {

	isOurAddress := make(map[uint32]bool)
	for _, credit := range ownedOutputs {
		isOurAddress[credit.Index] = true
	}

	for i, txOut := range msgTx.TxOut {
		sc, outAddresses, _, err := txscript.ExtractPkScriptAddrs(
			txOut.PkScript, w.cfg.ChainParams,
		)

		var addresses []address.Address
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

		details.Outputs = append(details.Outputs, Output{
			Type:      sc,
			Addresses: addresses,
			PkScript:  txOut.PkScript,
			Index:     i,
			Amount:    btcutil.Amount(txOut.Value),
			IsOurs:    isOurAddress[idx],
		})
	}
}

// populatePrevOuts populates prevouts for a store-backed TxDetail.
func (w *Wallet) populatePrevOuts(details *TxDetail, msgTx *wire.MsgTx,
	ownedInputs []db.TxOwnedInput) {

	isOurOutput := make(map[uint32]bool)
	for _, debit := range ownedInputs {
		isOurOutput[debit.Index] = true
	}

	for i, txIn := range msgTx.TxIn {
		idx, ok := safeIntToUint32(i)
		if !ok {
			log.Warnf("Input index %d out of uint32 range", i)
			continue
		}

		details.PrevOuts = append(details.PrevOuts, PrevOut{
			OutPoint: txIn.PreviousOutPoint,
			IsOurs:   isOurOutput[idx],
		})
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

// safeUint32ToInt32 converts a uint32 to an int32, returning false if the
// conversion would overflow.
func safeUint32ToInt32(u uint32) (int32, bool) {
	if u > math.MaxInt32 {
		return 0, false
	}

	return int32(u), true
}
