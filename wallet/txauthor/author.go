// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package txauthor provides transaction creation code for wallets.
package txauthor

import (
	"errors"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
)

// SumOutputValues sums up the list of TxOuts and returns an Amount.
//
// Deprecated: this sum is unchecked. It panics on a nil element, admits a
// negative or over-maximum value, and wraps silently on overflow. Use
// CheckOutputsAmount, which validates the set and returns the same total.
func SumOutputValues(outputs []*wire.TxOut) (totalOutput btcutil.Amount) {
	for _, txOut := range outputs {
		totalOutput += btcutil.Amount(txOut.Value)
	}
	return totalOutput
}

// InputSource provides transaction inputs referencing spendable outputs to
// construct a transaction outputting some target amount.  If the target amount
// can not be satisified, this can be signaled by returning a total amount less
// than the target or by returning a more detailed error implementing
// InputSourceError.
type InputSource func(target btcutil.Amount) (total btcutil.Amount, inputs []*wire.TxIn,
	inputValues []btcutil.Amount, scripts [][]byte, err error)

// InputSourceError describes the failure to provide enough input value from
// unspent transaction outputs to meet a target amount.  A typed error is used
// so input sources can provide their own implementations describing the reason
// for the error, for example, due to spendable policies or locked coins rather
// than the wallet not having enough available input value.
type InputSourceError interface {
	error
	InputSourceError()
}

// Default implementation of InputSourceError.
type insufficientFundsError struct{}

func (insufficientFundsError) InputSourceError() {}
func (insufficientFundsError) Error() string {
	return "insufficient funds available to construct transaction"
}

// AuthoredTx holds the state of a newly-created transaction and the change
// output (if one was added).
type AuthoredTx struct {
	Tx              *wire.MsgTx
	PrevScripts     [][]byte
	PrevInputValues []btcutil.Amount
	TotalInput      btcutil.Amount
	ChangeIndex     int // negative if no change
}

// ChangeSource provides change output scripts for transaction creation.
type ChangeSource struct {
	// NewScript is a closure that produces unique change output scripts per
	// invocation.
	NewScript func() ([]byte, error)

	// ScriptSize is the size in bytes of scripts produced by `NewScript`.
	ScriptSize int
}

// NewUnsignedTransaction creates an unsigned transaction paying to one or more
// non-change outputs.  An appropriate transaction fee is included based on the
// transaction size.
//
// Transaction inputs are chosen from repeated calls to fetchInputs with
// increasing targets amounts.
//
// If any remaining output value can be returned to the wallet via a change
// output without violating mempool dust rules, a P2WPKH change output is
// appended to the transaction outputs.  Since the change output may not be
// necessary, fetchChange is called zero or one times to generate this script.
// This function must return a P2WPKH script or smaller, otherwise fee estimation
// will be incorrect.
//
// If successful, the transaction, total input value spent, and all previous
// output scripts are returned.  If the input source was unable to provide
// enough input value to pay for every output any any necessary fees, an
// InputSourceError is returned.
//
// Every amount this function forms is checked. The output set is validated and
// the fee rate is rejected at or below zero before the first fetchInputs call,
// so a malformed request never reaches a callback. The per-iteration fee and
// change arithmetic depends on the inputs that were selected, so it necessarily
// follows input selection, but it still completes before changeSource.NewScript
// is called.
//
// It is SelectInputs followed by InputSelection.Complete, with the change
// script drawn from changeSource in between.
//
// BUGS: Fee estimation may be off when redeeming non-compressed P2PKH outputs.
func NewUnsignedTransaction(outputs []*wire.TxOut, feeRatePerKb btcutil.Amount,
	fetchInputs InputSource, changeSource *ChangeSource) (*AuthoredTx, error) {

	selection, err := SelectInputs(
		outputs, feeRatePerKb, fetchInputs, changeSource.ScriptSize,
	)
	if err != nil {
		return nil, err
	}

	changeScript, err := changeSource.NewScript()
	if err != nil {
		return nil, err
	}

	return selection.Complete(changeScript), nil
}

// InputSelection is a funded input set for a set of outputs, together with the
// value left over for change once the fee is paid. It is produced by
// SelectInputs before any change script exists, so a caller can obtain the
// change script however it likes and then finish the transaction with
// Complete.
type InputSelection struct {
	// outputs are the non-change outputs the inputs fund.
	outputs []*wire.TxOut

	// inputs are the selected transaction inputs.
	inputs []*wire.TxIn

	// prevScripts are the previous output scripts the inputs redeem.
	prevScripts [][]byte

	// prevInputValues are the previous output values the inputs redeem.
	prevInputValues []btcutil.Amount

	// totalInput is the sum of prevInputValues.
	totalInput btcutil.Amount

	// changeAmount is the value left for change after paying for every
	// output and a fee that assumes a change output is present.
	changeAmount btcutil.Amount
}

// SelectInputs chooses inputs that pay for outputs and a fee at feeRatePerKb,
// sizing the fee as though a change output whose script is changeScriptSize
// bytes is present. Transaction inputs are chosen from repeated calls to
// fetchInputs with increasing target amounts.
//
// The output set is validated and the fee rate is rejected at or below zero
// before the first fetchInputs call, so a malformed request never reaches the
// callback. If the input source was unable to provide enough input value to pay
// for every output and any necessary fees, an InputSourceError is returned.
//
// BUGS: Fee estimation may be off when redeeming non-compressed P2PKH outputs.
func SelectInputs(outputs []*wire.TxOut, feeRatePerKb btcutil.Amount,
	fetchInputs InputSource, changeScriptSize int) (*InputSelection, error) {

	targetAmount, err := CheckOutputsAmount(outputs)
	if err != nil {
		return nil, err
	}

	estimatedSize := txsizes.EstimateVirtualSize(
		0, 0, 1, 0, outputs, changeScriptSize,
	)

	targetFee, err := CheckedFeeForSerializeSize(
		feeRatePerKb, estimatedSize,
	)
	if err != nil {
		return nil, err
	}

	// The three checked add and subtract calls below cannot currently fail.
	// CheckOutputsAmount bounds the target and CheckedFeeForSerializeSize bounds
	// the fee, so their sum stays far inside an int64; each subtraction is
	// guarded by the comparison immediately above it. They are checked
	// anyway, so that a later change to either bound cannot reintroduce a
	// silent wrap, but a reader should not go looking for the input that
	// trips them.
	for {
		inputAmount, inputs, inputValues, scripts, err := fetchFunding(
			fetchInputs, targetAmount, targetFee,
		)
		if err != nil {
			return nil, err
		}

		// We count the types of inputs, which we'll use to estimate
		// the vsize of the transaction.
		p2pkh, p2tr, p2wpkh, nested := countInputTypes(scripts)

		maxSignedSize := txsizes.EstimateVirtualSize(
			p2pkh, p2tr, p2wpkh, nested, outputs, changeScriptSize,
		)

		maxRequiredFee, err := CheckedFeeForSerializeSize(
			feeRatePerKb, maxSignedSize,
		)
		if err != nil {
			return nil, err
		}

		remainingAmount, err := subAmounts(inputAmount, targetAmount)
		if err != nil {
			return nil, err
		}

		if remainingAmount < maxRequiredFee {
			targetFee = maxRequiredFee
			continue
		}

		// Reuse the sufficiency remainder rather than re-deriving the
		// change from the input total a second time.
		changeAmount, err := subAmounts(remainingAmount, maxRequiredFee)
		if err != nil {
			return nil, err
		}

		return &InputSelection{
			outputs:         outputs,
			inputs:          inputs,
			prevScripts:     scripts,
			prevInputValues: inputValues,
			totalInput:      inputAmount,
			changeAmount:    changeAmount,
		}, nil
	}
}

// fetchFunding asks fetchInputs for inputs covering targetAmount plus
// targetFee and returns an insufficient funds error if it supplies less.
func fetchFunding(fetchInputs InputSource, targetAmount,
	targetFee btcutil.Amount) (btcutil.Amount, []*wire.TxIn,
	[]btcutil.Amount, [][]byte, error) {

	// Form the target the inputs must cover once, and hold on to it so the
	// sufficiency comparison below tests the very same value the input
	// source was asked for.
	targetTotal, err := addAmounts(targetAmount, targetFee)
	if err != nil {
		return 0, nil, nil, nil, err
	}

	inputAmount, inputs, inputValues, scripts, err := fetchInputs(
		targetTotal,
	)
	if err != nil {
		return 0, nil, nil, nil, err
	}

	if inputAmount < targetTotal {
		return 0, nil, nil, nil, insufficientFundsError{}
	}

	return inputAmount, inputs, inputValues, scripts, nil
}

// Complete builds the unsigned transaction from the selection, paying the
// leftover value to changeScript. The change output is appended only when the
// leftover value is non-zero and not dust under the default relay fee;
// otherwise the leftover value is added to the fee and the result reports no
// change index. changeScript must be no larger than the script size given to
// SelectInputs, otherwise the fee estimate is too low.
func (s *InputSelection) Complete(changeScript []byte) *AuthoredTx {
	unsignedTransaction := &wire.MsgTx{
		Version:  wire.TxVersion,
		TxIn:     s.inputs,
		TxOut:    s.outputs,
		LockTime: 0,
	}

	changeIndex := -1

	change := wire.NewTxOut(int64(s.changeAmount), changeScript)
	if s.changeAmount != 0 && !txrules.IsDustOutput(change,
		txrules.DefaultRelayFeePerKb) {

		// Copy the outputs so the caller's slice is never grown in
		// place.
		txOuts := make([]*wire.TxOut, 0, len(s.outputs)+1)
		txOuts = append(txOuts, s.outputs...)
		txOuts = append(txOuts, change)

		unsignedTransaction.TxOut = txOuts
		changeIndex = len(s.outputs)
	}

	return &AuthoredTx{
		Tx:              unsignedTransaction,
		PrevScripts:     s.prevScripts,
		PrevInputValues: s.prevInputValues,
		TotalInput:      s.totalInput,
		ChangeIndex:     changeIndex,
	}
}

// countInputTypes classifies the previous output scripts an input set redeems.
// The counts drive the virtual size estimate, since each script type costs a
// different amount of witness and signature data to spend. The results are
// named because they are four values of the same type: transposing any two at
// the call site would compile and surface only as a slightly wrong fee.
func countInputTypes(scripts [][]byte) (p2pkh, p2tr, p2wpkh, nested int) {
	for _, pkScript := range scripts {
		switch {
		// If this is a p2sh output, we assume this is a nested P2WKH.
		case txscript.IsPayToScriptHash(pkScript):
			nested++
		case txscript.IsPayToWitnessPubKeyHash(pkScript):
			p2wpkh++
		case txscript.IsPayToTaproot(pkScript):
			p2tr++
		default:
			p2pkh++
		}
	}

	return p2pkh, p2tr, p2wpkh, nested
}

// RandomizeOutputPosition randomizes the position of a transaction's output by
// swapping it with a random output.  The new index is returned.  This should be
// done before signing.
func RandomizeOutputPosition(outputs []*wire.TxOut, index int) int {
	r := cprng.Int31n(int32(len(outputs)))
	outputs[r], outputs[index] = outputs[index], outputs[r]
	return int(r)
}

// RandomizeChangePosition randomizes the position of an authored transaction's
// change output.  This should be done before signing.
func (tx *AuthoredTx) RandomizeChangePosition() {
	tx.ChangeIndex = RandomizeOutputPosition(tx.Tx.TxOut, tx.ChangeIndex)
}

// SecretsSource provides private keys and redeem scripts necessary for
// constructing transaction input signatures.  Secrets are looked up by the
// corresponding Address for the previous output script.  Addresses for lookup
// are created using the source's blockchain parameters and means a single
// SecretsSource can only manage secrets for a single chain.
//
// TODO: Rewrite this interface to look up private keys and redeem scripts for
// pubkeys, pubkey hashes, script hashes, etc. as separate interface methods.
// This would remove the ChainParams requirement of the interface and could
// avoid unnecessary conversions from previous output scripts to Addresses.
// This can not be done without modifications to the txscript package.
type SecretsSource interface {
	txscript.KeyDB
	txscript.ScriptDB
	ChainParams() *chaincfg.Params
}

// AddAllInputScripts modifies transaction a transaction by adding inputs
// scripts for each input.  Previous output scripts being redeemed by each input
// are passed in prevPkScripts and the slice length must match the number of
// inputs.  Private keys and redeem scripts are looked up using a SecretsSource
// based on the previous output script.
func AddAllInputScripts(tx *wire.MsgTx, prevPkScripts [][]byte,
	inputValues []btcutil.Amount, secrets SecretsSource) error {

	inputFetcher, err := TXPrevOutFetcher(tx, prevPkScripts, inputValues)
	if err != nil {
		return err
	}

	inputs := tx.TxIn
	hashCache := txscript.NewTxSigHashes(tx, inputFetcher)
	chainParams := secrets.ChainParams()

	if len(inputs) != len(prevPkScripts) {
		return errors.New("tx.TxIn and prevPkScripts slices must " +
			"have equal length")
	}

	for i := range inputs {
		pkScript := prevPkScripts[i]

		switch {
		// If this is a p2sh output, who's script hash pre-image is a
		// witness program, then we'll need to use a modified signing
		// function which generates both the sigScript, and the witness
		// script.
		case txscript.IsPayToScriptHash(pkScript):
			err := spendNestedWitnessPubKeyHash(
				inputs[i], pkScript, int64(inputValues[i]),
				chainParams, secrets, tx, hashCache, i,
			)
			if err != nil {
				return err
			}

		case txscript.IsPayToWitnessPubKeyHash(pkScript):
			err := spendWitnessKeyHash(
				inputs[i], pkScript, int64(inputValues[i]),
				chainParams, secrets, tx, hashCache, i,
			)
			if err != nil {
				return err
			}

		case txscript.IsPayToTaproot(pkScript):
			err := spendTaprootKey(
				inputs[i], pkScript, int64(inputValues[i]),
				chainParams, secrets, tx, hashCache, i,
			)
			if err != nil {
				return err
			}

		default:
			sigScript := inputs[i].SignatureScript
			script, err := txscript.SignTxOutput(chainParams, tx, i,
				pkScript, txscript.SigHashAll, secrets, secrets,
				sigScript)
			if err != nil {
				return err
			}
			inputs[i].SignatureScript = script
		}
	}

	return nil
}

// spendWitnessKeyHash generates, and sets a valid witness for spending the
// passed pkScript with the specified input amount. The input amount *must*
// correspond to the output value of the previous pkScript, or else verification
// will fail since the new sighash digest algorithm defined in BIP0143 includes
// the input value in the sighash.
func spendWitnessKeyHash(txIn *wire.TxIn, pkScript []byte,
	inputValue int64, chainParams *chaincfg.Params, secrets SecretsSource,
	tx *wire.MsgTx, hashCache *txscript.TxSigHashes, idx int) error {

	// First obtain the key pair associated with this p2wkh address.
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript,
		chainParams)
	if err != nil {
		return err
	}
	privKey, compressed, err := secrets.GetKey(addrs[0])
	if err != nil {
		return err
	}
	pubKey := privKey.PubKey()

	// Once we have the key pair, generate a p2wkh address type, respecting
	// the compression type of the generated key.
	var pubKeyHash []byte
	if compressed {
		pubKeyHash = address.Hash160(pubKey.SerializeCompressed())
	} else {
		pubKeyHash = address.Hash160(pubKey.SerializeUncompressed())
	}
	p2wkhAddr, err := address.NewAddressWitnessPubKeyHash(pubKeyHash, chainParams)
	if err != nil {
		return err
	}

	// With the concrete address type, we can now generate the
	// corresponding witness program to be used to generate a valid witness
	// which will allow us to spend this output.
	witnessProgram, err := txscript.PayToAddrScript(p2wkhAddr)
	if err != nil {
		return err
	}
	witnessScript, err := txscript.WitnessSignature(tx, hashCache, idx,
		inputValue, witnessProgram, txscript.SigHashAll, privKey, true)
	if err != nil {
		return err
	}

	txIn.Witness = witnessScript

	return nil
}

// spendTaprootKey generates, and sets a valid witness for spending the passed
// pkScript with the specified input amount. The input amount *must*
// correspond to the output value of the previous pkScript, or else verification
// will fail since the new sighash digest algorithm defined in BIP0341 includes
// the input value in the sighash.
func spendTaprootKey(txIn *wire.TxIn, pkScript []byte,
	inputValue int64, chainParams *chaincfg.Params, secrets SecretsSource,
	tx *wire.MsgTx, hashCache *txscript.TxSigHashes, idx int) error {

	// First obtain the key pair associated with this p2tr address. If the
	// pkScript is incorrect or derived from a different internal key or
	// with a script root, we simply won't find a corresponding private key
	// here.
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript, chainParams)
	if err != nil {
		return err
	}
	privKey, _, err := secrets.GetKey(addrs[0])
	if err != nil {
		return err
	}

	// We can now generate a valid witness which will allow us to spend this
	// output.
	witnessScript, err := txscript.TaprootWitnessSignature(
		tx, hashCache, idx, inputValue, pkScript,
		txscript.SigHashDefault, privKey,
	)
	if err != nil {
		return err
	}

	txIn.Witness = witnessScript

	return nil
}

// spendNestedWitnessPubKey generates both a sigScript, and valid witness for
// spending the passed pkScript with the specified input amount. The generated
// sigScript is the version 0 p2wkh witness program corresponding to the queried
// key. The witness stack is identical to that of one which spends a regular
// p2wkh output. The input amount *must* correspond to the output value of the
// previous pkScript, or else verification will fail since the new sighash
// digest algorithm defined in BIP0143 includes the input value in the sighash.
func spendNestedWitnessPubKeyHash(txIn *wire.TxIn, pkScript []byte,
	inputValue int64, chainParams *chaincfg.Params, secrets SecretsSource,
	tx *wire.MsgTx, hashCache *txscript.TxSigHashes, idx int) error {

	// First we need to obtain the key pair related to this p2sh output.
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript,
		chainParams)
	if err != nil {
		return err
	}
	privKey, compressed, err := secrets.GetKey(addrs[0])
	if err != nil {
		return err
	}
	pubKey := privKey.PubKey()

	var pubKeyHash []byte
	if compressed {
		pubKeyHash = address.Hash160(pubKey.SerializeCompressed())
	} else {
		pubKeyHash = address.Hash160(pubKey.SerializeUncompressed())
	}

	// Next, we'll generate a valid sigScript that'll allow us to spend
	// the p2sh output. The sigScript will contain only a single push of
	// the p2wkh witness program corresponding to the matching public key
	// of this address.
	p2wkhAddr, err := address.NewAddressWitnessPubKeyHash(pubKeyHash, chainParams)
	if err != nil {
		return err
	}
	witnessProgram, err := txscript.PayToAddrScript(p2wkhAddr)
	if err != nil {
		return err
	}
	bldr := txscript.NewScriptBuilder()
	bldr.AddData(witnessProgram)
	sigScript, err := bldr.Script()
	if err != nil {
		return err
	}
	txIn.SignatureScript = sigScript

	// With the sigScript in place, we'll next generate the proper witness
	// that'll allow us to spend the p2wkh output.
	witnessScript, err := txscript.WitnessSignature(tx, hashCache, idx,
		inputValue, witnessProgram, txscript.SigHashAll, privKey, compressed)
	if err != nil {
		return err
	}

	txIn.Witness = witnessScript

	return nil
}

// AddAllInputScripts modifies an authored transaction by adding inputs scripts
// for each input of an authored transaction.  Private keys and redeem scripts
// are looked up using a SecretsSource based on the previous output script.
func (tx *AuthoredTx) AddAllInputScripts(secrets SecretsSource) error {
	return AddAllInputScripts(
		tx.Tx, tx.PrevScripts, tx.PrevInputValues, secrets,
	)
}

// TXPrevOutFetcher creates a txscript.PrevOutFetcher from a given slice of
// previous pk scripts and input values.
func TXPrevOutFetcher(tx *wire.MsgTx, prevPkScripts [][]byte,
	inputValues []btcutil.Amount) (*txscript.MultiPrevOutFetcher, error) {

	if len(tx.TxIn) != len(prevPkScripts) {
		return nil, errors.New("tx.TxIn and prevPkScripts slices " +
			"must have equal length")
	}
	if len(tx.TxIn) != len(inputValues) {
		return nil, errors.New("tx.TxIn and inputValues slices " +
			"must have equal length")
	}

	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	for idx, txin := range tx.TxIn {
		fetcher.AddPrevOut(txin.PreviousOutPoint, &wire.TxOut{
			Value:    int64(inputValues[idx]),
			PkScript: prevPkScripts[idx],
		})
	}

	return fetcher, nil
}
