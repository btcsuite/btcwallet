// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package txauthor provides transaction creation code for wallets.
package txauthor

import (
	"errors"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// SumOutputValues sums up the list of TxOuts and returns an Amount.
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
type insufficientFundsError struct {
}

func (insufficientFundsError) InputSourceError() {

}
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

// NewUnsignedTransaction creates an unsigned transaction paying to non or more
// non-change outputs.  An appropriate transaction fee is included based on the
// transaction size.
//
// Transaction inputs are added depending on the input selection strategy.
// In general inputs are selected one at a time and evaluated whether
// the current inputs suffice the funding amount plus fees.
// When constant input selection is required all inputs are added in a batch
// to be more efficient.
//
// When the input overshoots the amount of outputs an appropriate change is
// constructed. This change output however is not considered when its below
// the dust limit of the bitcoin network.
//
// If successful, the transaction, total input value spent, and all previous
// output scripts are returned. If the inputs were unable to provide
// enough value to pay for every output and any necessary fees, an
// InputSourceError is returned.
//
// BUGS: Fee estimation is off when redeeming inputs from a uncompressed P2PKH.
// Because one cannot evaluate whether an uncompressed or compressed public
// key was used in the P2PKH output before knowing the ScriptSig.
// The output of an P2PKH is the HASH160 of the public key. This public key
// is only provided when signing the transaction (public key is part of the
// ScriptSig) and can be compressed or uncompressed.
// We use the compressed format to estimate P2PKH inputs because uncompressed
// public keys are very rare which would lead to overpaying fees most of the
// time.
func NewUnsignedTransaction(outputs []*wire.TxOut, feeRatePerKb btcutil.Amount,
	inputs []wtxmgr.Credit, selectionStrategy InputSelectionStrategy,
	changeSource *ChangeSource) (*AuthoredTx, error) {

	changeScript, err := changeSource.NewScript()
	if err != nil {
		return nil, err
	}

	targetAmount := SumOutputValues(outputs)

	inputState := inputState{
		feeRatePerKb:      feeRatePerKb,
		targetAmount:      targetAmount,
		outputs:           outputs,
		selectionStrategy: selectionStrategy,
		changeOutpoint: wire.TxOut{
			PkScript: changeScript,
		},
	}

	switch selectionStrategy {
	case PositiveYieldingSelection, RandomSelection:
		// We look through all our inputs and add an input until
		// the amount is enough to pay the target amount and the
		// transaction fees.
		for _, input := range inputs {
			if !inputState.enoughInput() {
				// In case adding a new input fails in the
				// positive yielding strategy we fail quickly
				// because all follow up inputs will be negative
				// yielding too.
				if !inputState.add(input) &&
					selectionStrategy == PositiveYieldingSelection {

					return nil, txSelectionError{
						targetAmount: inputState.targetAmount,
						txFee:        inputState.txFee,
						availableAmt: inputState.inputTotal,
					}
				}
				continue
			}
			// We stop considering inputs when the input amount
			// is enough to fund the transaction.
			break
		}

	case ConstantSelection:
		// In case of a constant selection all inputs are added
		// although they might be negative yielding so we do not
		// check for the return value.
		inputState.add(inputs...)
	}

	// This check is needed to make sure our input amount suffice
	// after considering all eligable inputs.
	if !inputState.enoughInput() {
		return nil, txSelectionError{
			targetAmount: inputState.targetAmount,
			txFee:        inputState.txFee,
			availableAmt: inputState.inputTotal,
		}
	}

	// We need the inputs in the right format.
	numberInputs := len(inputState.inputs)
	txIn := make([]*wire.TxIn, 0, numberInputs)
	inputValues := make([]btcutil.Amount, 0, numberInputs)
	scripts := make([][]byte, 0, numberInputs)

	for _, input := range inputState.inputs {
		txIn = append(txIn, wire.NewTxIn(&input.OutPoint, nil, nil))
		inputValues = append(inputValues, input.Amount)
		scripts = append(scripts, input.PkScript)
	}

	unsignedTransaction := &wire.MsgTx{
		Version:  wire.TxVersion,
		TxIn:     txIn,
		TxOut:    outputs,
		LockTime: 0,
	}

	// Default is no change output. We check if changeOutpoint in the
	// input state is above dust, and add the change output to the
	// transaction.
	changeIndex := -1
	if !txrules.IsDustOutput(&inputState.changeOutpoint,
		txrules.DefaultRelayFeePerKb) {

		l := len(outputs)
		unsignedTransaction.TxOut = append(outputs[:l:l],
			&inputState.changeOutpoint)
		changeIndex = l
	}

	return &AuthoredTx{
		Tx:              unsignedTransaction,
		PrevScripts:     scripts,
		PrevInputValues: inputValues,
		TotalInput:      inputState.inputTotal,
		ChangeIndex:     changeIndex,
	}, nil

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
		pubKeyHash = btcutil.Hash160(pubKey.SerializeCompressed())
	} else {
		pubKeyHash = btcutil.Hash160(pubKey.SerializeUncompressed())
	}
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, chainParams)
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
		pubKeyHash = btcutil.Hash160(pubKey.SerializeCompressed())
	} else {
		pubKeyHash = btcutil.Hash160(pubKey.SerializeUncompressed())
	}

	// Next, we'll generate a valid sigScript that'll allow us to spend
	// the p2sh output. The sigScript will contain only a single push of
	// the p2wkh witness program corresponding to the matching public key
	// of this address.
	p2wkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, chainParams)
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
