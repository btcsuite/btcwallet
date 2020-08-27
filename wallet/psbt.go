// Copyright (c) 2020 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/psbt"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// FundPsbt creates a fully populated PSBT packet that contains enough inputs to
// fund the outputs specified in the passed in packet with the specified fee
// rate. If there is change left, a change output from the wallet is added.
//
// NOTE: If the packet doesn't contain any inputs, coin selection is performed
// automatically. If the packet does contain any inputs, it is assumed that full
// coin selection happened externally and no additional inputs are added. If the
// specified inputs aren't enough to fund the outputs with the given fee rate,
// an error is returned.
//
// NOTE: A caller of the method should hold the global coin selection lock of
// the wallet. However, no UTXO specific lock lease is acquired for any of the
// selected/validated inputs by this method. It is in the caller's
// responsibility to lock the inputs before handing the partial transaction out.
func (w *Wallet) FundPsbt(packet *psbt.Packet, account uint32,
	feeSatPerKB btcutil.Amount) error {

	// Make sure the packet is well formed. We only require there to be at
	// least one output but not necessarily any inputs.
	err := psbt.VerifyInputOutputLen(packet, false, true)
	if err != nil {
		return err
	}

	txOut := packet.UnsignedTx.TxOut
	txIn := packet.UnsignedTx.TxIn

	// Make sure none of the outputs are dust.
	for _, output := range txOut {
		// When checking an output for things like dusty-ness, we'll
		// use the default mempool relay fee rather than the target
		// effective fee rate to ensure accuracy. Otherwise, we may
		// mistakenly mark small-ish, but not quite dust output as
		// dust.
		err := txrules.CheckOutput(output, txrules.DefaultRelayFeePerKb)
		if err != nil {
			return err
		}
	}

	// Let's find out the amount to fund first.
	amt := int64(0)
	for _, output := range txOut {
		amt += output.Value
	}

	// addInputInfo is a helper function that fetches the UTXO information
	// of an input and attaches it to the PSBT packet.
	addInputInfo := func(inputs []*wire.TxIn) error {
		packet.Inputs = make([]psbt.PInput, len(inputs))
		for idx, in := range inputs {
			tx, utxo, _, err := w.FetchInputInfo(
				&in.PreviousOutPoint,
			)
			if err != nil {
				return fmt.Errorf("error fetching UTXO: %v",
					err)
			}

			// As a fix for CVE-2020-14199 we have to always include
			// the full non-witness UTXO in the PSBT for segwit v0.
			packet.Inputs[idx].NonWitnessUtxo = tx

			// To make it more obvious that this is actually a
			// witness output being spent, we also add the same
			// information as the witness UTXO.
			packet.Inputs[idx].WitnessUtxo = &wire.TxOut{
				Value:    utxo.Value,
				PkScript: utxo.PkScript,
			}
			packet.Inputs[idx].SighashType = txscript.SigHashAll

			// We don't want to include the witness just yet.
			packet.UnsignedTx.TxIn[idx].Witness = wire.TxWitness{}
		}

		return nil
	}

	var tx *txauthor.AuthoredTx
	switch {
	// We need to do coin selection.
	case len(txIn) == 0:
		// We ask the underlying wallet to fund a TX for us. This
		// includes everything we need, specifically fee estimation and
		// change address creation.
		tx, err = w.CreateSimpleTx(
			account, packet.UnsignedTx.TxOut, 1, feeSatPerKB,
			false,
		)
		if err != nil {
			return fmt.Errorf("error creating funding TX: %v", err)
		}

		// Copy over the inputs now then collect all UTXO information
		// that we can and attach them to the PSBT as well. We don't
		// include the witness as the resulting PSBT isn't expected not
		// should be signed yet.
		packet.UnsignedTx.TxIn = tx.Tx.TxIn
		err = addInputInfo(tx.Tx.TxIn)
		if err != nil {
			return err
		}

	// If there are inputs, we need to check if they're sufficient and add
	// a change output if necessary.
	default:
		// Make sure all inputs provided are actually ours.
		err = addInputInfo(txIn)
		if err != nil {
			return err
		}

		// We can leverage the fee calculation of the txauthor package
		// if we provide the selected UTXOs as a coin source.
		credits := make([]wtxmgr.Credit, len(txIn))
		for idx, in := range txIn {
			utxo := packet.Inputs[idx].WitnessUtxo
			credits[idx] = wtxmgr.Credit{
				OutPoint: in.PreviousOutPoint,
				Amount:   btcutil.Amount(utxo.Value),
				PkScript: utxo.PkScript,
			}
		}
		inputSource := makeInputSource(credits)

		// We also need a change source which needs to be able to insert
		// a new change addresse into the database.
		dbtx, err := w.db.BeginReadWriteTx()
		if err != nil {
			return err
		}
		_, changeSource := w.addrMgrWithChangeSource(dbtx, account)

		// Ask the txauthor to create a transaction with our selected
		// coins. This will perform fee estimation and add a change
		// output if necessary.
		tx, err = txauthor.NewUnsignedTransaction(
			txOut, feeSatPerKB, inputSource, changeSource,
		)
		if err != nil {
			_ = dbtx.Rollback()
			return fmt.Errorf("fee estimation not successful: %v",
				err)
		}

		// The transaction could be created, let's commit the DB TX to
		// store the change address (if one was created).
		err = dbtx.Commit()
		if err != nil {
			return fmt.Errorf("could not add change address to "+
				"database: %v", err)
		}
	}

	// If there is a change output, we need to copy it over to the PSBT now.
	if tx.ChangeIndex >= 0 {
		packet.UnsignedTx.TxOut = append(
			packet.UnsignedTx.TxOut,
			tx.Tx.TxOut[tx.ChangeIndex],
		)
		packet.Outputs = append(packet.Outputs, psbt.POutput{})
	}

	// Now that we have the final PSBT ready, we can sort it according to
	// BIP 69. This will sort the wire inputs and outputs and move the
	// partial inputs and outputs accordingly.
	err = psbt.InPlaceSort(packet)
	if err != nil {
		return fmt.Errorf("could not sort PSBT: %v", err)
	}

	return nil
}

// FinalizePsbt expects a partial transaction with all inputs and outputs fully
// declared and tries to sign all inputs that belong to the wallet. Our wallet
// must be the last signer of the transaction. That means, if there are any
// unsigned non-witness inputs or inputs without UTXO information attached or
// inputs without witness data that do not belong to the wallet, this method
// will fail. If no error is returned, the PSBT is ready to be extracted and the
// final TX within to be broadcast.
//
// NOTE: This method does NOT publish the transaction after it's been finalized
// successfully.
func (w *Wallet) FinalizePsbt(packet *psbt.Packet) error {
	// Let's check that this is actually something we can and want to sign.
	// We need at least one input and one output.
	err := psbt.VerifyInputOutputLen(packet, true, true)
	if err != nil {
		return err
	}

	// Go through each input that doesn't have final witness data attached
	// to it already and try to sign it. We do expect that we're the last
	// ones to sign. If there is any input without witness data that we
	// cannot sign because it's not our UTXO, this will be a hard failure.
	tx := packet.UnsignedTx
	sigHashes := txscript.NewTxSigHashes(tx)
	for idx, txIn := range tx.TxIn {
		in := packet.Inputs[idx]

		// We can only sign if we have UTXO information available. We
		// can just continue here as a later step will fail with a more
		// precise error message.
		if in.WitnessUtxo == nil && in.NonWitnessUtxo == nil {
			continue
		}

		// Skip this input if it's got final witness data attached.
		if len(in.FinalScriptWitness) > 0 {
			continue
		}

		// We can only sign this input if it's ours, so we try to map it
		// to a coin we own. If we can't, then we'll continue as it
		// isn't our input.
		fullTx, txOut, _, err := w.FetchInputInfo(
			&txIn.PreviousOutPoint,
		)
		if err != nil {
			continue
		}

		// Find out what UTXO we are signing. Wallets _should_ always
		// provide the full non-witness UTXO for segwit v0.
		var signOutput *wire.TxOut
		if in.NonWitnessUtxo != nil {
			prevIndex := txIn.PreviousOutPoint.Index
			signOutput = in.NonWitnessUtxo.TxOut[prevIndex]

			if !psbt.TxOutsEqual(txOut, signOutput) {
				return fmt.Errorf("found UTXO %#v but it "+
					"doesn't match PSBT's input %v", txOut,
					signOutput)
			}

			if fullTx.TxHash() != txIn.PreviousOutPoint.Hash {
				return fmt.Errorf("found UTXO tx %v but it "+
					"doesn't match PSBT's input %v",
					fullTx.TxHash(),
					txIn.PreviousOutPoint.Hash)
			}
		}

		// Fall back to witness UTXO only for older wallets.
		if in.WitnessUtxo != nil {
			signOutput = in.WitnessUtxo

			if !psbt.TxOutsEqual(txOut, signOutput) {
				return fmt.Errorf("found UTXO %#v but it "+
					"doesn't match PSBT's input %v", txOut,
					signOutput)
			}
		}

		// Finally, we'll sign the input as is, and populate the input
		// with the witness and sigScript (if needed).
		witness, sigScript, err := w.ComputeInputScript(
			tx, signOutput, idx, sigHashes, in.SighashType, nil,
		)
		if err != nil {
			return fmt.Errorf("error computing input script for "+
				"input %d: %v", idx, err)
		}

		// Serialize the witness format from the stack representation to
		// the wire representation.
		var witnessBytes bytes.Buffer
		err = psbt.WriteTxWitness(&witnessBytes, witness)
		if err != nil {
			return fmt.Errorf("error serializing witness: %v", err)
		}
		packet.Inputs[idx].FinalScriptWitness = witnessBytes.Bytes()
		packet.Inputs[idx].FinalScriptSig = sigScript
	}

	// Make sure the PSBT itself thinks it's finalized and ready to be
	// broadcast.
	err = psbt.MaybeFinalizeAll(packet)
	if err != nil {
		return fmt.Errorf("error finalizing PSBT: %v", err)
	}

	return nil
}
