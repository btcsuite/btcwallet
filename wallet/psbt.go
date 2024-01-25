// Copyright (c) 2020 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// FundPsbt creates a fully populated PSBT packet that contains enough inputs to
// fund the outputs specified in the passed in packet with the specified fee
// rate. If there is change left, a change output from the wallet is added and
// the index of the change output is returned. If no custom change scope is
// specified, we will use the coin selection scope (if not nil) or the BIP0086
// scope by default. Otherwise, no additional output is created and the
// index -1 is returned.
//
// NOTE: If the packet doesn't contain any inputs, coin selection is performed
// automatically, only selecting inputs from the account based on the given key
// scope and account number. If a key scope is not specified, then inputs from
// accounts matching the account number provided across all key scopes may be
// selected. This is done to handle the default account case, where a user wants
// to fund a PSBT with inputs regardless of their type (NP2WKH, P2WKH, etc.). If
// the packet does contain any inputs, it is assumed that full coin selection
// happened externally and no additional inputs are added. If the specified
// inputs aren't enough to fund the outputs with the given fee rate, an error is
// returned.
//
// NOTE: A caller of the method should hold the global coin selection lock of
// the wallet. However, no UTXO specific lock lease is acquired for any of the
// selected/validated inputs by this method. It is in the caller's
// responsibility to lock the inputs before handing the partial transaction out.
func (w *Wallet) FundPsbt(packet *psbt.Packet, keyScope *waddrmgr.KeyScope,
	minConfs int32, account uint32, feeSatPerKB btcutil.Amount,
	coinSelectionStrategy CoinSelectionStrategy,
	optFuncs ...TxCreateOption) (int32, error) {

	// Make sure the packet is well formed. We only require there to be at
	// least one input or output.
	err := psbt.VerifyInputOutputLen(packet, false, false)
	if err != nil {
		return 0, err
	}

	if len(packet.UnsignedTx.TxIn) == 0 && len(packet.UnsignedTx.TxOut) == 0 {
		return 0, fmt.Errorf("PSBT packet must contain at least one " +
			"input or output")
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
			return 0, err
		}
	}

	// Let's find out the amount to fund first.
	amt := int64(0)
	for _, output := range txOut {
		amt += output.Value
	}

	var tx *txauthor.AuthoredTx
	switch {
	// We need to do coin selection.
	case len(txIn) == 0:
		// We ask the underlying wallet to fund a TX for us. This
		// includes everything we need, specifically fee estimation and
		// change address creation.
		tx, err = w.CreateSimpleTx(
			keyScope, account, packet.UnsignedTx.TxOut, minConfs,
			feeSatPerKB, coinSelectionStrategy, false,
			optFuncs...,
		)
		if err != nil {
			return 0, fmt.Errorf("error creating funding TX: %v",
				err)
		}

		// Copy over the inputs now then collect all UTXO information
		// that we can and attach them to the PSBT as well. We don't
		// include the witness as the resulting PSBT isn't expected not
		// should be signed yet.
		packet.UnsignedTx.TxIn = tx.Tx.TxIn
		packet.Inputs = make([]psbt.PInput, len(packet.UnsignedTx.TxIn))

		for idx := range packet.UnsignedTx.TxIn {
			// We don't want to include the witness or any script
			// on the unsigned TX just yet.
			packet.UnsignedTx.TxIn[idx].Witness = wire.TxWitness{}
			packet.UnsignedTx.TxIn[idx].SignatureScript = nil
		}

		err := w.DecorateInputs(packet, true)
		if err != nil {
			return 0, err
		}

	// If there are inputs, we need to check if they're sufficient and add
	// a change output if necessary.
	default:
		// Make sure all inputs provided are actually ours.
		packet.Inputs = make([]psbt.PInput, len(packet.UnsignedTx.TxIn))

		for idx := range packet.UnsignedTx.TxIn {
			// We don't want to include the witness or any script
			// on the unsigned TX just yet.
			packet.UnsignedTx.TxIn[idx].Witness = wire.TxWitness{}
			packet.UnsignedTx.TxIn[idx].SignatureScript = nil
		}

		err := w.DecorateInputs(packet, true)
		if err != nil {
			return 0, err
		}

		// We can leverage the fee calculation of the txauthor package
		// if we provide the selected UTXOs as a coin source. We just
		// need to make sure we always return the full list of user-
		// selected UTXOs rather than a subset, otherwise our change
		// amount will be off (in case the user selected multiple UTXOs
		// that are large enough on their own). That's why we use our
		// own static input source creator instead of the more generic
		// makeInputSource() that selects a subset that is "large
		// enough".
		credits := make([]wtxmgr.Credit, len(txIn))
		for idx, in := range txIn {
			utxo := packet.Inputs[idx].WitnessUtxo
			credits[idx] = wtxmgr.Credit{
				OutPoint: in.PreviousOutPoint,
				Amount:   btcutil.Amount(utxo.Value),
				PkScript: utxo.PkScript,
			}
		}
		inputSource := constantInputSource(credits)

		// Build the TxCreateOption to retrieve the change scope.
		opts := defaultTxCreateOptions()
		for _, optFunc := range optFuncs {
			optFunc(opts)
		}

		if opts.changeKeyScope == nil {
			opts.changeKeyScope = keyScope
		}

		// We also need a change source which needs to be able to insert
		// a new change address into the database.
		err = walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error {
			_, changeSource, err := w.addrMgrWithChangeSource(
				dbtx, opts.changeKeyScope, account,
			)
			if err != nil {
				return err
			}

			// Ask the txauthor to create a transaction with our
			// selected coins. This will perform fee estimation and
			// add a change output if necessary.
			tx, err = txauthor.NewUnsignedTransaction(
				txOut, feeSatPerKB, inputSource, changeSource,
			)
			if err != nil {
				return fmt.Errorf("fee estimation not "+
					"successful: %v", err)
			}

			return nil
		})
		if err != nil {
			return 0, fmt.Errorf("could not add change address to "+
				"database: %v", err)
		}
	}

	// If there is a change output, we need to copy it over to the PSBT now.
	var changeTxOut *wire.TxOut
	if tx.ChangeIndex >= 0 {
		changeTxOut = tx.Tx.TxOut[tx.ChangeIndex]
		packet.UnsignedTx.TxOut = append(
			packet.UnsignedTx.TxOut, changeTxOut,
		)

		addr, _, _, err := w.ScriptForOutput(changeTxOut)
		if err != nil {
			return 0, fmt.Errorf("error querying wallet for "+
				"change addr: %w", err)
		}

		changeOutputInfo, err := createOutputInfo(changeTxOut, addr)
		if err != nil {
			return 0, fmt.Errorf("error adding output info to "+
				"change output: %w", err)
		}

		packet.Outputs = append(packet.Outputs, *changeOutputInfo)
	}

	// Now that we have the final PSBT ready, we can sort it according to
	// BIP 69. This will sort the wire inputs and outputs and move the
	// partial inputs and outputs accordingly.
	err = psbt.InPlaceSort(packet)
	if err != nil {
		return 0, fmt.Errorf("could not sort PSBT: %v", err)
	}

	// The change output index might have changed after the sorting. We need
	// to find our index again.
	changeIndex := int32(-1)
	if changeTxOut != nil {
		for idx, txOut := range packet.UnsignedTx.TxOut {
			if psbt.TxOutsEqual(changeTxOut, txOut) {
				changeIndex = int32(idx)
				break
			}
		}
	}

	return changeIndex, nil
}

// DecorateInputs fetches the UTXO information of all inputs it can identify and
// adds the required information to the package's inputs. The failOnUnknown
// boolean controls whether the method should return an error if it cannot
// identify an input or if it should just skip it.
func (w *Wallet) DecorateInputs(packet *psbt.Packet, failOnUnknown bool) error {
	for idx := range packet.Inputs {
		txIn := packet.UnsignedTx.TxIn[idx]

		tx, utxo, derivationPath, _, err := w.FetchInputInfo(
			&txIn.PreviousOutPoint,
		)

		switch {
		// If the error just means it's not an input our wallet controls
		// and the user doesn't care about that, then we can just skip
		// this input and continue.
		case errors.Is(err, ErrNotMine) && !failOnUnknown:
			continue

		case err != nil:
			return fmt.Errorf("error fetching UTXO: %v", err)
		}

		addr, witnessProgram, _, err := w.ScriptForOutput(utxo)
		if err != nil {
			return fmt.Errorf("error fetching UTXO script: %v", err)
		}

		switch {
		case txscript.IsPayToTaproot(utxo.PkScript):
			addInputInfoSegWitV1(
				&packet.Inputs[idx], utxo, derivationPath,
			)

		default:
			addInputInfoSegWitV0(
				&packet.Inputs[idx], tx, utxo, derivationPath,
				addr, witnessProgram,
			)
		}
	}

	return nil
}

// addInputInfoSegWitV0 adds the UTXO and BIP32 derivation info for a SegWit v0
// PSBT input (p2wkh, np2wkh) from the given wallet information.
func addInputInfoSegWitV0(in *psbt.PInput, prevTx *wire.MsgTx, utxo *wire.TxOut,
	derivationInfo *psbt.Bip32Derivation, addr waddrmgr.ManagedAddress,
	witnessProgram []byte) {

	// As a fix for CVE-2020-14199 we have to always include the full
	// non-witness UTXO in the PSBT for segwit v0.
	in.NonWitnessUtxo = prevTx

	// To make it more obvious that this is actually a witness output being
	// spent, we also add the same information as the witness UTXO.
	in.WitnessUtxo = &wire.TxOut{
		Value:    utxo.Value,
		PkScript: utxo.PkScript,
	}
	in.SighashType = txscript.SigHashAll

	// Include the derivation path for each input.
	in.Bip32Derivation = []*psbt.Bip32Derivation{
		derivationInfo,
	}

	// For nested P2WKH we need to add the redeem script to the input,
	// otherwise an offline wallet won't be able to sign for it. For normal
	// P2WKH this will be nil.
	if addr.AddrType() == waddrmgr.NestedWitnessPubKey {
		in.RedeemScript = witnessProgram
	}
}

// addInputInfoSegWitV0 adds the UTXO and BIP32 derivation info for a SegWit v1
// PSBT input (p2tr) from the given wallet information.
func addInputInfoSegWitV1(in *psbt.PInput, utxo *wire.TxOut,
	derivationInfo *psbt.Bip32Derivation) {

	// For SegWit v1 we only need the witness UTXO information.
	in.WitnessUtxo = &wire.TxOut{
		Value:    utxo.Value,
		PkScript: utxo.PkScript,
	}
	in.SighashType = txscript.SigHashDefault

	// Include the derivation path for each input in addition to the
	// taproot specific info we have below.
	in.Bip32Derivation = []*psbt.Bip32Derivation{
		derivationInfo,
	}

	// Include the derivation path for each input.
	in.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{{
		XOnlyPubKey:          derivationInfo.PubKey[1:],
		MasterKeyFingerprint: derivationInfo.MasterKeyFingerprint,
		Bip32Path:            derivationInfo.Bip32Path,
	}}
}

// createOutputInfo creates the BIP32 derivation info for an output from our
// internal wallet.
func createOutputInfo(txOut *wire.TxOut,
	addr waddrmgr.ManagedPubKeyAddress) (*psbt.POutput, error) {

	// We don't know the derivation path for imported keys. Those shouldn't
	// be selected as change outputs in the first place, but just to make
	// sure we don't run into an issue, we return early for imported keys.
	keyScope, derivationPath, isKnown := addr.DerivationInfo()
	if !isKnown {
		return nil, fmt.Errorf("error adding output info to PSBT, " +
			"change addr is an imported addr with unknown " +
			"derivation path")
	}

	// Include the derivation path for this output.
	derivation := &psbt.Bip32Derivation{
		PubKey:               addr.PubKey().SerializeCompressed(),
		MasterKeyFingerprint: derivationPath.MasterKeyFingerprint,
		Bip32Path: []uint32{
			keyScope.Purpose + hdkeychain.HardenedKeyStart,
			keyScope.Coin + hdkeychain.HardenedKeyStart,
			derivationPath.Account,
			derivationPath.Branch,
			derivationPath.Index,
		},
	}
	out := &psbt.POutput{
		Bip32Derivation: []*psbt.Bip32Derivation{
			derivation,
		},
	}

	// Include the Taproot derivation path as well if this is a P2TR output.
	if txscript.IsPayToTaproot(txOut.PkScript) {
		schnorrPubKey := derivation.PubKey[1:]
		out.TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{{
			XOnlyPubKey:          schnorrPubKey,
			MasterKeyFingerprint: derivation.MasterKeyFingerprint,
			Bip32Path:            derivation.Bip32Path,
		}}
		out.TaprootInternalKey = schnorrPubKey
	}

	return out, nil
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
func (w *Wallet) FinalizePsbt(keyScope *waddrmgr.KeyScope, account uint32,
	packet *psbt.Packet) error {

	// Let's check that this is actually something we can and want to sign.
	// We need at least one input and one output. In addition each
	// input needs nonWitness Utxo or witness Utxo data specified.
	err := psbt.InputsReadyToSign(packet)
	if err != nil {
		return err
	}

	// Go through each input that doesn't have final witness data attached
	// to it already and try to sign it. We do expect that we're the last
	// ones to sign. If there is any input without witness data that we
	// cannot sign because it's not our UTXO, this will be a hard failure.
	tx := packet.UnsignedTx
	sigHashes := txscript.NewTxSigHashes(tx, PsbtPrevOutputFetcher(packet))
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
		fullTx, txOut, _, _, err := w.FetchInputInfo(
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

		// Finally, if the input doesn't belong to a watch-only account,
		// then we'll sign it as is, and populate the input with the
		// witness and sigScript (if needed).
		watchOnly := false
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			ns := tx.ReadBucket(waddrmgrNamespaceKey)
			var err error
			if keyScope == nil {
				// If a key scope wasn't specified, then coin
				// selection was performed from the default
				// wallet accounts (NP2WKH, P2WKH, P2TR), so any
				// key scope provided doesn't impact the result
				// of this call.
				watchOnly, err = w.Manager.IsWatchOnlyAccount(
					ns, waddrmgr.KeyScopeBIP0084, account,
				)
			} else {
				watchOnly, err = w.Manager.IsWatchOnlyAccount(
					ns, *keyScope, account,
				)
			}
			return err
		})
		if err != nil {
			return fmt.Errorf("unable to determine if account is "+
				"watch-only: %v", err)
		}
		if watchOnly {
			continue
		}

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

// PsbtPrevOutputFetcher returns a txscript.PrevOutFetcher built from the UTXO
// information in a PSBT packet.
func PsbtPrevOutputFetcher(packet *psbt.Packet) *txscript.MultiPrevOutFetcher {
	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	for idx, txIn := range packet.UnsignedTx.TxIn {
		in := packet.Inputs[idx]

		// Skip any input that has no UTXO.
		if in.WitnessUtxo == nil && in.NonWitnessUtxo == nil {
			continue
		}

		if in.NonWitnessUtxo != nil {
			prevIndex := txIn.PreviousOutPoint.Index
			fetcher.AddPrevOut(
				txIn.PreviousOutPoint,
				in.NonWitnessUtxo.TxOut[prevIndex],
			)

			continue
		}

		// Fall back to witness UTXO only for older wallets.
		if in.WitnessUtxo != nil {
			fetcher.AddPrevOut(
				txIn.PreviousOutPoint, in.WitnessUtxo,
			)
		}
	}

	return fetcher
}

// constantInputSource creates an input source function that always returns the
// static set of user-selected UTXOs.
func constantInputSource(eligible []wtxmgr.Credit) txauthor.InputSource {
	// Current inputs and their total value. These won't change over
	// different invocations as we want our inputs to remain static since
	// they're selected by the user.
	currentTotal := btcutil.Amount(0)
	currentInputs := make([]*wire.TxIn, 0, len(eligible))
	currentScripts := make([][]byte, 0, len(eligible))
	currentInputValues := make([]btcutil.Amount, 0, len(eligible))

	for _, credit := range eligible {
		nextInput := wire.NewTxIn(&credit.OutPoint, nil, nil)
		currentTotal += credit.Amount
		currentInputs = append(currentInputs, nextInput)
		currentScripts = append(currentScripts, credit.PkScript)
		currentInputValues = append(currentInputValues, credit.Amount)
	}

	return func(target btcutil.Amount) (btcutil.Amount, []*wire.TxIn,
		[]btcutil.Amount, [][]byte, error) {

		return currentTotal, currentInputs, currentInputValues,
			currentScripts, nil
	}
}
