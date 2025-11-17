// Copyright (c) 2020 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// addInputInfoSegWitV0 adds the UTXO and BIP32 derivation info for a
// SegWit v0 PSBT input (p2wkh, np2wkh) from the given wallet
// information.
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
