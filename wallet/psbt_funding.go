// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

var (
	// ErrConflictingInputMetadata is returned when a caller's own input
	// metadata contradicts what the wallet knows about the same outpoint.
	ErrConflictingInputMetadata = errors.New(
		"psbt input metadata conflicts with wallet data",
	)
)

// callerInput is one input record as the caller handed it over, keyed away
// from the transaction it arrived in.
type callerInput struct {
	// sequence is the sequence number the caller set on this input.
	sequence uint32

	// pInput is the caller's own metadata for this input.
	pInput psbt.PInput
}

// indexCallerInputs keys a caller's input records by the outpoint each one
// spends.
//
// Position cannot be used: authoring rebuilds the input list and sorting
// reorders it, so only the outpoint survives both. That is also why the
// validator refuses a packet spending one outpoint twice, which would leave
// this index having to drop one of two records.
func indexCallerInputs(packet *psbt.Packet) map[wire.OutPoint]callerInput {
	txIns := packet.UnsignedTx.TxIn

	index := make(map[wire.OutPoint]callerInput, len(txIns))
	for i, txIn := range txIns {
		index[txIn.PreviousOutPoint] = callerInput{
			sequence: txIn.Sequence,
			pInput:   packet.Inputs[i],
		}
	}

	return index
}

// restoreInputMetadata puts a caller's own input metadata back onto a packet
// whose inputs the wallet has just decorated, and refuses the packet if the
// two disagree.
//
// Every field is either the wallet's to state or the caller's to keep. The
// wallet states what is being spent and which key spends it, since it looks
// those up rather than accepting them, so a caller that says otherwise is
// refused. Everything else is carried across untouched.
func restoreInputMetadata(packet *psbt.Packet,
	callerInputs map[wire.OutPoint]callerInput) error {

	for i, txIn := range packet.UnsignedTx.TxIn {
		caller, ok := callerInputs[txIn.PreviousOutPoint]
		if !ok {
			// An input the wallet selected itself. There is no
			// caller metadata for it to keep.
			continue
		}

		err := mergeCallerInput(&packet.Inputs[i], &caller.pInput, i)
		if err != nil {
			return err
		}
	}

	return nil
}

// mergeCallerInput merges one caller input record into the wallet's decorated
// record, in place, following the authority rule described on
// restoreInputMetadata.
func mergeCallerInput(decorated, caller *psbt.PInput, idx int) error {
	err := checkCallerInputAgrees(decorated, caller, idx)
	if err != nil {
		return err
	}

	if len(decorated.RedeemScript) == 0 {
		decorated.RedeemScript = caller.RedeemScript
	}

	// The wallet only records a parent transaction for segwit v0 inputs,
	// so a taproot input decorated by the wallet carries none at all. The
	// validator has already established that the caller's parent hashes to
	// the outpoint being spent, so keeping it costs nothing and dropping
	// it would lose a record the caller is entitled to have back.
	if decorated.NonWitnessUtxo == nil {
		decorated.NonWitnessUtxo = caller.NonWitnessUtxo
	}

	// Taproot derivations carry leaf hashes, which say which scripts the
	// key signs for. The wallet never derives those, so where the caller
	// and the wallet agree on the key itself, the caller's records are the
	// ones to keep: they hold everything the wallet's do and the leaf
	// hashes besides.
	if len(caller.TaprootBip32Derivation) > 0 {
		decorated.TaprootBip32Derivation = caller.TaprootBip32Derivation
	}

	// The caller's own fields, which the wallet never derives and
	// therefore never has an opinion on.
	decorated.WitnessScript = caller.WitnessScript
	decorated.TaprootLeafScript = caller.TaprootLeafScript
	decorated.TaprootMerkleRoot = caller.TaprootMerkleRoot

	if len(caller.TaprootInternalKey) > 0 {
		decorated.TaprootInternalKey = caller.TaprootInternalKey
	}

	// The wallet writes a default sighash type, so an explicit request
	// from the caller wins over it. SigHashDefault is zero and so cannot
	// be told apart from an absent field, which is the same thing the
	// wallet would have written for a taproot input anyway.
	if caller.SighashType != 0 {
		decorated.SighashType = caller.SighashType
	}

	return nil
}

// checkCallerInputAgrees reports whether the caller's records for an input can
// stand alongside the ones the wallet derived for it.
//
// Only the fields the wallet states for itself are compared. Where the caller
// says something different about the wallet's own coin or its own keys, that
// is a contradiction rather than an override, and funding refuses instead of
// silently picking one of the two answers.
func checkCallerInputAgrees(decorated, caller *psbt.PInput, idx int) error {
	if caller.WitnessUtxo != nil && decorated.WitnessUtxo != nil &&
		!psbt.TxOutsEqual(caller.WitnessUtxo, decorated.WitnessUtxo) {

		return fmt.Errorf("%w: input %d witness utxo",
			ErrConflictingInputMetadata, idx)
	}

	// The non-witness UTXO needs no comparison. The validator has already
	// established that the caller's parent transaction hashes to the
	// outpoint being spent, and the wallet looked its own parent up by
	// that same outpoint, so the two are the same transaction.

	err := checkDerivationAgrees(decorated, caller, idx)
	if err != nil {
		return err
	}

	if len(caller.RedeemScript) > 0 && len(decorated.RedeemScript) > 0 &&
		!bytes.Equal(caller.RedeemScript, decorated.RedeemScript) {

		return fmt.Errorf("%w: input %d redeem script",
			ErrConflictingInputMetadata, idx)
	}

	return nil
}

// checkDerivationAgrees refuses an input whose caller-supplied derivation
// information names a different key or path than the one the wallet derived
// for the same coin.
//
// Letting a caller's value stand here would let it choose which key the
// signing path goes looking for, which is not a choice a caller of a funding
// method gets to make about the wallet's own UTXO.
func checkDerivationAgrees(decorated, caller *psbt.PInput, idx int) error {
	err := checkDerivationFamily(decorated, caller, idx)
	if err != nil {
		return err
	}

	if len(caller.Bip32Derivation) > 0 &&
		len(decorated.Bip32Derivation) > 0 &&
		!bip32DerivationsEqual(
			caller.Bip32Derivation, decorated.Bip32Derivation,
		) {

		return fmt.Errorf("%w: input %d bip32 derivation",
			ErrConflictingInputMetadata, idx)
	}

	if len(caller.TaprootBip32Derivation) > 0 &&
		len(decorated.TaprootBip32Derivation) > 0 &&
		!taprootDerivationsAgree(
			caller.TaprootBip32Derivation,
			decorated.TaprootBip32Derivation,
		) {

		return fmt.Errorf("%w: input %d taproot bip32 derivation",
			ErrConflictingInputMetadata, idx)
	}

	return nil
}

// checkDerivationFamily reports whether a caller and the wallet agree on what
// kind of input this is.
func checkDerivationFamily(decorated, caller *psbt.PInput, idx int) error {
	callerTaproot := len(caller.TaprootBip32Derivation) > 0
	callerBip32 := len(caller.Bip32Derivation) > 0
	walletTaproot := len(decorated.TaprootBip32Derivation) > 0
	walletBip32 := len(decorated.Bip32Derivation) > 0

	if (callerTaproot && walletBip32) || (callerBip32 && walletTaproot) {
		return fmt.Errorf("%w: input %d derivation kind",
			ErrConflictingInputMetadata, idx)
	}

	return nil
}

// bip32DerivationsEqual reports whether two BIP32 derivation lists name the
// same keys, fingerprints and paths in the same order.
func bip32DerivationsEqual(a, b []*psbt.Bip32Derivation) bool {
	return slices.EqualFunc(a, b, bip32DerivationEqual)
}

// bip32DerivationEqual compares two BIP32 derivation records, treating a pair
// of absent records as equal.
func bip32DerivationEqual(a, b *psbt.Bip32Derivation) bool {
	if a == nil || b == nil {
		return a == b
	}

	return bytes.Equal(a.PubKey, b.PubKey) &&
		a.MasterKeyFingerprint == b.MasterKeyFingerprint &&
		slices.Equal(a.Bip32Path, b.Bip32Path)
}

// taprootDerivationsAgree reports whether two taproot BIP32 derivation lists
// name the same keys, fingerprints and paths in the same order.
//
// Leaf hashes are deliberately not compared. They say which scripts a key
// signs for, which is the caller's business and not something the wallet
// derives, so a caller that supplies them is adding information rather than
// contradicting any.
func taprootDerivationsAgree(a, b []*psbt.TaprootBip32Derivation) bool {
	return slices.EqualFunc(a, b, taprootDerivationAgrees)
}

// taprootDerivationAgrees compares the wallet-stated fields of two taproot
// BIP32 derivation records, treating a pair of absent records as agreeing.
func taprootDerivationAgrees(a, b *psbt.TaprootBip32Derivation) bool {
	if a == nil || b == nil {
		return a == b
	}

	return bytes.Equal(a.XOnlyPubKey, b.XOnlyPubKey) &&
		a.MasterKeyFingerprint == b.MasterKeyFingerprint &&
		slices.Equal(a.Bip32Path, b.Bip32Path)
}
