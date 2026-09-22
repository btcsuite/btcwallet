// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
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

// spendKind names the shape of the output an input spends, as far as the
// metadata that output can carry is concerned.
type spendKind uint8

const (
	// spendUnknown is an output the wallet cannot classify. It carries no
	// entitlement either way, so caller metadata is neither admitted nor
	// refused on the strength of it.
	spendUnknown spendKind = iota

	// spendWitnessKey is a single-key segwit v0 spend: P2WPKH.
	spendWitnessKey

	// spendWitnessScript is a script-hash segwit v0 spend: P2WSH.
	spendWitnessScript

	// spendNested is a segwit v0 spend wrapped in P2SH.
	spendNested

	// spendTaproot is a segwit v1 spend.
	spendTaproot
)

// singleKey reports whether the spend is satisfied by one key, which is to say
// it admits no cosigner.
func (k spendKind) singleKey() bool {
	return k == spendWitnessKey || k == spendTaproot
}

// classifySpend reports what kind of output an input spends, reading the script
// from the wallet's own record of the coin rather than from anything the caller
// supplied.
//
// The wallet writes a witness UTXO for every input it decorates, so this is
// the authoritative answer for an input funding selected. An input it could not
// decorate classifies as unknown.
func classifySpend(decorated *psbt.PInput) spendKind {
	if decorated.WitnessUtxo == nil {
		return spendUnknown
	}

	script := decorated.WitnessUtxo.PkScript

	switch {
	case txscript.IsPayToTaproot(script):
		return spendTaproot

	case txscript.IsPayToWitnessPubKeyHash(script):
		return spendWitnessKey

	case txscript.IsPayToWitnessScriptHash(script):
		return spendWitnessScript

	case txscript.IsPayToScriptHash(script):
		return spendNested

	default:
		return spendUnknown
	}
}

// mergeCallerInput merges one caller input record into the wallet's decorated
// record, in place, following the authority rule described on
// restoreInputMetadata.
func mergeCallerInput(decorated, caller *psbt.PInput, idx int) error {
	spend := classifySpend(decorated)

	err := checkFieldsFitSpend(caller, spend, idx)
	if err != nil {
		return err
	}

	err = checkCallerInputAgrees(decorated, caller, idx)
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

	decorated.Bip32Derivation, err = reconcileBip32(
		decorated.Bip32Derivation, caller.Bip32Derivation, idx,
	)
	if err != nil {
		return err
	}

	decorated.TaprootBip32Derivation, err = reconcileTaproot(
		decorated.TaprootBip32Derivation,
		caller.TaprootBip32Derivation, idx,
	)
	if err != nil {
		return err
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

// checkFieldsFitSpend reports whether the caller's records could belong to the
// output this input spends.
//
// Funding carries the caller's own fields across without forming an opinion on
// their contents, but a field that the spend cannot use at all is not metadata
// worth preserving: a taproot leaf script on a segwit v0 input, or a witness
// script on a spend that has no script to reveal. Carrying it would hand back
// a packet describing a spend that cannot happen.
//
// An unclassified spend is left alone. The wallet has no view on it, so it has
// no grounds to refuse anything either.
func checkFieldsFitSpend(caller *psbt.PInput, spend spendKind,
	idx int) error {

	if spend == spendUnknown {
		return nil
	}

	if spend == spendTaproot {
		return checkTaprootFields(caller, spend, idx)
	}

	return checkWitnessFields(caller, spend, idx)
}

// checkTaprootFields refuses the segwit v0 scripts on a taproot spend, which
// reveals neither.
func checkTaprootFields(caller *psbt.PInput, spend spendKind,
	idx int) error {

	if len(caller.WitnessScript) > 0 {
		return fieldFitError("witness script", spend, idx)
	}

	if len(caller.RedeemScript) > 0 {
		return fieldFitError("redeem script", spend, idx)
	}

	return nil
}

// checkWitnessFields refuses the taproot records on a segwit v0 spend, and the
// scripts that spend has nothing to reveal for.
func checkWitnessFields(caller *psbt.PInput, spend spendKind,
	idx int) error {

	switch {
	case len(caller.TaprootLeafScript) > 0:
		return fieldFitError("taproot leaf script", spend, idx)

	case len(caller.TaprootInternalKey) > 0:
		return fieldFitError("taproot internal key", spend, idx)

	case len(caller.TaprootMerkleRoot) > 0:
		return fieldFitError("taproot merkle root", spend, idx)
	}

	// A single-key spend reveals no script, so there is nothing for a
	// witness script to be.
	if spend == spendWitnessKey && len(caller.WitnessScript) > 0 {
		return fieldFitError("witness script", spend, idx)
	}

	// Only a P2SH spend has a redeem script to reveal.
	if spend != spendNested && len(caller.RedeemScript) > 0 {
		return fieldFitError("redeem script", spend, idx)
	}

	return nil
}

// fieldFitError names the field and the spend that cannot carry it.
func fieldFitError(field string, spend spendKind, idx int) error {
	return fmt.Errorf("%w: input %d carries a %s, which a %s spend cannot "+
		"use", ErrConflictingInputMetadata, idx, field, spend)
}

// String names a spend kind for an error message.
func (k spendKind) String() string {
	switch k {
	case spendUnknown:
		return "unclassified"

	case spendWitnessKey:
		return "witness key"

	case spendWitnessScript:
		return "witness script"

	case spendNested:
		return "nested witness"

	case spendTaproot:
		return "taproot"

	default:
		return "unclassified"
	}
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

	err := checkDerivationFamily(decorated, caller, idx)
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

// reconcileBip32 merges the derivation the wallet derived for its own key into
// the set the caller supplied.
//
// The wallet derives one record, for the one key it holds. A caller can carry
// several, one per cosigner on a multisig input, and those are metadata
// funding has to preserve rather than a disagreement. So only the record
// naming the wallet's own key is the wallet's to state: it must match if the
// caller supplied it, and is added if the caller did not. Every other record
// is carried untouched.
func reconcileBip32(wallet, caller []*psbt.Bip32Derivation,
	idx int) ([]*psbt.Bip32Derivation, error) {

	if len(caller) == 0 {
		return wallet, nil
	}

	merged := slices.Clone(caller)
	for _, w := range wallet {
		at := slices.IndexFunc(merged,
			func(c *psbt.Bip32Derivation) bool {
				return bytes.Equal(c.PubKey, w.PubKey)
			},
		)
		if at < 0 {
			// Nobody else may claim the wallet's own place in the
			// derivation tree.
			err := checkNoImpostor(merged, w, idx)
			if err != nil {
				return nil, err
			}

			merged = append(merged, w)

			continue
		}

		if !bip32DerivationEqual(merged[at], w) {
			return nil, fmt.Errorf("%w: input %d bip32 derivation",
				ErrConflictingInputMetadata, idx)
		}
	}

	return merged, nil
}

// checkNoImpostor refuses a caller record that claims the wallet's own
// fingerprint and path for some other key.
//
// Matching records by key alone is not enough. A caller that names the
// wallet's master fingerprint and derivation path while naming a different key
// is not a cosigner: it is asserting that the wallet's own path produces a key
// that it does not. Keeping such a record would leave the packet saying so.
func checkNoImpostor(caller []*psbt.Bip32Derivation,
	wallet *psbt.Bip32Derivation, idx int) error {

	for _, c := range caller {
		if c.MasterKeyFingerprint != wallet.MasterKeyFingerprint {
			continue
		}

		if !slices.Equal(c.Bip32Path, wallet.Bip32Path) {
			continue
		}

		return fmt.Errorf("%w: input %d names the wallet's own "+
			"derivation path for another key",
			ErrConflictingInputMetadata, idx)
	}

	return nil
}

// reconcileTaproot is reconcileBip32 for taproot derivations, matching records
// by their x-only key.
//
// Where both name the wallet's key the caller's record is the one kept, since
// it carries the leaf hashes the wallet does not derive and agrees with the
// wallet's on everything else.
func reconcileTaproot(wallet, caller []*psbt.TaprootBip32Derivation,
	idx int) ([]*psbt.TaprootBip32Derivation, error) {

	if len(caller) == 0 {
		return wallet, nil
	}

	merged := slices.Clone(caller)
	for _, w := range wallet {
		at := slices.IndexFunc(merged,
			func(c *psbt.TaprootBip32Derivation) bool {
				return bytes.Equal(c.XOnlyPubKey, w.XOnlyPubKey)
			},
		)
		if at < 0 {
			err := checkNoTaprootImpostor(merged, w, idx)
			if err != nil {
				return nil, err
			}

			merged = append(merged, w)

			continue
		}

		if !taprootDerivationAgrees(merged[at], w) {
			return nil, fmt.Errorf("%w: input %d taproot bip32 "+
				"derivation", ErrConflictingInputMetadata, idx)
		}
	}

	return merged, nil
}

// checkNoTaprootImpostor is checkNoImpostor for taproot derivations.
func checkNoTaprootImpostor(caller []*psbt.TaprootBip32Derivation,
	wallet *psbt.TaprootBip32Derivation, idx int) error {

	for _, c := range caller {
		if c.MasterKeyFingerprint != wallet.MasterKeyFingerprint {
			continue
		}

		if !slices.Equal(c.Bip32Path, wallet.Bip32Path) {
			continue
		}

		return fmt.Errorf("%w: input %d names the wallet's own "+
			"derivation path for another key",
			ErrConflictingInputMetadata, idx)
	}

	return nil
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

// changeSwappedOutputs builds a packet's output records in the order the
// authored transaction now holds its outputs.
//
// Authoring leaves the caller's outputs in their own order and appends its
// change output past them, then swaps it into a random position, so mirroring
// that one exchange is enough. changeIndex is where the change ended up, or
// negative if there is none; its own record starts empty and is filled in from
// the address the wallet derived.
func changeSwappedOutputs(callerOutputs []psbt.POutput,
	changeIndex int) ([]psbt.POutput, error) {

	if changeIndex < 0 {
		return callerOutputs, nil
	}

	// Change was appended past the caller's outputs, so it can only have
	// been swapped to a position that existed once it was there.
	if changeIndex > len(callerOutputs) {
		return nil, fmt.Errorf("%w: change output at %d of %d outputs",
			ErrPacketMalformed, changeIndex, len(callerOutputs)+1)
	}

	outputs := make([]psbt.POutput, len(callerOutputs)+1)
	copy(outputs, callerOutputs)

	// The change record is the empty one the copy left at the end.
	last := len(outputs) - 1
	outputs[changeIndex], outputs[last] = outputs[last],
		outputs[changeIndex]

	return outputs, nil
}

// sortPacketAndFindChange sorts a packet into the canonical BIP69 order and
// reports where the change output ended up, or -1 if there is none.
//
// changeIndex is where the change output sits before sorting.
func sortPacketAndFindChange(packet *psbt.Packet,
	changeIndex int) (int32, error) {

	// Take hold of the change output before sorting moves it. Sorting
	// reorders the outputs but does not rebuild them, so it is the same
	// object afterwards wherever it lands.
	var changeOutput *wire.TxOut

	if changeIndex >= 0 {
		if changeIndex >= len(packet.UnsignedTx.TxOut) {
			return 0, fmt.Errorf("%w: change output at %d of %d "+
				"outputs", ErrPacketMalformed, changeIndex,
				len(packet.UnsignedTx.TxOut))
		}

		changeOutput = packet.UnsignedTx.TxOut[changeIndex]
	}

	err := psbt.InPlaceSort(packet)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrPacketMalformed, err)
	}

	// A packet with no change output has no change index to report.
	if changeOutput == nil {
		return -1, nil
	}

	return changeIndexAfterSort(packet, changeOutput)
}

// changeIndexAfterSort reports where changeOutput sits in the packet's
// outputs, by identity rather than by value.
//
// Sorting reorders the outputs without rebuilding them, so the change output
// is still the same object. Comparing values would not do: two outputs paying
// the same amount to the same script are indistinguishable that way.
func changeIndexAfterSort(packet *psbt.Packet,
	changeOutput *wire.TxOut) (int32, error) {

	for i, txOut := range packet.UnsignedTx.TxOut {
		if txOut != changeOutput {
			continue
		}

		if i > math.MaxInt32 {
			return 0, ErrChangeIndexOutOfRange
		}

		// The bound above makes this conversion safe.
		//
		//nolint:gosec
		return int32(i), nil
	}

	return 0, fmt.Errorf("%w: change output is missing after sorting",
		ErrPacketMalformed)
}
