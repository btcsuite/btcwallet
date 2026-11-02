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
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

var (
	// ErrMissingInputWitnessSize is returned when imported Taproot script
	// funding receives no serialized witness bound or a zero bound.
	ErrMissingInputWitnessSize = errors.New(
		"missing input witness-size bound",
	)

	// ErrConflictingInputMetadata is returned when a caller's own input
	// metadata contradicts what the wallet knows about the same outpoint.
	ErrConflictingInputMetadata = errors.New(
		"psbt input metadata conflicts with wallet data",
	)
)

// checkFundingWitnessSizes requires an explicit bound for script imports and
// rejects a bound already contradicted by a revealed leaf/control-block pair.
// The caller remains responsible for bounding all eventual witness arguments.
func checkFundingWitnessSizes(packet *psbt.Packet,
	spends []waddrmgr.SpendType, witnessSizes map[wire.OutPoint]uint32) error {

	for i, spend := range spends {
		if spend != waddrmgr.SpendTypeTaprootScriptPath {
			continue
		}

		size := witnessSizes[packet.UnsignedTx.TxIn[i].PreviousOutPoint]
		if size == 0 {
			return fmt.Errorf("%w: input %d",
				ErrMissingInputWitnessSize, i)
		}

		// A final stack must at least contain its revealed script and
		// control block, even before adding signatures or arguments.
		for _, leaf := range packet.Inputs[i].TaprootLeafScript {
			witness := wire.TxWitness{leaf.Script, leaf.ControlBlock}
			if int64(size) < int64(witness.SerializeSize()) {
				return fmt.Errorf("%w: input %d witness-size "+
					"bound is smaller than its revealed leaf",
					ErrConflictingInputMetadata, i)
			}
		}
	}

	return nil
}

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
// wallet states the verified output and any known key origin, refusing caller
// contradictions and records its spend does not use. Imported Taproot scripts
// retain caller spending records for authorization by their signer.
// Everything else is carried across untouched. spends is how the wallet spends
// each input, by position.
func restoreInputMetadata(packet *psbt.Packet,
	callerInputs map[wire.OutPoint]callerInput,
	spends []waddrmgr.SpendType) error {

	for i, txIn := range packet.UnsignedTx.TxIn {
		caller, ok := callerInputs[txIn.PreviousOutPoint]
		if !ok {
			// An input the wallet selected itself. There is no
			// caller metadata for it to keep.
			continue
		}

		err := mergeCallerInput(
			&packet.Inputs[i], &caller.pInput, spends[i], i,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// mergeCallerInput merges one caller input record into the wallet's decorated
// record, in place, following the authority rule described on
// restoreInputMetadata.
func mergeCallerInput(decorated, caller *psbt.PInput,
	spend waddrmgr.SpendType, idx int) error {

	err := checkFieldsFitSpend(decorated, caller, spend, idx)
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

	// The fields the wallet never derives. Any its spend does not use were
	// refused above.
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

// checkFieldsFitSpend refuses caller records that the wallet's spend of this
// coin does not use.
//
// Such a record is inapplicable metadata, and handing it back would present it
// as describing the input. A record is present when it is non-nil, since that
// is when it is serialized. A spend type with no rule here is left alone.
func checkFieldsFitSpend(decorated, caller *psbt.PInput,
	spend waddrmgr.SpendType, idx int) error {

	switch spend {
	case waddrmgr.SpendTypeLegacyKey, waddrmgr.SpendTypeWitnessKey,
		waddrmgr.SpendTypeNestedWitnessKey,
		waddrmgr.SpendTypeTaprootKeyPath:

	case waddrmgr.SpendTypeUnknown, waddrmgr.SpendTypeScriptHash,
		waddrmgr.SpendTypeWitnessScript,
		waddrmgr.SpendTypeTaprootScriptPath,
		waddrmgr.SpendTypeAnyoneCanSpend:

		return nil
	}

	switch {
	case caller.WitnessScript != nil:
		return fieldFitError("witness script", idx)

	case caller.RedeemScript != nil &&
		spend != waddrmgr.SpendTypeNestedWitnessKey:

		return fieldFitError("redeem script", idx)

	case caller.TaprootMerkleRoot != nil:
		return fieldFitError("taproot merkle root", idx)

	case len(caller.TaprootLeafScript) > 0:
		return fieldFitError("taproot leaf script", idx)

	case caller.TaprootInternalKey == nil:
		return nil
	}

	err := checkWalletInternalKey(
		decorated.TaprootInternalKey, caller.TaprootInternalKey,
	)
	if err != nil {
		return fmt.Errorf("%w: input %d taproot internal key", err, idx)
	}

	return nil
}

// checkWalletInternalKey refuses a caller's taproot internal key other than
// the wallet's. The wallet's taproot coins commit to no script, so the key it
// knows is the internal key, even without an origin. Other spends have none.
func checkWalletInternalKey(internalKey, callerKey []byte) error {
	if len(internalKey) > 0 && bytes.Equal(internalKey, callerKey) {
		return nil
	}

	return ErrConflictingInputMetadata
}

// fieldFitError names a caller record the wallet's spend does not use.
func fieldFitError(field string, idx int) error {
	return fmt.Errorf("%w: input %d carries a %s, which the wallet's spend "+
		"of it does not use", ErrConflictingInputMetadata, idx, field)
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

	err := checkCallerDerivations(decorated, caller, idx)
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

// checkCallerDerivations refuses any derivation record the caller names other
// than the wallet's own.
//
// For derived inputs, decoration states the spending key; a derived Taproot
// coin uses the key path and no leaf hashes. Imported Taproot scripts instead
// retain caller records without selecting or authorizing their spending leaf.
// The wallet's signer refuses an input with more than one record of a kind.
func checkCallerDerivations(decorated, caller *psbt.PInput, idx int) error {
	for _, c := range caller.Bip32Derivation {
		if !slices.ContainsFunc(decorated.Bip32Derivation,
			func(w *psbt.Bip32Derivation) bool {
				return bip32DerivationEqual(c, w)
			},
		) {

			return fmt.Errorf("%w: input %d bip32 derivation",
				ErrConflictingInputMetadata, idx)
		}
	}

	for _, c := range caller.TaprootBip32Derivation {
		if !slices.ContainsFunc(decorated.TaprootBip32Derivation,
			func(w *psbt.TaprootBip32Derivation) bool {
				return taprootDerivationEqual(c, w)
			},
		) {

			return fmt.Errorf("%w: input %d taproot bip32 "+
				"derivation", ErrConflictingInputMetadata, idx)
		}
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

// taprootDerivationEqual compares two taproot BIP32 derivation records,
// treating a pair of absent records as equal.
func taprootDerivationEqual(a, b *psbt.TaprootBip32Derivation) bool {
	if a == nil || b == nil {
		return a == b
	}

	return bytes.Equal(a.XOnlyPubKey, b.XOnlyPubKey) &&
		a.MasterKeyFingerprint == b.MasterKeyFingerprint &&
		slices.Equal(a.Bip32Path, b.Bip32Path) &&
		slices.EqualFunc(a.LeafHashes, b.LeafHashes, bytes.Equal)
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
