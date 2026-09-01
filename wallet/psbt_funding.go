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
	"sort"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
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
// Position cannot be used for this. Authoring rebuilds the input list from the
// outpoints it was asked for, and sorting then reorders it, so an input's
// position in the funded packet says nothing about where it started. Its
// outpoint is the one thing that survives both, which is also why the
// validator refuses a packet that spends an outpoint twice: this index would
// otherwise have to pick one of two records and silently drop the other.
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
// This is where funding's authority over caller metadata is decided, and the
// rule is closed: every field is either the wallet's to state or the caller's
// to keep.
//
// The wallet states what is being spent and which key spends it, because those
// are facts about the wallet's own coins that it looks up rather than accepts.
// A caller that supplies them must supply the same values; a caller that
// supplies different ones is telling the wallet something untrue about its own
// UTXO, and is refused rather than quietly overruled. Every later stage, fee
// arithmetic and sighash computation included, reads exactly these fields.
//
// Everything else is the caller's, and is carried across untouched: witness
// scripts, taproot leaf scripts and merkle roots, and the internal key. The
// sighash type sits between the two: the wallet writes a default, so a caller
// that asked for a particular form keeps it and a caller that asked for
// nothing gets the default.
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
	// The wallet's facts about the coin. A caller value that differs from
	// what the wallet looked up is a contradiction, not an override.
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

	if len(decorated.RedeemScript) == 0 {
		decorated.RedeemScript = caller.RedeemScript
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

// checkDerivationAgrees refuses an input whose caller-supplied derivation
// information names a different key or path than the one the wallet derived
// for the same coin.
//
// Letting a caller's value stand here would let it choose which key the
// signing path goes looking for, which is not a choice a caller of a funding
// method gets to make about the wallet's own UTXO.
func checkDerivationAgrees(decorated, caller *psbt.PInput, idx int) error {
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
		!taprootDerivationsEqual(
			caller.TaprootBip32Derivation,
			decorated.TaprootBip32Derivation,
		) {

		return fmt.Errorf("%w: input %d taproot bip32 derivation",
			ErrConflictingInputMetadata, idx)
	}

	return nil
}

// bip32DerivationsEqual reports whether two BIP32 derivation lists name the
// same keys, fingerprints and paths in the same order.
func bip32DerivationsEqual(a, b []*psbt.Bip32Derivation) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] == nil || b[i] == nil {
			if a[i] != b[i] {
				return false
			}

			continue
		}

		if !bytes.Equal(a[i].PubKey, b[i].PubKey) ||
			a[i].MasterKeyFingerprint !=
				b[i].MasterKeyFingerprint ||
			!slices.Equal(a[i].Bip32Path, b[i].Bip32Path) {

			return false
		}
	}

	return true
}

// taprootDerivationsEqual reports whether two taproot BIP32 derivation lists
// name the same keys, fingerprints, paths and leaf hashes in the same order.
func taprootDerivationsEqual(a, b []*psbt.TaprootBip32Derivation) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] == nil || b[i] == nil {
			if a[i] != b[i] {
				return false
			}

			continue
		}

		if !bytes.Equal(a[i].XOnlyPubKey, b[i].XOnlyPubKey) ||
			a[i].MasterKeyFingerprint !=
				b[i].MasterKeyFingerprint ||
			!slices.Equal(a[i].Bip32Path, b[i].Bip32Path) ||
			len(a[i].LeafHashes) != len(b[i].LeafHashes) {

			return false
		}

		for j := range a[i].LeafHashes {
			if !bytes.Equal(
				a[i].LeafHashes[j], b[i].LeafHashes[j],
			) {

				return false
			}
		}
	}

	return true
}

// restoreOutputMetadata rebuilds a packet's output records so that each one
// sits with the output it describes, using the provenance the authoring
// boundary recorded.
//
// Authoring does not hand the caller's outputs back in the order it was given
// them: change is appended past them and then randomized into an arbitrary
// position. Reading the provenance is what makes the mapping exact. The
// alternative, matching an output by its value and script, cannot tell two
// outputs paying the same amount to the same script apart, and would attribute
// one caller's metadata to the other's output.
//
// The change output is the wallet's own, so it starts with no metadata; the
// funding path fills it in from the address it derived.
func restoreOutputMetadata(callerOutputs []psbt.POutput,
	origin []int) ([]psbt.POutput, error) {

	outputs := make([]psbt.POutput, len(origin))
	for i, from := range origin {
		if from == txauthor.ChangeOutputOrigin {
			continue
		}

		if from < 0 || from >= len(callerOutputs) {
			return nil, fmt.Errorf("%w: output %d claims caller "+
				"output %d of %d", ErrPacketMalformed, i, from,
				len(callerOutputs))
		}

		outputs[i] = callerOutputs[from]
	}

	return outputs, nil
}

// sortPacket sorts a packet's inputs and outputs into BIP69 order, carrying
// the per-input and per-output records along with the wire inputs and outputs
// they describe, and returns the position the change output ended up at, or -1
// if the packet has no change output.
//
// The wallet cannot use psbt.InPlaceSort here and then go looking for its
// change output afterwards, because there is nothing left to look for it by:
// two outputs paying the same amount to the same script are identical to
// anything that inspects them, and the caller is told the wrong index for its
// change. Sorting through an explicit permutation instead lets the provenance
// move with the outputs, so the change output is read off rather than
// rediscovered.
//
// The order this produces is BIP69's, the same one psbt.InPlaceSort produces,
// with one added property: outputs that BIP69 does not distinguish keep the
// order the caller gave them.
func sortPacket(packet *psbt.Packet, origin []int) (int32, error) {
	tx := packet.UnsignedTx

	if len(packet.Inputs) != len(tx.TxIn) ||
		len(packet.Outputs) != len(tx.TxOut) ||
		len(origin) != len(tx.TxOut) {

		return 0, fmt.Errorf("%w: cannot sort a packet whose records "+
			"do not match its transaction", ErrPacketMalformed)
	}

	inputOrder := sortOrder(len(tx.TxIn), func(i, j int) bool {
		return lessOutPoint(
			tx.TxIn[i].PreviousOutPoint,
			tx.TxIn[j].PreviousOutPoint,
		)
	})

	tx.TxIn = permute(tx.TxIn, inputOrder)
	packet.Inputs = permute(packet.Inputs, inputOrder)

	outputOrder := sortOrder(len(tx.TxOut), func(i, j int) bool {
		return lessTxOut(tx.TxOut[i], tx.TxOut[j])
	})

	tx.TxOut = permute(tx.TxOut, outputOrder)
	packet.Outputs = permute(packet.Outputs, outputOrder)
	sorted := permute(origin, outputOrder)

	return changeIndexOf(sorted)
}

// changeIndexOf reports the position the change output holds in a sorted
// provenance list, or -1 if the packet has no change output.
func changeIndexOf(origin []int) (int32, error) {
	for i, from := range origin {
		if from != txauthor.ChangeOutputOrigin {
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

	return -1, nil
}

// sortOrder returns the permutation that puts n elements in order according to
// less, which is stated over the elements' original positions.
//
// The sort is stable, so elements the ordering does not distinguish keep the
// order they arrived in rather than an arbitrary one.
func sortOrder(n int, less func(i, j int) bool) []int {
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}

	sort.SliceStable(order, func(i, j int) bool {
		return less(order[i], order[j])
	})

	return order
}

// permute returns the elements of a slice rearranged into the given order.
func permute[T any](values []T, order []int) []T {
	permuted := make([]T, len(order))
	for i, from := range order {
		permuted[i] = values[from]
	}

	return permuted
}

// lessOutPoint is BIP69's ordering over the outpoints a transaction spends:
// by transaction ID as it is displayed, then by output index.
func lessOutPoint(a, b wire.OutPoint) bool {
	if a.Hash == b.Hash {
		return a.Index < b.Index
	}

	// Transaction IDs are stored in the reverse of the byte order they are
	// displayed and compared in, so walk them from the far end.
	for i := chainhash.HashSize - 1; i >= 0; i-- {
		if a.Hash[i] != b.Hash[i] {
			return a.Hash[i] < b.Hash[i]
		}
	}

	return false
}

// lessTxOut is BIP69's ordering over a transaction's outputs: by amount, then
// by the script each pays.
func lessTxOut(a, b *wire.TxOut) bool {
	if a.Value == b.Value {
		return bytes.Compare(a.PkScript, b.PkScript) < 0
	}

	return a.Value < b.Value
}
