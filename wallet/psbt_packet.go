// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

var (
	// ErrPacketNil is returned when a PSBT packet, or the unsigned
	// transaction it wraps, is missing.
	ErrPacketNil = errors.New("psbt packet is nil")

	// ErrPacketMalformed is returned when a packet's metadata does not
	// line up with the transaction it describes.
	ErrPacketMalformed = errors.New("malformed psbt packet")

	// ErrDuplicateInput is returned when a packet spends the same outpoint
	// more than once.
	ErrDuplicateInput = errors.New("duplicate psbt input outpoint")

	// ErrUnclassifiedField is returned when a packet carries a field this
	// wallet cannot classify, and therefore cannot promise to preserve.
	ErrUnclassifiedField = errors.New("psbt carries unclassified fields")

	// ErrConflictingUtxo is returned when the UTXO records an input
	// carries disagree with each other or with the outpoint they claim to
	// describe.
	ErrConflictingUtxo = errors.New("conflicting psbt utxo records")

	// ErrUnsafeSighash is returned when an input asks for a sighash form
	// this operation cannot honour.
	ErrUnsafeSighash = errors.New("unsafe psbt sighash type")

	// ErrPacketSigned is returned when a packet already carries signature
	// material in an operation that is only defined for unsigned packets.
	ErrPacketSigned = errors.New("psbt already carries signatures")
)

// sighashBaseMask isolates the base sighash type from any modifier flags.
const sighashBaseMask = txscript.SigHashType(0x1f)

// validatePacket checks that a caller's packet describes one coherent
// transaction and that every record it carries can be read without guessing.
//
// It is side-effect free and takes no wallet state, so it is safe to run
// before the wallet consults its store, its keys or the chain. It says only
// whether the packet can be interpreted; rules belonging to one operation live
// with that operation, as validateFundPacket does for funding.
func validatePacket(packet *psbt.Packet) error {
	if packet == nil || packet.UnsignedTx == nil {
		return ErrPacketNil
	}

	// The cardinality invariant between the transaction and the record
	// lists is the psbt package's own, so ask it rather than keeping a
	// second copy of the rule here.
	err := psbt.VerifyInputOutputLen(packet, false, false)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPacketMalformed, err)
	}

	// Nothing below this point, here or in the wallet, checks these
	// pointers again. SanityCheck reads through the transaction's inputs
	// and cloning reads through every record list, so a nil entry has to
	// be refused before either of them runs.
	err = validatePacketPointers(packet)
	if err != nil {
		return err
	}

	// A PSBT's transaction carries its unlocking scripts in the per-input
	// records, never inline, so anything inline means the packet is not
	// the unsigned template it claims to be.
	err = packet.SanityCheck()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPacketMalformed, err)
	}

	// Global fields the wallet cannot classify would be dropped by any
	// transformation, so refuse them up front rather than silently losing
	// them.
	if len(packet.Unknowns) > 0 {
		return fmt.Errorf("%w: %d global fields",
			ErrUnclassifiedField, len(packet.Unknowns))
	}

	err = validatePacketInputs(packet)
	if err != nil {
		return err
	}

	return validatePacketOutputs(packet)
}

// validatePacketPointers checks that nothing the wallet will read through is
// nil: neither an entry in the unsigned transaction, nor an entry in any of
// the record lists a packet can carry.
//
// A caller builds a Packet as a plain struct, so any of these slices can hold
// a nil element. Every one of them is dereferenced later, by SanityCheck, by
// cloning, or by the funding merge, and a nil there is a panic rather than a
// rejection.
func validatePacketPointers(packet *psbt.Packet) error {
	tx := packet.UnsignedTx

	for i, txIn := range tx.TxIn {
		if txIn == nil {
			return fmt.Errorf("%w: input %d is nil",
				ErrPacketMalformed, i)
		}
	}

	for i, txOut := range tx.TxOut {
		if txOut == nil {
			return fmt.Errorf("%w: output %d is nil",
				ErrPacketMalformed, i)
		}
	}

	for i := range packet.Inputs {
		err := validateInputPointers(&packet.Inputs[i], i)
		if err != nil {
			return err
		}
	}

	for i := range packet.Outputs {
		pOut := &packet.Outputs[i]

		err := validateRecordPointers(
			"output", i, pOut.Bip32Derivation,
			pOut.TaprootBip32Derivation, pOut.Unknowns,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// validateInputPointers checks every pointer-bearing record list on a single
// input for nil entries.
func validateInputPointers(pIn *psbt.PInput, idx int) error {
	for i, sig := range pIn.PartialSigs {
		if sig == nil {
			return fmt.Errorf("%w: input %d partial signature %d "+
				"is nil", ErrPacketMalformed, idx, i)
		}
	}

	for i, sig := range pIn.TaprootScriptSpendSig {
		if sig == nil {
			return fmt.Errorf("%w: input %d taproot script spend "+
				"signature %d is nil", ErrPacketMalformed,
				idx, i)
		}
	}

	for i, leaf := range pIn.TaprootLeafScript {
		if leaf == nil {
			return fmt.Errorf("%w: input %d taproot leaf script "+
				"%d is nil", ErrPacketMalformed, idx, i)
		}
	}

	err := validateParentPointers(pIn.NonWitnessUtxo, idx)
	if err != nil {
		return err
	}

	return validateRecordPointers(
		"input", idx, pIn.Bip32Derivation,
		pIn.TaprootBip32Derivation, pIn.Unknowns,
	)
}

// validateParentPointers checks the entries of a caller's parent transaction.
//
// Hashing it to compare against the outpoint reads through its own inputs and
// outputs, and so does copying it, so a nil entry in either is a panic rather
// than a rejection.
func validateParentPointers(parent *wire.MsgTx, idx int) error {
	if parent == nil {
		return nil
	}

	for i, txIn := range parent.TxIn {
		if txIn == nil {
			return fmt.Errorf("%w: input %d parent input %d is nil",
				ErrPacketMalformed, idx, i)
		}
	}

	for i, txOut := range parent.TxOut {
		if txOut == nil {
			return fmt.Errorf("%w: input %d parent output %d is "+
				"nil", ErrPacketMalformed, idx, i)
		}
	}

	return nil
}

// validateRecordPointers checks the three record lists that both inputs and
// outputs carry. kind and idx only name the offender in the error.
func validateRecordPointers(kind string, idx int,
	derivations []*psbt.Bip32Derivation,
	taproot []*psbt.TaprootBip32Derivation,
	unknowns []*psbt.Unknown) error {

	for i, d := range derivations {
		if d == nil {
			return fmt.Errorf("%w: %s %d bip32 derivation %d is "+
				"nil", ErrPacketMalformed, kind, idx, i)
		}
	}

	for i, d := range taproot {
		if d == nil {
			return fmt.Errorf("%w: %s %d taproot derivation %d "+
				"is nil", ErrPacketMalformed, kind, idx, i)
		}
	}

	for i, u := range unknowns {
		if u == nil {
			return fmt.Errorf("%w: %s %d unknown field %d is nil",
				ErrPacketMalformed, kind, idx, i)
		}
	}

	return nil
}

// validatePacketInputs runs the per-input half of validatePacket. It is split
// out only so that each half stays readable.
func validatePacketInputs(packet *psbt.Packet) error {
	tx := packet.UnsignedTx

	seen := make(map[wire.OutPoint]int, len(tx.TxIn))
	for i, txIn := range tx.TxIn {
		outPoint := txIn.PreviousOutPoint

		// Two inputs spending one outpoint make the packet's own
		// per-input metadata ambiguous, and the transaction it
		// describes unspendable.
		if first, ok := seen[outPoint]; ok {
			return fmt.Errorf("%w: inputs %d and %d spend %v",
				ErrDuplicateInput, first, i, outPoint)
		}

		seen[outPoint] = i

		pIn := &packet.Inputs[i]

		if len(pIn.Unknowns) > 0 {
			return fmt.Errorf("%w: input %d carries %d fields",
				ErrUnclassifiedField, i, len(pIn.Unknowns))
		}

		err := validateInputUtxos(pIn, outPoint, i)
		if err != nil {
			return err
		}

		// Reuse the signing path's derivation rules so that a packet
		// admitted here cannot be rejected later for a reason this
		// gate could have caught.
		_, err = validateDerivation(pIn, i)
		if err != nil {
			return err
		}

		err = validateInputSighash(pIn, i)
		if err != nil {
			return err
		}
	}

	return nil
}

// validatePacketOutputs runs the per-output half of validatePacket.
func validatePacketOutputs(packet *psbt.Packet) error {
	for i := range packet.Outputs {
		if len(packet.Outputs[i].Unknowns) > 0 {
			return fmt.Errorf("%w: output %d carries %d fields",
				ErrUnclassifiedField, i,
				len(packet.Outputs[i].Unknowns))
		}
	}

	return nil
}

// validateInputUtxos checks that the UTXO records an input carries describe
// the outpoint that input actually spends, and that they agree with each other
// where both are present.
//
// This is the check that stops a caller from handing the wallet a prevout of
// its own choosing: every later stage, from fee arithmetic to sighash
// computation, reads the spent output from these records.
func validateInputUtxos(pIn *psbt.PInput, outPoint wire.OutPoint,
	idx int) error {

	var claimed *wire.TxOut

	if pIn.NonWitnessUtxo != nil {
		// The full parent transaction must be the one this input
		// names, or it describes some other output entirely.
		txHash := pIn.NonWitnessUtxo.TxHash()
		if txHash != outPoint.Hash {
			return fmt.Errorf("%w: input %d spends %v but carries "+
				"parent %v", ErrConflictingUtxo, idx,
				outPoint.Hash, txHash)
		}

		if uint64(outPoint.Index) >=
			uint64(len(pIn.NonWitnessUtxo.TxOut)) {

			return fmt.Errorf("%w: input %d spends output %d of a "+
				"parent with %d outputs", ErrConflictingUtxo,
				idx, outPoint.Index,
				len(pIn.NonWitnessUtxo.TxOut))
		}

		claimed = pIn.NonWitnessUtxo.TxOut[outPoint.Index]
	}

	// Where a packet carries both views of the spent output, they have to
	// be the same output. Otherwise the wallet has no way to tell which
	// one the caller meant.
	if claimed != nil && pIn.WitnessUtxo != nil &&
		!psbt.TxOutsEqual(claimed, pIn.WitnessUtxo) {

		return fmt.Errorf("%w: input %d carries a witness utxo that "+
			"disagrees with its parent transaction",
			ErrConflictingUtxo, idx)
	}

	return nil
}

// validateInputSighash checks that an input asks for a sighash type that
// exists.
//
// The base type is the low five bits and the only modifier defined on top of
// it is ANYONECANPAY, so anything outside that shape is a value no signer
// could honour. Whether a well-formed type is appropriate for a given
// operation is that operation's question, not this one's.
func validateInputSighash(pIn *psbt.PInput, idx int) error {
	sigHash := pIn.SighashType
	base := sigHash & sighashBaseMask
	modifiers := sigHash &^ sighashBaseMask

	if modifiers&^txscript.SigHashAnyOneCanPay != 0 {
		return fmt.Errorf("%w: input %d requests unknown sighash "+
			"flags %#x", ErrUnsafeSighash, idx, uint32(sigHash))
	}

	anyoneCanPay := modifiers&txscript.SigHashAnyOneCanPay != 0

	// The default type is the absence of a sighash type, so there is
	// nothing for a modifier to modify. No spending path defines an
	// ANYONECANPAY form of it.
	if base == txscript.SigHashDefault && anyoneCanPay {
		return fmt.Errorf("%w: input %d requests ANYONECANPAY with a "+
			"default sighash type", ErrUnsafeSighash, idx)
	}

	//nolint:exhaustive // ANYONECANPAY is masked off above, so it cannot
	// appear in base.
	switch base {
	// SigHashDefault is only meaningful for taproot inputs, but it is
	// indistinguishable from an unset field, so it is admitted for all.
	case txscript.SigHashDefault, txscript.SigHashAll,
		txscript.SigHashNone, txscript.SigHashSingle:

		return nil

	default:
		return fmt.Errorf("%w: input %d requests unknown sighash "+
			"type %#x", ErrUnsafeSighash, idx, uint32(sigHash))
	}
}

// validateFundPacket checks that a packet is structurally sound and that
// funding may proceed on it.
//
// Funding rewrites the transaction, adding inputs, appending a change output
// and reordering everything. That is why an existing signature is refused
// rather than silently invalidated, and why SIGHASH_SINGLE cannot be honoured:
// it commits an input to the output at its own index.
func validateFundPacket(packet *psbt.Packet) error {
	err := validatePacket(packet)
	if err != nil {
		return err
	}

	for i := range packet.Inputs {
		pIn := &packet.Inputs[i]

		if inputIsSigned(pIn) {
			return fmt.Errorf("%w: input %d, funding is only "+
				"defined on unsigned packets", ErrPacketSigned,
				i)
		}

		if pIn.SighashType&sighashBaseMask ==
			txscript.SigHashSingle {

			return fmt.Errorf("%w: input %d requests "+
				"SIGHASH_SINGLE, which funding cannot "+
				"preserve across added outputs and sorting",
				ErrUnsafeSighash, i)
		}
	}

	return nil
}

// inputIsSigned reports whether an input carries any signature material, in
// any of the forms a PSBT can hold it.
func inputIsSigned(pIn *psbt.PInput) bool {
	return len(pIn.PartialSigs) > 0 ||
		len(pIn.TaprootKeySpendSig) > 0 ||
		len(pIn.TaprootScriptSpendSig) > 0 ||
		len(pIn.FinalScriptSig) > 0 ||
		len(pIn.FinalScriptWitness) > 0
}
