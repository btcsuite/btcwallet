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

	// ErrPacketSigned is returned when a packet already carries signature
	// material in an operation that is only defined for unsigned packets.
	ErrPacketSigned = errors.New("psbt already carries signatures")

	// ErrUnsafeSighash is returned when an input asks for a sighash form
	// this operation cannot honour.
	ErrUnsafeSighash = errors.New("unsafe psbt sighash type")

	// ErrConflictingUtxo is returned when the UTXO records an input
	// carries disagree with each other or with the outpoint they claim to
	// describe.
	ErrConflictingUtxo = errors.New("conflicting psbt utxo records")

	// ErrMalformedSignature is returned when an admitted signature record
	// is not structurally well formed.
	ErrMalformedSignature = errors.New("malformed psbt signature record")
)

const (
	// schnorrSigLen is the length of a BIP340 signature without a trailing
	// sighash byte.
	schnorrSigLen = 64

	// schnorrSigLenWithSighash is the length of a BIP340 signature that
	// carries an explicit, non-default sighash byte.
	schnorrSigLenWithSighash = 65

	// schnorrPubKeyLen is the length of an x-only BIP340 public key.
	schnorrPubKeyLen = 32

	// sighashBaseMask isolates the base sighash type from any modifier
	// flags.
	sighashBaseMask = txscript.SigHashType(0x1f)
)

// psbtOperation names the wallet operation a packet is being admitted for.
// Structural validity is not one rule but a family of them: a packet that is
// perfectly valid to sign is not valid to fund, because funding still has to
// add inputs and outputs that any existing signature already commits to.
type psbtOperation uint8

const (
	// psbtOpFund admits a packet that the wallet is about to fund. Funding
	// rewrites the transaction, so the packet must carry no signatures at
	// all.
	psbtOpFund psbtOperation = iota

	// psbtOpSign admits a packet that the wallet is about to add
	// signatures to. Signatures from other parties are expected here and
	// are preserved untouched.
	psbtOpSign

	// psbtOpFinalize admits a packet the wallet is about to finalize.
	// As with signing, existing signatures are the point of the operation.
	psbtOpFinalize
)

// String returns a human readable name for the operation.
func (o psbtOperation) String() string {
	switch o {
	case psbtOpFund:
		return "fund"

	case psbtOpSign:
		return "sign"

	case psbtOpFinalize:
		return "finalize"

	default:
		return fmt.Sprintf("unknown psbt operation %d", uint8(o))
	}
}

// admitsSignatures returns true if this operation is defined on packets that
// already carry signature material.
func (o psbtOperation) admitsSignatures() bool {
	return o != psbtOpFund
}

// validatePacket checks that a caller's packet is structurally sound and
// admissible for the given operation. It is the single gate every PSBT
// operation passes through before the wallet consults its store, its keys, or
// the chain, so that a malformed packet is refused before it can allocate a
// change address, take a lease, or reach a signing key.
//
// The check is deliberately side-effect free and takes no wallet state: it
// reads the packet and nothing else, and it never modifies it. That is what
// makes it safe to run first, and what lets the signing and finalization paths
// share it.
//
// The rules are:
//
//  1. The packet, and the transaction it wraps, must be present, and its
//     metadata must describe exactly the inputs and outputs that transaction
//     has.
//  2. The unsigned transaction must actually be unsigned: no input may carry a
//     script signature or witness inline.
//  3. No outpoint may be spent twice.
//  4. Every field must be one this wallet knows about. A packet carrying
//     unclassified fields is refused rather than silently stripped of them.
//  5. The UTXO records an input carries must agree with each other and with
//     the outpoint they describe.
//  6. Derivation information must be unambiguous.
//  7. Sighash forms must be ones the operation can honour.
//  8. Signature material is admitted only for operations defined on signed
//     packets, and even then only when structurally well formed.
func validatePacket(packet *psbt.Packet, op psbtOperation) error {
	if packet == nil || packet.UnsignedTx == nil {
		return ErrPacketNil
	}

	tx := packet.UnsignedTx

	// The per-input and per-output metadata is addressed by position, so a
	// packet whose metadata is a different length than its transaction
	// cannot be interpreted at all.
	if len(packet.Inputs) != len(tx.TxIn) {
		return fmt.Errorf("%w: %d inputs but %d input records",
			ErrPacketMalformed, len(tx.TxIn), len(packet.Inputs))
	}

	if len(packet.Outputs) != len(tx.TxOut) {
		return fmt.Errorf("%w: %d outputs but %d output records",
			ErrPacketMalformed, len(tx.TxOut), len(packet.Outputs))
	}

	// A PSBT's transaction carries its unlocking scripts in the per-input
	// records, never inline, so anything inline means the packet is not
	// the unsigned template it claims to be.
	err := packet.SanityCheck()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPacketMalformed, err)
	}

	// Global fields the wallet cannot classify would be dropped by any
	// transformation, so refuse them up front rather than silently losing
	// them.
	if len(packet.Unknowns) > 0 {
		return fmt.Errorf("%w: %d global fields",
			ErrUnclassifiedField, len(packet.Unknowns))
	}

	err = validatePacketInputs(packet, op)
	if err != nil {
		return err
	}

	for i := range packet.Outputs {
		if len(packet.Outputs[i].Unknowns) > 0 {
			return fmt.Errorf("%w: output %d carries %d fields",
				ErrUnclassifiedField, i,
				len(packet.Outputs[i].Unknowns))
		}
	}

	return nil
}

// validatePacketInputs runs the per-input half of validatePacket. It is split
// out only so that each half stays readable.
func validatePacketInputs(packet *psbt.Packet, op psbtOperation) error {
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

		err = validateInputSighash(pIn, i, len(tx.TxOut), op)
		if err != nil {
			return err
		}

		err = validateInputSignatures(pIn, i, op)
		if err != nil {
			return err
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

		if outPoint.Index >= uint32(len(pIn.NonWitnessUtxo.TxOut)) {
			return fmt.Errorf("%w: input %d spends output %d of a "+
				"parent with %d outputs", ErrConflictingUtxo,
				idx, outPoint.Index,
				len(pIn.NonWitnessUtxo.TxOut))
		}

		claimed = pIn.NonWitnessUtxo.TxOut[outPoint.Index]
	}

	if pIn.WitnessUtxo == nil || claimed == nil {
		return nil
	}

	// Both records are present, so they must describe the same output.
	// Otherwise the packet says two different things about what is being
	// spent, and which one wins would be decided by whichever stage reads
	// it first.
	if !psbt.TxOutsEqual(pIn.WitnessUtxo, claimed) {
		return fmt.Errorf("%w: input %d witness utxo disagrees with "+
			"its parent transaction", ErrConflictingUtxo, idx)
	}

	return nil
}

// validateInputSighash checks that an input's sighash type is one the given
// operation can honour.
//
// SIGHASH_SINGLE is the form that needs care. It commits an input to the
// output at its own index, so it is only meaningful while that pairing holds.
// Funding breaks the pairing outright by appending a change output and
// re-sorting, and even outside funding a packet whose input index has no
// matching output cannot produce a valid signature.
func validateInputSighash(pIn *psbt.PInput, idx, numOutputs int,
	op psbtOperation) error {

	sigHash := pIn.SighashType

	// The base type is the low five bits; the only modifier defined on top
	// of it is ANYONECANPAY.
	base := sigHash & sighashBaseMask
	modifiers := sigHash &^ sighashBaseMask

	if modifiers&^txscript.SigHashAnyOneCanPay != 0 {
		return fmt.Errorf("%w: input %d requests unknown sighash "+
			"flags %#x", ErrUnsafeSighash, idx, uint32(sigHash))
	}

	switch base {
	// SigHashDefault is only meaningful for taproot inputs, but it is
	// indistinguishable from an unset field, so it is admitted for all.
	case txscript.SigHashDefault, txscript.SigHashAll,
		txscript.SigHashNone:

		return nil

	case txscript.SigHashSingle:
		if op == psbtOpFund {
			return fmt.Errorf("%w: input %d requests "+
				"SIGHASH_SINGLE, which %s cannot preserve "+
				"across added outputs and sorting",
				ErrUnsafeSighash, idx, op)
		}

		// Outside funding the pairing is fixed, so all that is left to
		// check is that the paired output exists.
		if idx >= numOutputs {
			return fmt.Errorf("%w: input %d requests "+
				"SIGHASH_SINGLE but the packet has only %d "+
				"outputs", ErrUnsafeSighash, idx, numOutputs)
		}

		return nil

	default:
		return fmt.Errorf("%w: input %d requests unknown sighash "+
			"type %#x", ErrUnsafeSighash, idx, uint32(sigHash))
	}
}

// validateInputSignatures decides whether an input's signature material is
// admissible for the given operation, and whether what is there is well
// formed.
//
// Funding is defined only on unsigned packets: it rewrites the very
// transaction any existing signature commits to, so a signature present at
// that point is either already void or about to be. Signing and finalization
// are the opposite case, where signatures from other parties are the whole
// point; those are admitted and left untouched for the authorization checks
// that own them.
func validateInputSignatures(pIn *psbt.PInput, idx int,
	op psbtOperation) error {

	signed := len(pIn.PartialSigs) > 0 ||
		len(pIn.TaprootKeySpendSig) > 0 ||
		len(pIn.TaprootScriptSpendSig) > 0 ||
		len(pIn.FinalScriptSig) > 0 ||
		len(pIn.FinalScriptWitness) > 0

	if !op.admitsSignatures() {
		if signed {
			return fmt.Errorf("%w: input %d, %s is only defined "+
				"on unsigned packets", ErrPacketSigned, idx, op)
		}

		return nil
	}

	// The records are admitted, so they must at least be well formed. An
	// empty or truncated record cannot be authorized later, and would only
	// fail further along with less to say about why.
	for _, sig := range pIn.PartialSigs {
		if sig == nil {
			return fmt.Errorf("%w: input %d has an empty partial "+
				"signature record", ErrMalformedSignature, idx)
		}

		if len(sig.PubKey) == 0 || len(sig.Signature) == 0 {
			return fmt.Errorf("%w: input %d has a partial "+
				"signature with an empty key or signature",
				ErrMalformedSignature, idx)
		}
	}

	err := validateSchnorrSig(pIn.TaprootKeySpendSig, idx, "key spend")
	if err != nil {
		return err
	}

	for _, sig := range pIn.TaprootScriptSpendSig {
		if sig == nil {
			return fmt.Errorf("%w: input %d has an empty taproot "+
				"script spend record", ErrMalformedSignature,
				idx)
		}

		err := validateSchnorrSig(sig.Signature, idx, "script spend")
		if err != nil {
			return err
		}

		if len(sig.XOnlyPubKey) != schnorrPubKeyLen {
			return fmt.Errorf("%w: input %d has a %d byte taproot "+
				"script spend key", ErrMalformedSignature, idx,
				len(sig.XOnlyPubKey))
		}
	}

	return nil
}

// validateSchnorrSig checks the length of a BIP340 signature record, which is
// the only structural property of it the wallet can judge without the key and
// the sighash it was made over. An absent record is not an error; only a
// present one that cannot be a signature at all.
func validateSchnorrSig(sig []byte, idx int, kind string) error {
	switch len(sig) {
	case 0, schnorrSigLen, schnorrSigLenWithSighash:
		return nil

	default:
		return fmt.Errorf("%w: input %d has a %d byte taproot %s "+
			"signature", ErrMalformedSignature, idx, len(sig),
			kind)
	}
}
