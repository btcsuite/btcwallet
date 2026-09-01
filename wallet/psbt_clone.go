// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"slices"

	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// clonePacket returns a deep copy of a packet that shares no memory with the
// original. Every operation that transforms a packet works on a clone, so that
// a caller's own packet is never left half rewritten by an operation that
// failed part of the way through.
//
// A nil packet clones to nil, so that validation, not this function, decides
// what to do about it.
func clonePacket(packet *psbt.Packet) *psbt.Packet {
	if packet == nil {
		return nil
	}

	clone := &psbt.Packet{
		Inputs:  make([]psbt.PInput, len(packet.Inputs)),
		Outputs: make([]psbt.POutput, len(packet.Outputs)),
	}

	if packet.UnsignedTx != nil {
		clone.UnsignedTx = packet.UnsignedTx.Copy()
	}

	for i := range packet.Inputs {
		clone.Inputs[i] = clonePInput(&packet.Inputs[i])
	}

	for i := range packet.Outputs {
		clone.Outputs[i] = clonePOutput(&packet.Outputs[i])
	}

	clone.XPubs = cloneXPubs(packet.XPubs)
	clone.Unknowns = cloneUnknowns(packet.Unknowns)

	return clone
}

// clonePInput returns a deep copy of a single input record.
func clonePInput(in *psbt.PInput) psbt.PInput {
	out := psbt.PInput{
		SighashType:        in.SighashType,
		RedeemScript:       bytes.Clone(in.RedeemScript),
		WitnessScript:      bytes.Clone(in.WitnessScript),
		FinalScriptSig:     bytes.Clone(in.FinalScriptSig),
		FinalScriptWitness: bytes.Clone(in.FinalScriptWitness),
		TaprootKeySpendSig: bytes.Clone(in.TaprootKeySpendSig),
		TaprootInternalKey: bytes.Clone(in.TaprootInternalKey),
		TaprootMerkleRoot:  bytes.Clone(in.TaprootMerkleRoot),
		Unknowns:           cloneUnknowns(in.Unknowns),
	}

	if in.NonWitnessUtxo != nil {
		out.NonWitnessUtxo = in.NonWitnessUtxo.Copy()
	}

	if in.WitnessUtxo != nil {
		out.WitnessUtxo = &wire.TxOut{
			Value:    in.WitnessUtxo.Value,
			PkScript: bytes.Clone(in.WitnessUtxo.PkScript),
		}
	}

	if in.PartialSigs != nil {
		out.PartialSigs = make(
			[]*psbt.PartialSig, len(in.PartialSigs),
		)
		for i, sig := range in.PartialSigs {
			if sig == nil {
				continue
			}

			out.PartialSigs[i] = &psbt.PartialSig{
				PubKey:    bytes.Clone(sig.PubKey),
				Signature: bytes.Clone(sig.Signature),
			}
		}
	}

	out.Bip32Derivation = cloneBip32Derivations(in.Bip32Derivation)
	out.TaprootBip32Derivation = cloneTaprootBip32Derivations(
		in.TaprootBip32Derivation,
	)

	if in.TaprootScriptSpendSig != nil {
		out.TaprootScriptSpendSig = make(
			[]*psbt.TaprootScriptSpendSig,
			len(in.TaprootScriptSpendSig),
		)
		for i, sig := range in.TaprootScriptSpendSig {
			if sig == nil {
				continue
			}

			out.TaprootScriptSpendSig[i] =
				&psbt.TaprootScriptSpendSig{
					XOnlyPubKey: bytes.Clone(
						sig.XOnlyPubKey,
					),
					LeafHash:  bytes.Clone(sig.LeafHash),
					Signature: bytes.Clone(sig.Signature),
					SigHash:   sig.SigHash,
				}
		}
	}

	if in.TaprootLeafScript != nil {
		out.TaprootLeafScript = make(
			[]*psbt.TaprootTapLeafScript,
			len(in.TaprootLeafScript),
		)
		for i, leaf := range in.TaprootLeafScript {
			if leaf == nil {
				continue
			}

			out.TaprootLeafScript[i] = &psbt.TaprootTapLeafScript{
				ControlBlock: bytes.Clone(leaf.ControlBlock),
				Script:       bytes.Clone(leaf.Script),
				LeafVersion:  leaf.LeafVersion,
			}
		}
	}

	return out
}

// clonePOutput returns a deep copy of a single output record.
func clonePOutput(out *psbt.POutput) psbt.POutput {
	return psbt.POutput{
		RedeemScript:       bytes.Clone(out.RedeemScript),
		WitnessScript:      bytes.Clone(out.WitnessScript),
		Bip32Derivation:    cloneBip32Derivations(out.Bip32Derivation),
		TaprootInternalKey: bytes.Clone(out.TaprootInternalKey),
		TaprootTapTree:     bytes.Clone(out.TaprootTapTree),
		TaprootBip32Derivation: cloneTaprootBip32Derivations(
			out.TaprootBip32Derivation,
		),
		Unknowns: cloneUnknowns(out.Unknowns),
	}
}

// cloneBip32Derivations returns a deep copy of a BIP32 derivation list.
func cloneBip32Derivations(
	derivations []*psbt.Bip32Derivation) []*psbt.Bip32Derivation {

	if derivations == nil {
		return nil
	}

	clone := make([]*psbt.Bip32Derivation, len(derivations))
	for i, d := range derivations {
		if d == nil {
			continue
		}

		clone[i] = &psbt.Bip32Derivation{
			PubKey:               bytes.Clone(d.PubKey),
			MasterKeyFingerprint: d.MasterKeyFingerprint,
			Bip32Path:            slices.Clone(d.Bip32Path),
		}
	}

	return clone
}

// cloneTaprootBip32Derivations returns a deep copy of a taproot BIP32
// derivation list.
func cloneTaprootBip32Derivations(
	derivations []*psbt.TaprootBip32Derivation,
) []*psbt.TaprootBip32Derivation {

	if derivations == nil {
		return nil
	}

	clone := make([]*psbt.TaprootBip32Derivation, len(derivations))
	for i, d := range derivations {
		if d == nil {
			continue
		}

		leafHashes := make([][]byte, len(d.LeafHashes))
		for j, hash := range d.LeafHashes {
			leafHashes[j] = bytes.Clone(hash)
		}

		clone[i] = &psbt.TaprootBip32Derivation{
			XOnlyPubKey:          bytes.Clone(d.XOnlyPubKey),
			LeafHashes:           leafHashes,
			MasterKeyFingerprint: d.MasterKeyFingerprint,
			Bip32Path:            slices.Clone(d.Bip32Path),
		}
	}

	return clone
}

// cloneXPubs returns a deep copy of a global extended key list.
func cloneXPubs(xPubs []psbt.XPub) []psbt.XPub {
	if xPubs == nil {
		return nil
	}

	clone := make([]psbt.XPub, len(xPubs))
	for i, x := range xPubs {
		clone[i] = psbt.XPub{
			ExtendedKey:          bytes.Clone(x.ExtendedKey),
			MasterKeyFingerprint: x.MasterKeyFingerprint,
			Bip32Path:            slices.Clone(x.Bip32Path),
		}
	}

	return clone
}

// cloneUnknowns returns a deep copy of an unclassified field list. The wallet
// refuses to transform packets that carry these, but cloning must still be
// faithful for the validator to be able to report on them.
func cloneUnknowns(unknowns []*psbt.Unknown) []*psbt.Unknown {
	if unknowns == nil {
		return nil
	}

	clone := make([]*psbt.Unknown, len(unknowns))
	for i, u := range unknowns {
		if u == nil {
			continue
		}

		clone[i] = &psbt.Unknown{
			Key:   bytes.Clone(u.Key),
			Value: bytes.Clone(u.Value),
		}
	}

	return clone
}
