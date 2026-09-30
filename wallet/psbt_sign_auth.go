// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"errors"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// ErrInvalidSignatureRecord is returned when a packet carries an existing
// signature record that does not verify for the input it sits on.
var ErrInvalidSignatureRecord = errors.New("invalid psbt signature record")

// authorizeSignRecords checks the existing signature records in a packet
// against the input each sits on. It uses no wallet state.
func authorizeSignRecords(packet *psbt.Packet, sigHashes *txscript.TxSigHashes,
	prevOuts txscript.PrevOutputFetcher) error {

	for i := range packet.Inputs {
		pIn := &packet.Inputs[i]

		if len(pIn.TaprootScriptSpendSig) == 0 &&
			pIn.TaprootKeySpendSig == nil {

			continue
		}

		utxo, err := fetchPsbtUtxo(packet, i)
		if err != nil {
			return err
		}

		err = authorizeTaprootScriptSpendSigs(
			packet, i, utxo, sigHashes, prevOuts,
		)
		if err != nil {
			return fmt.Errorf("%w: input %d: %w",
				ErrInvalidSignatureRecord, i, err)
		}

		err = authorizeTaprootKeySpendSig(
			packet, i, utxo, sigHashes, prevOuts,
		)
		if err != nil {
			return fmt.Errorf("%w: input %d: %w",
				ErrInvalidSignatureRecord, i, err)
		}
	}

	return nil
}

// authorizeTaprootScriptSpendSigs checks an input's Taproot script-path
// records.
func authorizeTaprootScriptSpendSigs(packet *psbt.Packet, idx int,
	utxo *wire.TxOut, sigHashes *txscript.TxSigHashes,
	prevOuts txscript.PrevOutputFetcher) error {

	pIn := &packet.Inputs[idx]
	if len(pIn.TaprootScriptSpendSig) == 0 {
		return nil
	}

	if txscript.GetScriptClass(utxo.PkScript) !=
		txscript.WitnessV1TaprootTy {

		return errors.New("script spend signature on a non-taproot " +
			"output")
	}

	seen := make(map[string]struct{}, len(pIn.TaprootScriptSpendSig))
	for _, sig := range pIn.TaprootScriptSpendSig {
		id := string(sig.XOnlyPubKey) + string(sig.LeafHash)
		if _, ok := seen[id]; ok {
			return errors.New("two script spend signatures for one " +
				"key and leaf")
		}

		seen[id] = struct{}{}

		leaf, err := committedTapLeaf(pIn, utxo.PkScript[2:34], sig)
		if err != nil {
			return err
		}

		if !scriptCommitsToKey(leaf.Script, sig.XOnlyPubKey) {
			return errors.New("script spend signature key is not " +
				"committed to by its leaf")
		}

		if !taprootSigHashAllowed(sig.SigHash, pIn.SighashType) {
			return fmt.Errorf("script spend signature sighash %#x, "+
				"input requests %#x", uint32(sig.SigHash),
				uint32(pIn.SighashType))
		}

		digest, err := tapscriptDigest(
			sigHashes, sig.SigHash, packet.UnsignedTx, idx,
			prevOuts, leaf,
		)
		if err != nil {
			return fmt.Errorf("script spend digest: %w", err)
		}

		err = verifySchnorr(sig.Signature, digest, sig.XOnlyPubKey)
		if err != nil {
			return fmt.Errorf("script spend signature: %w", err)
		}
	}

	return nil
}

// committedTapLeaf returns the leaf a script-path record names, once one of
// the input's leaf scripts both hashes to it and is proven into the output
// key by its control block, under the same leaf version.
func committedTapLeaf(pIn *psbt.PInput, outputKey []byte,
	sig *psbt.TaprootScriptSpendSig) (txscript.TapLeaf, error) {

	for _, leafScript := range pIn.TaprootLeafScript {
		leaf := txscript.TapLeaf{
			LeafVersion: leafScript.LeafVersion,
			Script:      leafScript.Script,
		}

		leafHash := leaf.TapHash()
		if !bytes.Equal(leafHash[:], sig.LeafHash) {
			continue
		}

		controlBlock, err := txscript.ParseControlBlock(
			leafScript.ControlBlock,
		)
		if err != nil {
			continue
		}

		// The spend runs the leaf version its control block names.
		if controlBlock.LeafVersion != leafScript.LeafVersion {
			continue
		}

		err = txscript.VerifyTaprootLeafCommitment(
			controlBlock, outputKey, leaf.Script,
		)
		if err != nil {
			continue
		}

		return leaf, nil
	}

	return txscript.TapLeaf{}, errors.New("script spend signature " +
		"names no leaf the output commits to")
}

// authorizeTaprootKeySpendSig checks an input's Taproot key-path record
// against the output key.
func authorizeTaprootKeySpendSig(packet *psbt.Packet, idx int,
	utxo *wire.TxOut, sigHashes *txscript.TxSigHashes,
	prevOuts txscript.PrevOutputFetcher) error {

	pIn := &packet.Inputs[idx]

	sig := pIn.TaprootKeySpendSig
	if sig == nil {
		return nil
	}

	if txscript.GetScriptClass(utxo.PkScript) !=
		txscript.WitnessV1TaprootTy {

		return errors.New("key spend signature on a non-taproot output")
	}

	// A default sighash is encoded by omitting the byte, so an explicit
	// zero byte is invalid. Other lengths fail to parse below.
	hashType := txscript.SigHashDefault
	if len(sig) == schnorr.SignatureSize+1 {
		hashType = txscript.SigHashType(sig[schnorr.SignatureSize])
		if hashType == txscript.SigHashDefault {
			return errors.New("key spend signature encodes the " +
				"default sighash explicitly")
		}

		sig = sig[:schnorr.SignatureSize]
	}

	if !taprootSigHashAllowed(hashType, pIn.SighashType) {
		return fmt.Errorf("key spend signature sighash %#x, input "+
			"requests %#x", uint32(hashType),
			uint32(pIn.SighashType))
	}

	digest, err := txscript.CalcTaprootSignatureHash(
		sigHashes, hashType, packet.UnsignedTx, idx, prevOuts,
	)
	if err != nil {
		return fmt.Errorf("key spend digest: %w", err)
	}

	err = verifySchnorr(sig, digest, utxo.PkScript[2:34])
	if err != nil {
		return fmt.Errorf("key spend signature: %w", err)
	}

	return nil
}

// taprootSigHashAllowed reports whether a Taproot signature's sighash is one
// its input allows. An input that sets a sighash type allows only that type.
// One that sets none allows SIGHASH_DEFAULT, the BIP 371 default, and an
// explicit SIGHASH_ALL, which commits to the same transaction data.
func taprootSigHashAllowed(sigHash, inputSigHash txscript.SigHashType) bool {
	if inputSigHash != txscript.SigHashDefault {
		return sigHash == inputSigHash
	}

	return sigHash == txscript.SigHashDefault ||
		sigHash == txscript.SigHashAll
}

// tapscriptDigest returns the sighash a script-path signature on a leaf signs,
// including the position of the last code separator the leaf runs.
func tapscriptDigest(sigHashes *txscript.TxSigHashes,
	sigHash txscript.SigHashType, tx *wire.MsgTx, idx int,
	prevOuts txscript.PrevOutputFetcher,
	leaf txscript.TapLeaf) ([]byte, error) {

	_, codeSepPos, err := lastCodeSeparator(leaf.Script)
	if err != nil {
		return nil, err
	}

	leafHash := leaf.TapHash()

	return txscript.CalcTapscriptSignaturehash(
		sigHashes, sigHash, tx, idx, prevOuts, leaf,
		txscript.WithBaseTapscriptVersion(codeSepPos, leafHash[:]),
	)
}

// lastCodeSeparator returns the byte offset just past a script's last
// OP_CODESEPARATOR and that opcode's position, as the script engine counts
// them. A script without one gives offset 0 and position math.MaxUint32, the
// engine's values before any separator runs.
//
// It fails when a separator's context cannot be told from the script alone:
// the script branches, or checks a signature before its last separator. It
// also fails on a script that does not parse.
func lastCodeSeparator(script []byte) (int, uint32, error) {
	var (
		offset    int
		pos       uint32 = math.MaxUint32
		found     bool
		branches  bool
		sigOps    bool
		sigBefore bool
	)

	tokenizer := txscript.MakeScriptTokenizer(0, script)
	for tokenizer.Next() {
		switch tokenizer.Opcode() {
		case txscript.OP_IF, txscript.OP_NOTIF, txscript.OP_ELSE,
			txscript.OP_ENDIF:

			branches = true

		case txscript.OP_CHECKSIG, txscript.OP_CHECKSIGVERIFY,
			txscript.OP_CHECKMULTISIG, txscript.OP_CHECKMULTISIGVERIFY,
			txscript.OP_CHECKSIGADD:

			sigOps = true

		case txscript.OP_CODESEPARATOR:
			found = true
			sigBefore = sigOps
			offset = int(tokenizer.ByteIndex())

			//nolint:gosec // Not negative once Next returns an opcode.
			pos = uint32(tokenizer.OpcodePosition())
		}
	}

	err := tokenizer.Err()
	if err != nil {
		return 0, math.MaxUint32, fmt.Errorf("script does not parse: %w",
			err)
	}

	if found && (branches || sigBefore) {
		return 0, math.MaxUint32, errors.New("code separator context " +
			"is ambiguous")
	}

	return offset, pos, nil
}

// verifySchnorr checks a bare 64-byte Schnorr signature over a digest.
func verifySchnorr(sig, digest, xOnlyKey []byte) error {
	key, err := schnorr.ParsePubKey(xOnlyKey)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}

	parsed, err := schnorr.ParseSignature(sig)
	if err != nil {
		return err
	}

	if !parsed.Verify(digest, key) {
		return errors.New("does not verify")
	}

	return nil
}

// scriptCommitsToKey reports whether a script pushes a key or its hash.
func scriptCommitsToKey(script, key []byte) bool {
	return scriptPushesData(script, key) ||
		scriptPushesData(script, address.Hash160(key))
}

// scriptPushesData reports whether a script pushes exactly the given data.
func scriptPushesData(script, data []byte) bool {
	// Opcodes that push nothing report nil data, which would match.
	if len(data) == 0 {
		return false
	}

	tokenizer := txscript.MakeScriptTokenizer(0, script)
	for tokenizer.Next() {
		if bytes.Equal(tokenizer.Data(), data) {
			return true
		}
	}

	return false
}
