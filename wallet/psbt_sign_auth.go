// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// ErrInvalidSignatureRecord is returned when a packet carries an existing
// signature record that does not verify for the input it sits on.
var ErrInvalidSignatureRecord = errors.New("invalid psbt signature record")

// ecdsaScriptContext is what an ECDSA signature on one input commits to.
type ecdsaScriptContext struct {
	// script is the script the spend runs. The sighash covers it from
	// its last code separator.
	script []byte

	// witness is true for a segwit v0 spend.
	witness bool

	// keyHash is the key hash the spend commits to, for the key-hash
	// forms. It is nil for script forms.
	keyHash []byte
}

// authorizeSignRecords checks the existing signature records in a packet
// against the input each sits on. It uses no wallet state.
func authorizeSignRecords(packet *psbt.Packet, sigHashes *txscript.TxSigHashes,
	prevOuts txscript.PrevOutputFetcher) error {

	for i := range packet.Inputs {
		pIn := &packet.Inputs[i]

		if len(pIn.PartialSigs) == 0 &&
			len(pIn.TaprootScriptSpendSig) == 0 &&
			pIn.TaprootKeySpendSig == nil {

			continue
		}

		utxo, err := fetchPsbtUtxo(packet, i)
		if err != nil {
			return err
		}

		err = authorizePartialSigs(packet, i, utxo, sigHashes)
		if err != nil {
			return fmt.Errorf("%w: input %d: %w",
				ErrInvalidSignatureRecord, i, err)
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

// authorizePartialSigs checks an input's ECDSA records.
func authorizePartialSigs(packet *psbt.Packet, idx int, utxo *wire.TxOut,
	sigHashes *txscript.TxSigHashes) error {

	pIn := &packet.Inputs[idx]
	if len(pIn.PartialSigs) == 0 {
		return nil
	}

	scriptCtx, err := ecdsaScriptFor(pIn, utxo)
	if err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(pIn.PartialSigs))
	for _, sig := range pIn.PartialSigs {
		if _, ok := seen[string(sig.PubKey)]; ok {
			return errors.New("two partial signatures for one key")
		}

		seen[string(sig.PubKey)] = struct{}{}

		err := authorizePartialSig(
			packet.UnsignedTx, idx, utxo, pIn.SighashType,
			scriptCtx, sigHashes, sig,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

// authorizePartialSig checks one ECDSA record against its input.
func authorizePartialSig(tx *wire.MsgTx, idx int, utxo *wire.TxOut,
	hashType txscript.SigHashType, scriptCtx ecdsaScriptContext,
	sigHashes *txscript.TxSigHashes, sig *psbt.PartialSig) error {

	pubKey, err := btcec.ParsePubKey(sig.PubKey)
	if err != nil {
		return fmt.Errorf("partial signature key: %w", err)
	}

	err = scriptCtx.checkKey(sig.PubKey)
	if err != nil {
		return err
	}

	if len(sig.Signature) == 0 {
		return errors.New("empty partial signature")
	}

	sigHash := txscript.SigHashType(sig.Signature[len(sig.Signature)-1])
	if !ecdsaSigHashAllowed(sigHash, hashType) {
		return fmt.Errorf("partial signature sighash %#x, input "+
			"requests %#x", uint32(sigHash), uint32(hashType))
	}

	parsed, err := parseStrictDER(sig.Signature[:len(sig.Signature)-1])
	if err != nil {
		return fmt.Errorf("partial signature: %w", err)
	}

	digest, err := scriptCtx.digest(tx, idx, utxo, sigHash, sigHashes)
	if err != nil {
		return fmt.Errorf("partial signature digest: %w", err)
	}

	if !parsed.Verify(digest, pubKey) {
		return errors.New("partial signature does not verify")
	}

	return nil
}

// ecdsaSigHashAllowed reports whether a partial signature's sighash is one its
// input allows. An input that sets a sighash type allows only that type. One
// that sets none allows SIGHASH_ALL, the BIP 174 default, and the zero byte
// this wallet currently signs with in that case.
func ecdsaSigHashAllowed(sigHash, inputSigHash txscript.SigHashType) bool {
	if inputSigHash != txscript.SigHashDefault {
		return sigHash == inputSigHash
	}

	// TODO: drop the zero byte once the wallet signs such inputs with
	// SIGHASH_ALL. A spend that uses it is non-standard.
	return sigHash == txscript.SigHashAll ||
		sigHash == txscript.SigHashDefault
}

// checkKey checks that the spend commits to a key: by hash for the key-hash
// forms, and otherwise by a push of the key or its hash in the script.
func (c ecdsaScriptContext) checkKey(pubKey []byte) error {
	if c.keyHash != nil {
		if !bytes.Equal(address.Hash160(pubKey), c.keyHash) {
			return errors.New("partial signature key is not the " +
				"key the output pays")
		}

		return nil
	}

	if !scriptCommitsToKey(c.script, pubKey) {
		return errors.New("partial signature key is not committed " +
			"to by the spent script")
	}

	return nil
}

// digest returns the sighash an ECDSA signature on the input signs, over the
// script from the last code separator it runs.
func (c ecdsaScriptContext) digest(tx *wire.MsgTx, idx int, utxo *wire.TxOut,
	hashType txscript.SigHashType,
	sigHashes *txscript.TxSigHashes) ([]byte, error) {

	offset, _, err := lastCodeSeparator(c.script)
	if err != nil {
		return nil, err
	}

	scriptCode := c.script[offset:]
	if c.witness {
		return txscript.CalcWitnessSigHash(
			scriptCode, sigHashes, hashType, tx, idx, utxo.Value,
		)
	}

	return txscript.CalcSignatureHash(scriptCode, hashType, tx, idx)
}

// parseStrictDER parses a DER signature and refuses any bytes after it, which
// ParseDERSignature ignores and the script engine rejects.
func parseStrictDER(der []byte) (*ecdsa.Signature, error) {
	sig, err := ecdsa.ParseDERSignature(der)
	if err != nil {
		return nil, err
	}

	// The sequence tag and length byte, which a parsed signature has,
	// precede the length's worth of content.
	const header = 2

	end := header + int(der[1])
	if len(der) != end {
		return nil, fmt.Errorf("%d bytes after the DER signature",
			len(der)-end)
	}

	return sig, nil
}

// ecdsaScriptFor resolves what an ECDSA signature on an input commits to. A
// redeem or witness script is used only once the output is shown to commit to
// it.
func ecdsaScriptFor(pIn *psbt.PInput,
	utxo *wire.TxOut) (ecdsaScriptContext, error) {

	pkScript := utxo.PkScript

	//nolint:exhaustive // Any other class uses the output script as the
	// script code.
	switch txscript.GetScriptClass(pkScript) {
	case txscript.PubKeyHashTy:
		return ecdsaScriptContext{
			script:  pkScript,
			keyHash: pkScript[3:23],
		}, nil

	case txscript.WitnessV0PubKeyHashTy:
		return ecdsaScriptContext{
			script:  pkScript,
			witness: true,
			keyHash: pkScript[2:22],
		}, nil

	case txscript.WitnessV0ScriptHashTy:
		return witnessScriptFor(pIn, pkScript[2:34])

	case txscript.ScriptHashTy:
		return redeemScriptFor(pIn, pkScript[2:22])

	default:
		return ecdsaScriptContext{script: pkScript}, nil
	}
}

// redeemScriptFor resolves a P2SH spend through its redeem script.
func redeemScriptFor(pIn *psbt.PInput,
	scriptHash []byte) (ecdsaScriptContext, error) {

	redeem := pIn.RedeemScript
	if !bytes.Equal(address.Hash160(redeem), scriptHash) {
		return ecdsaScriptContext{}, errors.New("redeem script does " +
			"not match the output")
	}

	//nolint:exhaustive // Any other redeem script is the script code.
	switch txscript.GetScriptClass(redeem) {
	case txscript.WitnessV0PubKeyHashTy:
		return ecdsaScriptContext{
			script:  redeem,
			witness: true,
			keyHash: redeem[2:22],
		}, nil

	case txscript.WitnessV0ScriptHashTy:
		return witnessScriptFor(pIn, redeem[2:34])

	default:
		return ecdsaScriptContext{script: redeem}, nil
	}
}

// witnessScriptFor resolves a P2WSH spend through its witness script.
func witnessScriptFor(pIn *psbt.PInput,
	program []byte) (ecdsaScriptContext, error) {

	hash := sha256.Sum256(pIn.WitnessScript)
	if !bytes.Equal(hash[:], program) {
		return ecdsaScriptContext{}, errors.New("witness script does " +
			"not match the output")
	}

	return ecdsaScriptContext{
		script:  pIn.WitnessScript,
		witness: true,
	}, nil
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
