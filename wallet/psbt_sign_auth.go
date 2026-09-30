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

		if !taprootSigHashAllowed(sig.SigHash, pIn.SighashType) {
			return fmt.Errorf("script spend signature sighash %#x, "+
				"input requests %#x", uint32(sig.SigHash),
				uint32(pIn.SighashType))
		}

		err = verifyScriptSpendSig(
			sigHashes, packet.UnsignedTx, idx, prevOuts, leaf, sig,
		)
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

// verifyScriptSpendSig checks a script-path signature against the leaf's
// signature checks that use its key, each under the code separator it runs.
func verifyScriptSpendSig(sigHashes *txscript.TxSigHashes, tx *wire.MsgTx,
	idx int, prevOuts txscript.PrevOutputFetcher, leaf txscript.TapLeaf,
	sig *psbt.TaprootScriptSpendSig) error {

	leafHash := leaf.TapHash()
	for _, check := range keySigChecks(leaf.Script, sig.XOnlyPubKey) {
		digest, err := txscript.CalcTapscriptSignaturehash(
			sigHashes, sig.SigHash, tx, idx, prevOuts, leaf,
			txscript.WithBaseTapscriptVersion(
				check.codeSepPos, leafHash[:],
			),
		)
		if err != nil {
			return err
		}

		if verifySchnorr(sig.Signature, digest, sig.XOnlyPubKey) == nil {
			return nil
		}
	}

	return errors.New("does not verify against a signature check that " +
		"uses its key")
}

// sigCheck is a signature check a script runs, as far as the script alone
// shows it.
type sigCheck struct {
	// keys are the keys the check is shown to use. keyHash is set instead
	// when the script commits to the key only by its HASH160.
	keys    [][]byte
	keyHash []byte

	// codeOffset is the byte offset just past the last code separator
	// before the check, and codeSepPos that separator's opcode position,
	// as the script engine counts them. Without one they are 0 and
	// math.MaxUint32.
	codeOffset int
	codeSepPos uint32

	// ambiguous is set when that separator sits inside a branch, so it
	// may not have run before the check.
	ambiguous bool
}

// uses reports whether the check is shown to use a key.
func (c sigCheck) uses(key []byte) bool {
	for _, k := range c.keys {
		if bytes.Equal(k, key) {
			return true
		}
	}

	return c.keyHash != nil && bytes.Equal(c.keyHash, address.Hash160(key))
}

// keySigChecks returns the signature checks in a script that are shown to use
// a key and run under a known code separator context. A script that does not
// parse has none.
//
// A check is only shown to use a key in these shapes, ignoring code
// separators, which leave the stack alone: the key pushed right before
// OP_CHECKSIG, OP_CHECKSIGVERIFY or OP_CHECKSIGADD; OP_DUP OP_HASH160 <hash>
// OP_EQUALVERIFY right before one of those; or the keys pushed right before
// <n> OP_CHECKMULTISIG or OP_CHECKMULTISIGVERIFY. A key that reaches its
// check any other way is not recognized.
func keySigChecks(script, key []byte) []sigCheck {
	var known []sigCheck
	for _, check := range scriptSigChecks(script) {
		if check.uses(key) && !check.ambiguous {
			known = append(known, check)
		}
	}

	return known
}

// scriptSigChecks returns the signature checks in a script, each with the code
// separator context it runs under.
func scriptSigChecks(script []byte) []sigCheck {
	ops := parseScriptOps(script)

	var (
		checks []sigCheck
		depth  int

		// context is the code separator context at the current op.
		context = sigCheck{codeSepPos: math.MaxUint32}

		// stackOps are the ops so far that act on the stack.
		stackOps = make([]scriptOp, 0, len(ops))
	)
	for _, op := range ops {
		switch op.opcode {
		case txscript.OP_IF, txscript.OP_NOTIF:
			depth++

		case txscript.OP_ENDIF:
			depth--

		case txscript.OP_CODESEPARATOR:
			context = sigCheck{
				codeOffset: op.end,
				codeSepPos: op.pos,
				ambiguous:  depth > 0,
			}

			continue

		case txscript.OP_CHECKSIG, txscript.OP_CHECKSIGVERIFY,
			txscript.OP_CHECKSIGADD, txscript.OP_CHECKMULTISIG,
			txscript.OP_CHECKMULTISIGVERIFY:

			check := context
			check.keys, check.keyHash = checkKeys(stackOps, op.opcode)
			checks = append(checks, check)
		}

		stackOps = append(stackOps, op)
	}

	return checks
}

// keyHashShapeLen is the length of OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY.
const keyHashShapeLen = 4

// checkKeys reads the keys a signature check uses from the ops before it, in
// the shapes keySigChecks describes.
func checkKeys(before []scriptOp, opcode byte) ([][]byte, []byte) {
	// tail is the last ops, padded at the front with OP_0s, which no
	// shape matches.
	var tail [keyHashShapeLen]scriptOp
	copy(
		tail[max(0, len(tail)-len(before)):],
		before[max(0, len(before)-len(tail)):],
	)

	switch {
	case opcode == txscript.OP_CHECKMULTISIG ||
		opcode == txscript.OP_CHECKMULTISIGVERIFY:

		return multisigKeys(before, tail[len(tail)-1].opcode), nil

	case len(tail[len(tail)-1].data) > 0:
		return [][]byte{tail[len(tail)-1].data}, nil

	case tail[0].opcode == txscript.OP_DUP &&
		tail[1].opcode == txscript.OP_HASH160 &&
		len(tail[2].data) == ripemd160Size &&
		tail[3].opcode == txscript.OP_EQUALVERIFY:

		return nil, tail[2].data
	}

	return nil, nil
}

// multisigKeys reads the keys pushed right before <n> OP_CHECKMULTISIG, where
// countOp is the last op before it.
func multisigKeys(before []scriptOp, countOp byte) [][]byte {
	count := int(countOp) - int(txscript.OP_1) + 1
	if count < 1 || countOp > txscript.OP_16 || count > len(before)-1 {
		return nil
	}

	keys := make([][]byte, 0, count)
	for _, op := range before[len(before)-1-count : len(before)-1] {
		if len(op.data) == 0 {
			return nil
		}

		keys = append(keys, op.data)
	}

	return keys
}

// ripemd160Size is the size of a HASH160.
const ripemd160Size = 20

// scriptOp is one parsed op of a script.
type scriptOp struct {
	opcode byte
	data   []byte

	// end is the byte offset just past the op, and pos its position, as
	// the script engine counts them.
	end int
	pos uint32
}

// parseScriptOps parses a script the way the script engine reads it. It
// returns nil for a script that does not parse.
func parseScriptOps(script []byte) []scriptOp {
	var ops []scriptOp

	tokenizer := txscript.MakeScriptTokenizer(0, script)
	for tokenizer.Next() {
		ops = append(ops, scriptOp{
			opcode: tokenizer.Opcode(),
			data:   tokenizer.Data(),
			end:    int(tokenizer.ByteIndex()),

			//nolint:gosec // Not negative once Next returns an op.
			pos: uint32(tokenizer.OpcodePosition()),
		})
	}

	if tokenizer.Err() != nil {
		return nil
	}

	return ops
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
