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
	"slices"

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

// ErrSigningKeyMismatch is returned when the key SignPsbt would sign an input
// with is not one the input's script checks, or not the key the wallet
// derives for it.
var ErrSigningKeyMismatch = errors.New("signing key does not satisfy the " +
	"psbt input")

// ecdsaScriptContext is what an ECDSA signature on one input commits to.
type ecdsaScriptContext struct {
	// script is the script the spend runs.
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

	scriptCodes := scriptCtx.scriptCodes(sig.PubKey)

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

	for _, scriptCode := range scriptCodes {
		digest, err := scriptCtx.digest(
			scriptCode, tx, idx, utxo, sigHash, sigHashes,
		)
		if err != nil {
			return fmt.Errorf("partial signature digest: %w", err)
		}

		if parsed.Verify(digest, pubKey) {
			return nil
		}
	}

	return errors.New("partial signature does not verify against a " +
		"signature check that uses its key")
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

// scriptCodes returns the script codes an ECDSA signature by a key may sign:
// the script itself for the key-hash forms when the key is the one the output
// pays, and otherwise the script from the code separator of each signature
// check shown to use the key.
func (c ecdsaScriptContext) scriptCodes(pubKey []byte) [][]byte {
	if c.keyHash != nil {
		if !bytes.Equal(address.Hash160(pubKey), c.keyHash) {
			return nil
		}

		return [][]byte{c.script}
	}

	checks := keySigChecks(c.script, pubKey)

	scriptCodes := make([][]byte, 0, len(checks))
	for _, check := range checks {
		scriptCodes = append(scriptCodes, c.script[check.codeOffset:])
	}

	return scriptCodes
}

// digest returns the sighash an ECDSA signature on the input signs over a
// script code.
func (c ecdsaScriptContext) digest(scriptCode []byte, tx *wire.MsgTx, idx int,
	utxo *wire.TxOut, hashType txscript.SigHashType,
	sigHashes *txscript.TxSigHashes) ([]byte, error) {

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

		leaf, err := committedTapLeaf(
			pIn, utxo.PkScript[2:34], sig.LeafHash,
		)
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

// committedTapLeaf returns the leaf with the given hash, once one of the
// input's leaf scripts both hashes to it and is proven into the output key by
// its control block, under the same leaf version.
func committedTapLeaf(pIn *psbt.PInput, outputKey []byte,
	leafHash []byte) (txscript.TapLeaf, error) {

	for _, leafScript := range pIn.TaprootLeafScript {
		leaf := txscript.TapLeaf{
			LeafVersion: leafScript.LeafVersion,
			Script:      leafScript.Script,
		}

		hash := leaf.TapHash()
		if !bytes.Equal(hash[:], leafHash) {
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

// ecdsaSignerKey returns the key a derivation record's key becomes under a
// tweak, as a PSBT record names it. An untweaked key keeps the record's bytes.
func ecdsaSignerKey(record []byte, tweak KeyTweak) ([]byte, error) {
	base, err := btcec.ParsePubKey(record)
	if err != nil {
		return nil, fmt.Errorf("%w: derivation key: %w",
			ErrInvalidSignParam, err)
	}

	if tweak == (KeyTweak{}) {
		return record, nil
	}

	key, err := tweak.pubKey(base)
	if err != nil {
		return nil, err
	}

	return key.SerializeCompressed(), nil
}

// ecdsaSignerScript returns what a new ECDSA signature by key on an input
// signs over, once the input's script is shown to check that key over the
// whole script.
func ecdsaSignerScript(pIn *psbt.PInput, utxo *wire.TxOut,
	key []byte) (ecdsaScriptContext, error) {

	scriptCtx, err := ecdsaScriptFor(pIn, utxo)
	if err != nil {
		return ecdsaScriptContext{}, fmt.Errorf("%w: %w",
			ErrSigningKeyMismatch, err)
	}

	// Segwit v0 spends accept only compressed keys.
	if scriptCtx.witness && len(key) != btcec.PubKeyBytesLenCompressed {
		return ecdsaScriptContext{}, fmt.Errorf("%w: uncompressed "+
			"segwit key", ErrSigningKeyMismatch)
	}

	checksKey := slices.ContainsFunc(
		scriptCtx.scriptCodes(key), func(code []byte) bool {
			return bytes.Equal(code, scriptCtx.script)
		},
	)
	if !checksKey {
		return ecdsaScriptContext{}, fmt.Errorf("%w: script does not "+
			"check the key", ErrSigningKeyMismatch)
	}

	return scriptCtx, nil
}

// authorizeTaprootSigner checks that the key a Taproot derivation names is
// the one its spend uses: the output's internal key on the key path, or a key
// a committed leaf checks on the script path.
func authorizeTaprootSigner(pIn *psbt.PInput, utxo *wire.TxOut,
	derivation *psbt.TaprootBip32Derivation) error {

	if txscript.GetScriptClass(utxo.PkScript) !=
		txscript.WitnessV1TaprootTy {

		return fmt.Errorf("%w: output is not taproot",
			ErrSigningKeyMismatch)
	}

	outputKey := utxo.PkScript[2:34]
	key := derivation.XOnlyPubKey

	if len(derivation.LeafHashes) == 0 {
		if len(pIn.TaprootInternalKey) > 0 &&
			!bytes.Equal(pIn.TaprootInternalKey, key) {

			return fmt.Errorf("%w: internal key is not the "+
				"derivation key", ErrSigningKeyMismatch)
		}

		internalKey, err := schnorr.ParsePubKey(key)
		if err != nil {
			return fmt.Errorf("%w: derivation key: %w",
				ErrSigningKeyMismatch, err)
		}

		tweaked := txscript.ComputeTaprootOutputKey(
			internalKey, pIn.TaprootMerkleRoot,
		)
		if !bytes.Equal(schnorr.SerializePubKey(tweaked), outputKey) {
			return fmt.Errorf("%w: output key is not the "+
				"derivation key", ErrSigningKeyMismatch)
		}

		return nil
	}

	leaf, err := committedTapLeaf(pIn, outputKey, derivation.LeafHashes[0])
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSigningKeyMismatch, err)
	}

	// The wallet signs base-version leaves with no code separator.
	if leaf.LeafVersion != txscript.BaseLeafVersion {
		return fmt.Errorf("%w: leaf version %#x",
			ErrSigningKeyMismatch, uint8(leaf.LeafVersion))
	}

	checksKey := slices.ContainsFunc(
		keySigChecks(leaf.Script, key), func(check sigCheck) bool {
			return check.codeSepPos == math.MaxUint32
		},
	)
	if !checksKey {
		return fmt.Errorf("%w: leaf does not check the key",
			ErrSigningKeyMismatch)
	}

	return nil
}

// recordKeyIs reports whether the key a PSBT record names is pub: by x-only
// form for a 32-byte key, otherwise as a serialized key.
func recordKeyIs(record []byte, pub *btcec.PublicKey) bool {
	if len(record) == schnorr.PubKeyBytesLen {
		return bytes.Equal(record, schnorr.SerializePubKey(pub))
	}

	key, err := btcec.ParsePubKey(record)

	return err == nil && key.IsEqual(pub)
}
