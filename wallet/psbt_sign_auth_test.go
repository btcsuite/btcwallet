// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"math"
	"slices"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// testAuthKeys returns two deterministic private keys, so a fixture can sign
// with one key and name another.
func testAuthKeys() [2]*btcec.PrivateKey {
	first, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{1}, 32))
	second, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{2}, 32))

	return [2]*btcec.PrivateKey{first, second}
}

// testAuthPacket returns a one-input packet spending utxo at the given input
// sighash, along with the sighash cache and prevout fetcher for it.
func testAuthPacket(t *testing.T, utxo *wire.TxOut,
	hashType txscript.SigHashType) (*psbt.Packet, *txscript.TxSigHashes,
	txscript.PrevOutputFetcher) {

	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 3}})
	tx.AddTxOut(&wire.TxOut{Value: 500, PkScript: []byte{txscript.OP_TRUE}})

	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	packet.Inputs[0].WitnessUtxo = utxo
	packet.Inputs[0].SighashType = hashType

	prevOuts, err := PsbtPrevOutputFetcher(packet)
	require.NoError(t, err)

	return packet, txscript.NewTxSigHashes(tx, prevOuts), prevOuts
}

// testP2WPKHScript returns the P2WPKH output script paying a key.
func testP2WPKHScript(t *testing.T, key *btcec.PublicKey) []byte {
	t.Helper()

	addr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(key.SerializeCompressed()), &chainParams,
	)
	require.NoError(t, err)

	script, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	return script
}

// testTapscriptFixture returns a Taproot output with one leaf,
// `<key 0> OP_CHECKSIG`, under internal key 1, along with that leaf and the
// leaf script record proving it into the output.
func testTapscriptFixture(t *testing.T, keys [2]*btcec.PrivateKey) (
	*wire.TxOut, txscript.TapLeaf, *psbt.TaprootTapLeafScript) {

	t.Helper()

	script, err := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(keys[0].PubKey())).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	leaf := txscript.NewBaseTapLeaf(script)
	tree := txscript.AssembleTaprootScriptTree(leaf)
	root := tree.RootNode.TapHash()

	internalKey := keys[1].PubKey()
	outputKey := txscript.ComputeTaprootOutputKey(internalKey, root[:])
	pkScript, err := txscript.PayToTaprootScript(outputKey)
	require.NoError(t, err)

	controlBlock := tree.LeafMerkleProofs[0].ToControlBlock(internalKey)
	controlBytes, err := controlBlock.ToBytes()
	require.NoError(t, err)

	leafScript := &psbt.TaprootTapLeafScript{
		ControlBlock: controlBytes,
		Script:       script,
		LeafVersion:  txscript.BaseLeafVersion,
	}

	return &wire.TxOut{Value: 1000, PkScript: pkScript}, leaf, leafScript
}

// TestAuthorizeSignRecordsScriptSpend verifies that a Taproot script-path
// record is kept only when the leaf commits to its key, its sighash is one its
// input allows, and it verifies over that leaf's digest.
func TestAuthorizeSignRecordsScriptSpend(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		// signer is the key that produces the signature.
		signer int

		// recordKey is the key the record names.
		recordKey int

		// sigHash is the sighash the signature is made with and the
		// record claims. The input sets none.
		sigHash txscript.SigHashType

		// wantErr is nil for a record that passes.
		wantErr error
	}{{
		name: "valid",
	}, {
		name:    "signed by another key",
		signer:  1,
		wantErr: ErrInvalidSignatureRecord,
	}, {
		name:      "key not in the leaf",
		signer:    1,
		recordKey: 1,
		wantErr:   ErrInvalidSignatureRecord,
	}, {
		name:    "explicit sighash all on an unset input",
		sigHash: txscript.SigHashAll,
	}, {
		name:    "other sighash",
		sigHash: txscript.SigHashNone,
		wantErr: ErrInvalidSignatureRecord,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: the one-leaf output and a record signed as
			// the case describes.
			keys := testAuthKeys()
			utxo, leaf, leafScript := testTapscriptFixture(t, keys)
			packet, sigHashes, prevOuts := testAuthPacket(
				t, utxo, txscript.SigHashDefault,
			)
			packet.Inputs[0].TaprootLeafScript =
				[]*psbt.TaprootTapLeafScript{leafScript}

			sig, err := txscript.RawTxInTapscriptSignature(
				packet.UnsignedTx, sigHashes, 0, utxo.Value,
				utxo.PkScript, leaf, tc.sigHash,
				keys[tc.signer],
			)
			require.NoError(t, err)

			// The record holds the bare signature, with any sighash
			// byte the signer appended moved to its own field.
			leafHash := leaf.TapHash()
			recordKey := keys[tc.recordKey].PubKey()
			packet.Inputs[0].TaprootScriptSpendSig =
				[]*psbt.TaprootScriptSpendSig{{
					XOnlyPubKey: schnorr.SerializePubKey(
						recordKey,
					),
					LeafHash:  leafHash[:],
					Signature: sig[:schnorr.SignatureSize],
					SigHash:   tc.sigHash,
				}}

			// Act: authorize the packet's records.
			err = authorizeSignRecords(packet, sigHashes, prevOuts)

			// Assert: only the valid record passes.
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestAuthorizeSignRecordsScriptSpendHashCommittedKey verifies that a
// script-path record is kept when its leaf commits to the key by hash rather
// than pushing it.
func TestAuthorizeSignRecordsScriptSpendHashCommittedKey(t *testing.T) {
	t.Parallel()

	// Arrange: a one-leaf Taproot output whose leaf pushes only the hash
	// of key 0, and a valid signature over that leaf.
	keys := testAuthKeys()
	xOnlyKey := schnorr.SerializePubKey(keys[0].PubKey())
	script, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_DUP).
		AddOp(txscript.OP_HASH160).
		AddData(address.Hash160(xOnlyKey)).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	leaf := txscript.NewBaseTapLeaf(script)
	tree := txscript.AssembleTaprootScriptTree(leaf)
	root := tree.RootNode.TapHash()

	internalKey := keys[1].PubKey()
	pkScript, err := txscript.PayToTaprootScript(
		txscript.ComputeTaprootOutputKey(internalKey, root[:]),
	)
	require.NoError(t, err)

	controlBlock := tree.LeafMerkleProofs[0].ToControlBlock(internalKey)
	controlBytes, err := controlBlock.ToBytes()
	require.NoError(t, err)

	utxo := &wire.TxOut{Value: 1000, PkScript: pkScript}
	packet, sigHashes, prevOuts := testAuthPacket(
		t, utxo, txscript.SigHashDefault,
	)
	packet.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: controlBytes,
		Script:       script,
		LeafVersion:  txscript.BaseLeafVersion,
	}}

	sig, err := txscript.RawTxInTapscriptSignature(
		packet.UnsignedTx, sigHashes, 0, utxo.Value, pkScript, leaf,
		txscript.SigHashDefault, keys[0],
	)
	require.NoError(t, err)

	leafHash := leaf.TapHash()
	packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{{
		XOnlyPubKey: xOnlyKey,
		LeafHash:    leafHash[:],
		Signature:   sig,
	}}

	// Act: authorize the packet's records.
	err = authorizeSignRecords(packet, sigHashes, prevOuts)

	// Assert: the record passes.
	require.NoError(t, err)
}

// testOneLeafOutput returns a Taproot output committing to a single leaf with
// the given script under internal key 1, along with that leaf and the leaf
// script record proving it into the output.
func testOneLeafOutput(t *testing.T, keys [2]*btcec.PrivateKey,
	script []byte) (*wire.TxOut, txscript.TapLeaf,
	*psbt.TaprootTapLeafScript) {

	t.Helper()

	leaf := txscript.NewBaseTapLeaf(script)
	tree := txscript.AssembleTaprootScriptTree(leaf)
	root := tree.RootNode.TapHash()

	internalKey := keys[1].PubKey()
	pkScript, err := txscript.PayToTaprootScript(
		txscript.ComputeTaprootOutputKey(internalKey, root[:]),
	)
	require.NoError(t, err)

	controlBlock := tree.LeafMerkleProofs[0].ToControlBlock(internalKey)
	controlBytes, err := controlBlock.ToBytes()
	require.NoError(t, err)

	leafScript := &psbt.TaprootTapLeafScript{
		ControlBlock: controlBytes,
		Script:       script,
		LeafVersion:  txscript.BaseLeafVersion,
	}

	return &wire.TxOut{Value: 1000, PkScript: pkScript}, leaf, leafScript
}

// TestAuthorizeSignRecordsScriptSpendCodeSeparator verifies that a
// script-path record is checked under the code separator its leaf runs, and
// refused when that separator cannot be told from the leaf alone.
func TestAuthorizeSignRecordsScriptSpendCodeSeparator(t *testing.T) {
	t.Parallel()

	keys := testAuthKeys()
	key := schnorr.SerializePubKey(keys[0].PubKey())
	other := schnorr.SerializePubKey(keys[1].PubKey())

	build := func(b *txscript.ScriptBuilder) []byte {
		script, err := b.Script()
		require.NoError(t, err)

		return script
	}

	separated := build(txscript.NewScriptBuilder().
		AddData(key).
		AddOp(txscript.OP_CODESEPARATOR).
		AddOp(txscript.OP_CHECKSIG))
	branching := build(txscript.NewScriptBuilder().
		AddOp(txscript.OP_IF).
		AddOp(txscript.OP_CODESEPARATOR).
		AddOp(txscript.OP_ENDIF).
		AddData(key).
		AddOp(txscript.OP_CHECKSIG))
	checkedFirst := build(txscript.NewScriptBuilder().
		AddData(other).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddOp(txscript.OP_CODESEPARATOR).
		AddData(key).
		AddOp(txscript.OP_CHECKSIG))
	unparseable := append(
		build(txscript.NewScriptBuilder().
			AddData(key).
			AddOp(txscript.OP_CHECKSIG)),
		txscript.OP_PUSHDATA1,
	)

	tests := []struct {
		name string

		// script is the leaf the output commits to.
		script []byte

		// codeSepPos is the separator position the signature commits
		// to. math.MaxUint32 means no separator.
		codeSepPos uint32

		// wantErr is nil for a record that passes.
		wantErr error
	}{{
		name:       "separator the leaf runs",
		script:     separated,
		codeSepPos: 1,
	}, {
		name:       "signature that omits the separator",
		script:     separated,
		codeSepPos: math.MaxUint32,
		wantErr:    ErrInvalidSignatureRecord,
	}, {
		name:       "separator inside a branch",
		script:     branching,
		codeSepPos: 1,
		wantErr:    ErrInvalidSignatureRecord,
	}, {
		name:       "signature check before the separator",
		script:     checkedFirst,
		codeSepPos: 2,
		wantErr:    ErrInvalidSignatureRecord,
	}, {
		name:       "leaf that does not parse",
		script:     unparseable,
		codeSepPos: math.MaxUint32,
		wantErr:    ErrInvalidSignatureRecord,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: an output committing to the case's leaf, and
			// a signature by key 0 at the case's separator position.
			utxo, leaf, leafScript := testOneLeafOutput(
				t, keys, tc.script,
			)
			packet, sigHashes, prevOuts := testAuthPacket(
				t, utxo, txscript.SigHashDefault,
			)
			packet.Inputs[0].TaprootLeafScript =
				[]*psbt.TaprootTapLeafScript{leafScript}

			leafHash := leaf.TapHash()
			digest, err := txscript.CalcTapscriptSignaturehash(
				sigHashes, txscript.SigHashDefault,
				packet.UnsignedTx, 0, prevOuts, leaf,
				txscript.WithBaseTapscriptVersion(
					tc.codeSepPos, leafHash[:],
				),
			)
			require.NoError(t, err)

			sig, err := schnorr.Sign(keys[0], digest)
			require.NoError(t, err)

			packet.Inputs[0].TaprootScriptSpendSig =
				[]*psbt.TaprootScriptSpendSig{{
					XOnlyPubKey: key,
					LeafHash:    leafHash[:],
					Signature:   sig.Serialize(),
				}}

			// Act: authorize the packet's records.
			err = authorizeSignRecords(packet, sigHashes, prevOuts)

			// Assert: only the signature under the separator the
			// leaf runs passes.
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestAuthorizeSignRecordsScriptSpendLeaf verifies that a script-path record
// must name a leaf the output commits to: one the input carries, under a
// control block that proves it into the output key under the same leaf
// version.
func TestAuthorizeSignRecordsScriptSpendLeaf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		// leafScripts is how many copies of the leaf script the input
		// carries.
		leafScripts int

		// controlBlockFlip is XORed into the control block's last byte,
		// so a non-zero value breaks the proof.
		controlBlockFlip byte

		// controlBlockTrim is how many bytes are cut from the end of
		// the control block, so a non-zero value leaves it too short to
		// parse.
		controlBlockTrim int

		// leafHashFlip is XORed into the first byte of the leaf hash
		// the record names, so a non-zero value names another leaf.
		leafHashFlip byte

		// leafVersionFlip is XORed into the leaf version the input's
		// leaf script states, so a non-zero value disagrees with its
		// control block. The record names and signs that stated leaf.
		leafVersionFlip byte
	}{{
		name: "leaf the input does not carry",
	}, {
		name:             "control block that does not prove the leaf",
		leafScripts:      1,
		controlBlockFlip: 0x01,
	}, {
		name:             "control block that does not parse",
		leafScripts:      1,
		controlBlockTrim: 1,
	}, {
		name:         "leaf hash other than the proven leaf",
		leafScripts:  1,
		leafHashFlip: 0x01,
	}, {
		name:            "leaf version its control block does not name",
		leafScripts:     1,
		leafVersionFlip: 0x02,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a valid signature for the leaf the input
			// states, with the leaf's proof missing or broken, or the
			// record naming another leaf.
			keys := testAuthKeys()
			utxo, _, leafScript := testTapscriptFixture(t, keys)
			packet, sigHashes, prevOuts := testAuthPacket(
				t, utxo, txscript.SigHashDefault,
			)

			leafScript.ControlBlock[len(leafScript.ControlBlock)-1] ^=
				tc.controlBlockFlip
			leafScript.ControlBlock = leafScript.ControlBlock[:len(
				leafScript.ControlBlock)-tc.controlBlockTrim]
			leafScript.LeafVersion ^= txscript.TapscriptLeafVersion(
				tc.leafVersionFlip,
			)
			packet.Inputs[0].TaprootLeafScript = slices.Repeat(
				[]*psbt.TaprootTapLeafScript{leafScript},
				tc.leafScripts,
			)

			stated := txscript.TapLeaf{
				LeafVersion: leafScript.LeafVersion,
				Script:      leafScript.Script,
			}
			sig, err := txscript.RawTxInTapscriptSignature(
				packet.UnsignedTx, sigHashes, 0, utxo.Value,
				utxo.PkScript, stated, txscript.SigHashDefault,
				keys[0],
			)
			require.NoError(t, err)

			leafHash := stated.TapHash()
			leafHash[0] ^= tc.leafHashFlip
			packet.Inputs[0].TaprootScriptSpendSig =
				[]*psbt.TaprootScriptSpendSig{{
					XOnlyPubKey: schnorr.SerializePubKey(
						keys[0].PubKey(),
					),
					LeafHash:  leafHash[:],
					Signature: sig,
				}}

			// Act: authorize the packet's records.
			err = authorizeSignRecords(packet, sigHashes, prevOuts)

			// Assert: the record is refused.
			require.ErrorIs(t, err, ErrInvalidSignatureRecord)
		})
	}
}

// TestAuthorizeSignRecordsScriptSpendEncoding verifies that a script-path
// record must hold a bare 64-byte signature with its sighash in its own field,
// and may appear only once per key and leaf.
func TestAuthorizeSignRecordsScriptSpendEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		// sigHash is used for both the input and the signature.
		sigHash txscript.SigHashType

		// copies is how many times the record appears.
		copies int
	}{{
		// The signer appends a non-default sighash byte, so this
		// record's signature field is 65 bytes.
		name:    "sighash byte left in the signature",
		sigHash: txscript.SigHashAll,
		copies:  1,
	}, {
		name:    "duplicate record",
		sigHash: txscript.SigHashDefault,
		copies:  2,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a record exactly as the signer returns it.
			keys := testAuthKeys()
			utxo, leaf, leafScript := testTapscriptFixture(t, keys)
			packet, sigHashes, prevOuts := testAuthPacket(
				t, utxo, tc.sigHash,
			)
			packet.Inputs[0].TaprootLeafScript =
				[]*psbt.TaprootTapLeafScript{leafScript}

			sig, err := txscript.RawTxInTapscriptSignature(
				packet.UnsignedTx, sigHashes, 0, utxo.Value,
				utxo.PkScript, leaf, tc.sigHash, keys[0],
			)
			require.NoError(t, err)

			leafHash := leaf.TapHash()
			record := &psbt.TaprootScriptSpendSig{
				XOnlyPubKey: schnorr.SerializePubKey(
					keys[0].PubKey(),
				),
				LeafHash:  leafHash[:],
				Signature: sig,
				SigHash:   tc.sigHash,
			}

			packet.Inputs[0].TaprootScriptSpendSig = slices.Repeat(
				[]*psbt.TaprootScriptSpendSig{record}, tc.copies,
			)

			// Act: authorize the packet's records.
			err = authorizeSignRecords(packet, sigHashes, prevOuts)

			// Assert: the record is refused.
			require.ErrorIs(t, err, ErrInvalidSignatureRecord)
		})
	}
}

// TestAuthorizeSignRecordsScriptSpendOnSegwit verifies that a script-path
// record is refused on an output that is not Taproot, which has no output key
// to prove a leaf into.
func TestAuthorizeSignRecordsScriptSpendOnSegwit(t *testing.T) {
	t.Parallel()

	// Arrange: a P2WPKH output carrying a script-path record.
	keys := testAuthKeys()
	utxo := &wire.TxOut{
		Value: 1000, PkScript: testP2WPKHScript(t, keys[0].PubKey()),
	}
	packet, sigHashes, prevOuts := testAuthPacket(
		t, utxo, txscript.SigHashDefault,
	)
	packet.Inputs[0].TaprootScriptSpendSig = []*psbt.TaprootScriptSpendSig{{
		XOnlyPubKey: schnorr.SerializePubKey(keys[0].PubKey()),
		LeafHash:    bytes.Repeat([]byte{0x01}, 32),
		Signature:   bytes.Repeat([]byte{0x01}, 64),
	}}

	// Act: authorize the packet's records.
	err := authorizeSignRecords(packet, sigHashes, prevOuts)

	// Assert: the record is refused.
	require.ErrorIs(t, err, ErrInvalidSignatureRecord)
}

// TestScriptPushesData verifies that a script only counts as pushing data it
// actually pushes. Empty data must not match, because opcodes that push
// nothing report empty data too.
func TestScriptPushesData(t *testing.T) {
	t.Parallel()

	key := schnorr.SerializePubKey(testAuthKeys()[0].PubKey())
	other := schnorr.SerializePubKey(testAuthKeys()[1].PubKey())

	tests := []struct {
		name string
		data []byte
		want bool
	}{{
		name: "pushed key",
		data: key,
		want: true,
	}, {
		name: "key not pushed",
		data: other,
	}, {
		name: "empty data",
		data: []byte{},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a script pushing one key.
			script, err := txscript.NewScriptBuilder().
				AddData(key).
				AddOp(txscript.OP_CHECKSIG).
				Script()
			require.NoError(t, err)

			// Act: ask whether it pushes the case's data.
			got := scriptPushesData(script, tc.data)

			// Assert: only the pushed key matches.
			require.Equal(t, tc.want, got)
		})
	}
}

// testKeySpendOutput returns a BIP-86 output for key 0.
func testKeySpendOutput(t *testing.T, keys [2]*btcec.PrivateKey) *wire.TxOut {
	t.Helper()

	pkScript, err := txscript.PayToTaprootScript(
		txscript.ComputeTaprootKeyNoScript(keys[0].PubKey()),
	)
	require.NoError(t, err)

	return &wire.TxOut{Value: 1000, PkScript: pkScript}
}

// TestAuthorizeSignRecordsKeySpend verifies that a Taproot key-path record is
// kept only when it verifies against the output key at a sighash its input
// allows.
func TestAuthorizeSignRecordsKeySpend(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		// signer is the internal key that produces the signature.
		signer int

		// inputSigHash is the sighash the input requests.
		inputSigHash txscript.SigHashType

		// sigHash is the sighash the signature is made with.
		sigHash txscript.SigHashType

		// wantErr is nil for a record that passes.
		wantErr error
	}{{
		name: "valid default sighash",
	}, {
		name:         "valid explicit sighash",
		inputSigHash: txscript.SigHashAll,
		sigHash:      txscript.SigHashAll,
	}, {
		name:    "signed by another key",
		signer:  1,
		wantErr: ErrInvalidSignatureRecord,
	}, {
		name:    "explicit sighash all on an unset input",
		sigHash: txscript.SigHashAll,
	}, {
		name:    "other sighash",
		sigHash: txscript.SigHashNone,
		wantErr: ErrInvalidSignatureRecord,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a BIP-86 output for key 0 and a key-path
			// signature made as the case describes.
			keys := testAuthKeys()
			utxo := testKeySpendOutput(t, keys)
			packet, sigHashes, prevOuts := testAuthPacket(
				t, utxo, tc.inputSigHash,
			)

			sig, err := txscript.RawTxInTaprootSignature(
				packet.UnsignedTx, sigHashes, 0, utxo.Value,
				utxo.PkScript, nil, tc.sigHash, keys[tc.signer],
			)
			require.NoError(t, err)

			packet.Inputs[0].TaprootKeySpendSig = sig

			// Act: authorize the packet's records.
			err = authorizeSignRecords(packet, sigHashes, prevOuts)

			// Assert: only the valid record passes.
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestAuthorizeSignRecordsKeySpendEncoding verifies that a key-path record
// whose bytes are not a signature is refused, including a present but empty
// one and one spelling out the default sighash.
func TestAuthorizeSignRecordsKeySpendEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		// suffix is appended to a valid default-sighash signature.
		suffix []byte

		// truncate is how many bytes are cut from its end.
		truncate int
	}{{
		name:   "explicit default sighash byte",
		suffix: []byte{byte(txscript.SigHashDefault)},
	}, {
		name:     "short signature",
		truncate: 1,
	}, {
		name:     "empty but present",
		truncate: schnorr.SignatureSize,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a valid signature, then reshaped.
			keys := testAuthKeys()
			utxo := testKeySpendOutput(t, keys)
			packet, sigHashes, prevOuts := testAuthPacket(
				t, utxo, txscript.SigHashDefault,
			)

			sig, err := txscript.RawTxInTaprootSignature(
				packet.UnsignedTx, sigHashes, 0, utxo.Value,
				utxo.PkScript, nil, txscript.SigHashDefault,
				keys[0],
			)
			require.NoError(t, err)

			sig = append(sig[:len(sig)-tc.truncate], tc.suffix...)
			packet.Inputs[0].TaprootKeySpendSig = sig

			// Act: authorize the packet's records.
			err = authorizeSignRecords(packet, sigHashes, prevOuts)

			// Assert: the record is refused.
			require.ErrorIs(t, err, ErrInvalidSignatureRecord)
		})
	}
}

// TestAuthorizeSignRecordsKeySpendOnSegwit verifies that a key-path record is
// refused on an output that is not Taproot.
func TestAuthorizeSignRecordsKeySpendOnSegwit(t *testing.T) {
	t.Parallel()

	// Arrange: a P2WPKH output carrying a key-path record.
	keys := testAuthKeys()
	utxo := &wire.TxOut{
		Value: 1000, PkScript: testP2WPKHScript(t, keys[0].PubKey()),
	}
	packet, sigHashes, prevOuts := testAuthPacket(
		t, utxo, txscript.SigHashDefault,
	)
	packet.Inputs[0].TaprootKeySpendSig = bytes.Repeat([]byte{0x01}, 64)

	// Act: authorize the packet's records.
	err := authorizeSignRecords(packet, sigHashes, prevOuts)

	// Assert: the record is refused.
	require.ErrorIs(t, err, ErrInvalidSignatureRecord)
}

// TestAuthorizeSignRecordsKeySpendBadOutputKey verifies that a key-path record
// is refused when the Taproot output's program is not a valid key.
func TestAuthorizeSignRecordsKeySpendBadOutputKey(t *testing.T) {
	t.Parallel()

	// Arrange: a Taproot output whose program is not on the curve, with a
	// well-formed key-path signature.
	pkScript := append(
		[]byte{txscript.OP_1, txscript.OP_DATA_32},
		bytes.Repeat([]byte{0xff}, 32)...,
	)
	utxo := &wire.TxOut{Value: 1000, PkScript: pkScript}
	packet, sigHashes, prevOuts := testAuthPacket(
		t, utxo, txscript.SigHashDefault,
	)

	sig, err := txscript.RawTxInTaprootSignature(
		packet.UnsignedTx, sigHashes, 0, utxo.Value, utxo.PkScript,
		nil, txscript.SigHashDefault, testAuthKeys()[0],
	)
	require.NoError(t, err)

	packet.Inputs[0].TaprootKeySpendSig = sig

	// Act: authorize the packet's records.
	err = authorizeSignRecords(packet, sigHashes, prevOuts)

	// Assert: the record is refused.
	require.ErrorIs(t, err, ErrInvalidSignatureRecord)
}
