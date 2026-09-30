// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"crypto/sha256"
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

// TestAuthorizeSignRecordsP2WPKH verifies that a P2WPKH partial signature is
// kept only when its key is the one the output pays and it verifies over the
// input's digest at the input's sighash.
func TestAuthorizeSignRecordsP2WPKH(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		// signer is the key that produces the signature.
		signer int

		// recordKey is the key the record names.
		recordKey int

		// valueDelta is added to the spent value before signing, so a
		// non-zero value signs the wrong digest.
		valueDelta int64

		// sigHash is the sighash the signature is made with. The input
		// requests SIGHASH_ALL.
		sigHash txscript.SigHashType

		// wantErr is nil for a record that passes.
		wantErr error
	}{{
		name:    "valid",
		sigHash: txscript.SigHashAll,
	}, {
		name:      "key the output does not pay",
		signer:    1,
		recordKey: 1,
		sigHash:   txscript.SigHashAll,
		wantErr:   ErrInvalidSignatureRecord,
	}, {
		name:    "signed by another key",
		signer:  1,
		sigHash: txscript.SigHashAll,
		wantErr: ErrInvalidSignatureRecord,
	}, {
		name:       "wrong digest",
		valueDelta: 1,
		sigHash:    txscript.SigHashAll,
		wantErr:    ErrInvalidSignatureRecord,
	}, {
		name:    "other sighash",
		sigHash: txscript.SigHashNone,
		wantErr: ErrInvalidSignatureRecord,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: an output paying key 0, and a record signed
			// as the case describes.
			keys := testAuthKeys()
			utxo := &wire.TxOut{
				Value:    1000,
				PkScript: testP2WPKHScript(t, keys[0].PubKey()),
			}
			packet, sigHashes, prevOuts := testAuthPacket(
				t, utxo, txscript.SigHashAll,
			)

			sig, err := txscript.RawTxInWitnessSignature(
				packet.UnsignedTx, sigHashes, 0,
				utxo.Value+tc.valueDelta, utxo.PkScript,
				tc.sigHash, keys[tc.signer],
			)
			require.NoError(t, err)

			recordKey := keys[tc.recordKey].PubKey()
			packet.Inputs[0].PartialSigs = []*psbt.PartialSig{{
				PubKey:    recordKey.SerializeCompressed(),
				Signature: sig,
			}}

			// Act: authorize the packet's records.
			err = authorizeSignRecords(packet, sigHashes, prevOuts)

			// Assert: only the valid record passes.
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestAuthorizeSignRecordsUnsetSighash verifies which partial signatures an
// input that sets no sighash type accepts: SIGHASH_ALL, the BIP 174 default,
// and the zero byte this wallet signs with, but nothing else.
func TestAuthorizeSignRecordsUnsetSighash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sigHash txscript.SigHashType
		// wantErr is nil for a record that passes.
		wantErr error
	}{{
		name:    "bip 174 default",
		sigHash: txscript.SigHashAll,
	}, {
		name:    "zero byte",
		sigHash: txscript.SigHashDefault,
	}, {
		name:    "other sighash",
		sigHash: txscript.SigHashNone,
		wantErr: ErrInvalidSignatureRecord,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: an input with no sighash type, carrying a
			// signature made with the case's sighash.
			key := testAuthKeys()[0]
			utxo := &wire.TxOut{
				Value:    1000,
				PkScript: testP2WPKHScript(t, key.PubKey()),
			}
			packet, sigHashes, prevOuts := testAuthPacket(
				t, utxo, txscript.SigHashDefault,
			)

			sig, err := txscript.RawTxInWitnessSignature(
				packet.UnsignedTx, sigHashes, 0, utxo.Value,
				utxo.PkScript, tc.sigHash, key,
			)
			require.NoError(t, err)

			packet.Inputs[0].PartialSigs = []*psbt.PartialSig{{
				PubKey:    key.PubKey().SerializeCompressed(),
				Signature: sig,
			}}

			// Act: authorize the packet's records.
			err = authorizeSignRecords(packet, sigHashes, prevOuts)

			// Assert: only the default and the zero byte pass.
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestAuthorizeSignRecordsP2PKH verifies that a legacy P2PKH signature is
// checked over the legacy digest.
func TestAuthorizeSignRecordsP2PKH(t *testing.T) {
	t.Parallel()

	// Arrange: a P2PKH output and a signature for it.
	key := testAuthKeys()[0]
	addr, err := address.NewAddressPubKeyHash(
		address.Hash160(key.PubKey().SerializeCompressed()),
		&chainParams,
	)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	utxo := &wire.TxOut{Value: 1000, PkScript: pkScript}
	packet, sigHashes, prevOuts := testAuthPacket(
		t, utxo, txscript.SigHashAll,
	)

	sig, err := txscript.RawTxInSignature(
		packet.UnsignedTx, 0, pkScript, txscript.SigHashAll, key,
	)
	require.NoError(t, err)

	packet.Inputs[0].PartialSigs = []*psbt.PartialSig{{
		PubKey:    key.PubKey().SerializeCompressed(),
		Signature: sig,
	}}

	// Act: authorize the packet's records.
	err = authorizeSignRecords(packet, sigHashes, prevOuts)

	// Assert: the record passes.
	require.NoError(t, err)
}

// TestAuthorizeSignRecordsNestedP2WPKH verifies that a nested P2WPKH signature
// is checked through the redeem script the output commits to.
func TestAuthorizeSignRecordsNestedP2WPKH(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		// redeemKey is the key whose P2WPKH program the input carries
		// as its redeem script, and that signs over it. The output
		// always wraps key 0's program.
		redeemKey int

		// wantErr is nil for a record that passes.
		wantErr error
	}{{
		name: "committed redeem script",
	}, {
		name:      "redeem script the output does not pay",
		redeemKey: 1,
		wantErr:   ErrInvalidSignatureRecord,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a P2SH output wrapping key 0's P2WPKH
			// program, and an input carrying the case's redeem
			// script with a signature over it.
			keys := testAuthKeys()
			addr, err := address.NewAddressScriptHash(
				testP2WPKHScript(t, keys[0].PubKey()),
				&chainParams,
			)
			require.NoError(t, err)
			pkScript, err := txscript.PayToAddrScript(addr)
			require.NoError(t, err)

			utxo := &wire.TxOut{Value: 1000, PkScript: pkScript}
			packet, sigHashes, prevOuts := testAuthPacket(
				t, utxo, txscript.SigHashAll,
			)

			signer := keys[tc.redeemKey]
			redeem := testP2WPKHScript(t, signer.PubKey())
			packet.Inputs[0].RedeemScript = redeem

			sig, err := txscript.RawTxInWitnessSignature(
				packet.UnsignedTx, sigHashes, 0, utxo.Value,
				redeem, txscript.SigHashAll, signer,
			)
			require.NoError(t, err)

			packet.Inputs[0].PartialSigs = []*psbt.PartialSig{{
				PubKey:    signer.PubKey().SerializeCompressed(),
				Signature: sig,
			}}

			// Act: authorize the packet's records.
			err = authorizeSignRecords(packet, sigHashes, prevOuts)

			// Assert: only the committed redeem script passes.
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// testP2WSHMultisig returns a 2-of-2 witness script over both test keys and the
// P2WSH output script paying it.
func testP2WSHMultisig(t *testing.T,
	keys [2]*btcec.PrivateKey) ([]byte, []byte) {

	t.Helper()

	addrKeys := make([]*address.AddressPubKey, 0, len(keys))
	for _, key := range keys {
		addrKey, err := address.NewAddressPubKey(
			key.PubKey().SerializeCompressed(), &chainParams,
		)
		require.NoError(t, err)

		addrKeys = append(addrKeys, addrKey)
	}

	witnessScript, err := txscript.MultiSigScript(addrKeys, 2)
	require.NoError(t, err)

	hash := sha256.Sum256(witnessScript)
	addr, err := address.NewAddressWitnessScriptHash(hash[:], &chainParams)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	return witnessScript, pkScript
}

// TestAuthorizeSignRecordsP2WSH verifies that a P2WSH signature is checked
// through the witness script the output commits to.
func TestAuthorizeSignRecordsP2WSH(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		// scriptSuffix is appended to the witness script the input
		// carries, so a non-empty suffix breaks the commitment.
		scriptSuffix []byte

		// signer is the key that signs and that the record names: 1
		// is the script's co-signer, 2 a key the script does not push.
		signer int

		// wantErr is nil for a record that passes.
		wantErr error
	}{{
		name:   "co-signer in the committed script",
		signer: 1,
	}, {
		name:    "key the script does not push",
		signer:  2,
		wantErr: ErrInvalidSignatureRecord,
	}, {
		name:         "witness script the output does not pay",
		scriptSuffix: []byte{txscript.OP_NOP},
		signer:       1,
		wantErr:      ErrInvalidSignatureRecord,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a 2-of-2 output, and one signature over the
			// witness script the input carries.
			keys := testAuthKeys()
			witnessScript, pkScript := testP2WSHMultisig(t, keys)

			outsider, _ := btcec.PrivKeyFromBytes(
				bytes.Repeat([]byte{3}, 32),
			)
			signer := [3]*btcec.PrivateKey{
				keys[0], keys[1], outsider,
			}[tc.signer]

			utxo := &wire.TxOut{Value: 1000, PkScript: pkScript}
			packet, sigHashes, prevOuts := testAuthPacket(
				t, utxo, txscript.SigHashAll,
			)

			packet.Inputs[0].WitnessScript = append(
				bytes.Clone(witnessScript), tc.scriptSuffix...,
			)

			sig, err := txscript.RawTxInWitnessSignature(
				packet.UnsignedTx, sigHashes, 0, utxo.Value,
				packet.Inputs[0].WitnessScript,
				txscript.SigHashAll, signer,
			)
			require.NoError(t, err)

			packet.Inputs[0].PartialSigs = []*psbt.PartialSig{{
				PubKey:    signer.PubKey().SerializeCompressed(),
				Signature: sig,
			}}

			// Act: authorize the packet's records.
			err = authorizeSignRecords(packet, sigHashes, prevOuts)

			// Assert: only the committed script passes.
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestAuthorizeSignRecordsMalformedPartialSig verifies that a partial
// signature whose bytes cannot be read is refused rather than trusted.
func TestAuthorizeSignRecordsMalformedPartialSig(t *testing.T) {
	t.Parallel()

	key := testAuthKeys()[0].PubKey().SerializeCompressed()

	tests := []struct {
		name      string
		pubKey    []byte
		signature []byte
	}{{
		name:      "empty signature",
		pubKey:    key,
		signature: []byte{},
	}, {
		name:      "not DER",
		pubKey:    key,
		signature: []byte{0x30, 0x01, byte(txscript.SigHashAll)},
	}, {
		name:      "key that does not parse",
		pubKey:    bytes.Repeat([]byte{0x05}, 33),
		signature: []byte{0x30, 0x01, byte(txscript.SigHashAll)},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a P2WPKH input paying the key, carrying the
			// malformed record.
			keys := testAuthKeys()
			utxo := &wire.TxOut{
				Value:    1000,
				PkScript: testP2WPKHScript(t, keys[0].PubKey()),
			}
			packet, sigHashes, prevOuts := testAuthPacket(
				t, utxo, txscript.SigHashAll,
			)
			packet.Inputs[0].PartialSigs = []*psbt.PartialSig{{
				PubKey:    tc.pubKey,
				Signature: tc.signature,
			}}

			// Act: authorize the packet's records.
			err := authorizeSignRecords(packet, sigHashes, prevOuts)

			// Assert: the record is refused.
			require.ErrorIs(t, err, ErrInvalidSignatureRecord)
		})
	}
}

// TestAuthorizeSignRecordsUnparseableScriptKey verifies that a partial
// signature naming a key that does not parse is refused, even when the
// committed witness script pushes those exact bytes.
func TestAuthorizeSignRecordsUnparseableScriptKey(t *testing.T) {
	t.Parallel()

	// Arrange: a P2WSH output whose witness script pushes 33 bytes that
	// are not a key, and a record naming them with a well-formed DER
	// signature.
	badKey := bytes.Repeat([]byte{0x05}, 33)
	witnessScript, err := txscript.NewScriptBuilder().
		AddData(badKey).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	hash := sha256.Sum256(witnessScript)
	addr, err := address.NewAddressWitnessScriptHash(hash[:], &chainParams)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	utxo := &wire.TxOut{Value: 1000, PkScript: pkScript}
	packet, sigHashes, prevOuts := testAuthPacket(
		t, utxo, txscript.SigHashAll,
	)
	packet.Inputs[0].WitnessScript = witnessScript

	sig, err := txscript.RawTxInWitnessSignature(
		packet.UnsignedTx, sigHashes, 0, utxo.Value, witnessScript,
		txscript.SigHashAll, testAuthKeys()[0],
	)
	require.NoError(t, err)

	packet.Inputs[0].PartialSigs = []*psbt.PartialSig{{
		PubKey:    badKey,
		Signature: sig,
	}}

	// Act: authorize the packet's records.
	err = authorizeSignRecords(packet, sigHashes, prevOuts)

	// Assert: the record is refused.
	require.ErrorIs(t, err, ErrInvalidSignatureRecord)
}

// TestAuthorizeSignRecordsDuplicatePartialSig verifies that two records for one
// key are refused, even when each would verify on its own.
func TestAuthorizeSignRecordsDuplicatePartialSig(t *testing.T) {
	t.Parallel()

	// Arrange: the same valid record twice.
	key := testAuthKeys()[0]
	utxo := &wire.TxOut{
		Value: 1000, PkScript: testP2WPKHScript(t, key.PubKey()),
	}
	packet, sigHashes, prevOuts := testAuthPacket(
		t, utxo, txscript.SigHashAll,
	)

	sig, err := txscript.RawTxInWitnessSignature(
		packet.UnsignedTx, sigHashes, 0, utxo.Value, utxo.PkScript,
		txscript.SigHashAll, key,
	)
	require.NoError(t, err)

	record := &psbt.PartialSig{
		PubKey:    key.PubKey().SerializeCompressed(),
		Signature: sig,
	}
	packet.Inputs[0].PartialSigs = []*psbt.PartialSig{record, record}

	// Act: authorize the packet's records.
	err = authorizeSignRecords(packet, sigHashes, prevOuts)

	// Assert: the duplicate is refused.
	require.ErrorIs(t, err, ErrInvalidSignatureRecord)
}

// TestAuthorizeSignRecordsPartialSigOnTaproot verifies that an ECDSA record is
// refused on a Taproot output, where it can never be part of a valid spend.
func TestAuthorizeSignRecordsPartialSigOnTaproot(t *testing.T) {
	t.Parallel()

	// Arrange: a BIP-86 output carrying an ECDSA record.
	key := testAuthKeys()[0]
	pkScript, err := txscript.PayToTaprootScript(
		txscript.ComputeTaprootKeyNoScript(key.PubKey()),
	)
	require.NoError(t, err)

	utxo := &wire.TxOut{Value: 1000, PkScript: pkScript}
	packet, sigHashes, prevOuts := testAuthPacket(
		t, utxo, txscript.SigHashAll,
	)

	sig, err := txscript.RawTxInWitnessSignature(
		packet.UnsignedTx, sigHashes, 0, utxo.Value,
		testP2WPKHScript(t, key.PubKey()), txscript.SigHashAll, key,
	)
	require.NoError(t, err)

	packet.Inputs[0].PartialSigs = []*psbt.PartialSig{{
		PubKey:    key.PubKey().SerializeCompressed(),
		Signature: sig,
	}}

	// Act: authorize the packet's records.
	err = authorizeSignRecords(packet, sigHashes, prevOuts)

	// Assert: the record is refused.
	require.ErrorIs(t, err, ErrInvalidSignatureRecord)
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
// record is kept only when its key is in the leaf, its sighash is one its input
// allows, and it verifies over that leaf's digest.
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

// TestAuthorizeSignRecordsScriptSpendLeaf verifies that a script-path record
// must name a leaf the output commits to: one the input carries, under a
// control block that proves it into the output key.
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
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a valid signature for the leaf, with the
			// leaf's proof missing or broken, or the record naming
			// another leaf.
			keys := testAuthKeys()
			utxo, leaf, leafScript := testTapscriptFixture(t, keys)
			packet, sigHashes, prevOuts := testAuthPacket(
				t, utxo, txscript.SigHashDefault,
			)

			leafScript.ControlBlock[len(leafScript.ControlBlock)-1] ^=
				tc.controlBlockFlip
			leafScript.ControlBlock = leafScript.ControlBlock[:len(
				leafScript.ControlBlock)-tc.controlBlockTrim]
			packet.Inputs[0].TaprootLeafScript = slices.Repeat(
				[]*psbt.TaprootTapLeafScript{leafScript},
				tc.leafScripts,
			)

			sig, err := txscript.RawTxInTapscriptSignature(
				packet.UnsignedTx, sigHashes, 0, utxo.Value,
				utxo.PkScript, leaf, txscript.SigHashDefault,
				keys[0],
			)
			require.NoError(t, err)

			leafHash := leaf.TapHash()
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
