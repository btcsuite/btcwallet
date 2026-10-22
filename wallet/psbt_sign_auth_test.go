// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"crypto/sha256"
	"math"
	"slices"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/mock"
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
		// is the script's co-signer, 2 a key the script does not
		// commit to.
		signer int

		// wantErr is nil for a record that passes.
		wantErr error
	}{{
		name:   "co-signer in the committed script",
		signer: 1,
	}, {
		name:    "key the script does not commit to",
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

// testKeyHashScript returns a script that commits to a key by its hash,
// `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG`.
func testKeyHashScript(t *testing.T, key *btcec.PublicKey) []byte {
	t.Helper()

	script, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_DUP).
		AddOp(txscript.OP_HASH160).
		AddData(address.Hash160(key.SerializeCompressed())).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	return script
}

// TestAuthorizeSignRecordsHashCommittedWitnessKey verifies that a P2WSH
// signature is kept when its witness script commits to the key by hash rather
// than pushing it.
func TestAuthorizeSignRecordsHashCommittedWitnessKey(t *testing.T) {
	t.Parallel()

	// Arrange: a P2WSH output whose witness script pushes only the key's
	// hash, and a valid signature over that script.
	key := testAuthKeys()[0]
	witnessScript := testKeyHashScript(t, key.PubKey())

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
		txscript.SigHashAll, key,
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

// TestAuthorizeSignRecordsHashCommittedRedeemKey verifies that a legacy P2SH
// signature is kept when its redeem script commits to the key by hash rather
// than pushing it.
func TestAuthorizeSignRecordsHashCommittedRedeemKey(t *testing.T) {
	t.Parallel()

	// Arrange: a P2SH output whose redeem script pushes only the key's
	// hash, and a valid legacy signature over that script.
	key := testAuthKeys()[0]
	redeem := testKeyHashScript(t, key.PubKey())

	addr, err := address.NewAddressScriptHash(redeem, &chainParams)
	require.NoError(t, err)
	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	utxo := &wire.TxOut{Value: 1000, PkScript: pkScript}
	packet, sigHashes, prevOuts := testAuthPacket(
		t, utxo, txscript.SigHashAll,
	)
	packet.Inputs[0].RedeemScript = redeem

	sig, err := txscript.RawTxInSignature(
		packet.UnsignedTx, 0, redeem, txscript.SigHashAll, key,
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

// TestAuthorizeSignRecordsTrailingDERBytes verifies that a partial signature
// with bytes between its DER signature and its sighash byte is refused, even
// though the DER signature itself verifies.
func TestAuthorizeSignRecordsTrailingDERBytes(t *testing.T) {
	t.Parallel()

	// Arrange: a valid P2WPKH signature with one byte inserted after its
	// DER signature.
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

	der := sig[:len(sig)-1]
	padded := append(bytes.Clone(der), 0xaa, byte(txscript.SigHashAll))
	packet.Inputs[0].PartialSigs = []*psbt.PartialSig{{
		PubKey:    key.PubKey().SerializeCompressed(),
		Signature: padded,
	}}

	// Act: authorize the packet's records.
	err = authorizeSignRecords(packet, sigHashes, prevOuts)

	// Assert: the record is refused.
	require.ErrorIs(t, err, ErrInvalidSignatureRecord)
}

// TestAuthorizeSignRecordsWitnessKeyUse verifies that a P2WSH signature is
// kept only when a signature check in the witness script is shown to use its
// key.
func TestAuthorizeSignRecordsWitnessKeyUse(t *testing.T) {
	t.Parallel()

	keys := testAuthKeys()
	key := keys[0].PubKey().SerializeCompressed()
	other := keys[1].PubKey().SerializeCompressed()

	build := func(b *txscript.ScriptBuilder) []byte {
		script, err := b.Script()
		require.NoError(t, err)

		return script
	}

	tests := []struct {
		name string

		// script is the witness script the output commits to.
		script []byte

		// wantErr is nil for a record that passes.
		wantErr error
	}{{
		name: "key checked by OP_CHECKSIG",
		script: build(txscript.NewScriptBuilder().
			AddData(key).
			AddOp(txscript.OP_CHECKSIG)),
	}, {
		name: "key in a multisig",
		script: build(txscript.NewScriptBuilder().
			AddOp(txscript.OP_1).
			AddData(other).
			AddData(key).
			AddOp(txscript.OP_2).
			AddOp(txscript.OP_CHECKMULTISIG)),
	}, {
		name: "multisig counting more keys than it pushes",
		script: build(txscript.NewScriptBuilder().
			AddData(key).
			AddOp(txscript.OP_2).
			AddOp(txscript.OP_CHECKMULTISIG)),
		wantErr: ErrInvalidSignatureRecord,
	}, {
		name: "multisig counting an op that is not a key",
		script: build(txscript.NewScriptBuilder().
			AddOp(txscript.OP_1).
			AddOp(txscript.OP_DUP).
			AddData(key).
			AddOp(txscript.OP_2).
			AddOp(txscript.OP_CHECKMULTISIG)),
		wantErr: ErrInvalidSignatureRecord,
	}, {
		name: "key dropped before another key's check",
		script: build(txscript.NewScriptBuilder().
			AddData(key).
			AddOp(txscript.OP_DROP).
			AddData(other).
			AddOp(txscript.OP_CHECKSIG)),
		wantErr: ErrInvalidSignatureRecord,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a P2WSH output committing to the case's
			// script, and a valid signature by key 0 over it.
			hash := sha256.Sum256(tc.script)
			addr, err := address.NewAddressWitnessScriptHash(
				hash[:], &chainParams,
			)
			require.NoError(t, err)
			pkScript, err := txscript.PayToAddrScript(addr)
			require.NoError(t, err)

			utxo := &wire.TxOut{Value: 1000, PkScript: pkScript}
			packet, sigHashes, prevOuts := testAuthPacket(
				t, utxo, txscript.SigHashAll,
			)
			packet.Inputs[0].WitnessScript = tc.script

			sig, err := txscript.RawTxInWitnessSignature(
				packet.UnsignedTx, sigHashes, 0, utxo.Value,
				tc.script, txscript.SigHashAll, keys[0],
			)
			require.NoError(t, err)

			packet.Inputs[0].PartialSigs = []*psbt.PartialSig{{
				PubKey:    key,
				Signature: sig,
			}}

			// Act: authorize the packet's records.
			err = authorizeSignRecords(packet, sigHashes, prevOuts)

			// Assert: only a key a check is shown to use passes.
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestAuthorizeSignRecordsWitnessCodeSeparator verifies that a P2WSH
// signature is checked over the witness script from the code separator its
// signature check runs, and refused when that separator cannot be told from
// the script alone.
func TestAuthorizeSignRecordsWitnessCodeSeparator(t *testing.T) {
	t.Parallel()

	keys := testAuthKeys()
	key := keys[0].PubKey().SerializeCompressed()
	other := keys[1].PubKey().SerializeCompressed()

	build := func(b *txscript.ScriptBuilder) []byte {
		script, err := b.Script()
		require.NoError(t, err)

		return script
	}

	// A 33-byte key push takes 34 bytes and a separator one more.
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
	keyFirst := build(txscript.NewScriptBuilder().
		AddOp(txscript.OP_CODESEPARATOR).
		AddOp(txscript.OP_IF).
		AddData(key).
		AddOp(txscript.OP_CHECKSIG).
		AddOp(txscript.OP_ELSE).
		AddData(other).
		AddOp(txscript.OP_CHECKSIG).
		AddOp(txscript.OP_ENDIF))
	keySecond := build(txscript.NewScriptBuilder().
		AddOp(txscript.OP_CODESEPARATOR).
		AddOp(txscript.OP_IF).
		AddData(other).
		AddOp(txscript.OP_CHECKSIG).
		AddOp(txscript.OP_ELSE).
		AddData(key).
		AddOp(txscript.OP_CHECKSIG).
		AddOp(txscript.OP_ENDIF))

	tests := []struct {
		name string

		// script is the witness script the output commits to.
		script []byte

		// signedFrom is the byte offset the signed script code starts
		// at.
		signedFrom int

		// wantErr is nil for a record that passes.
		wantErr error
	}{{
		name:       "separator the script runs",
		script:     separated,
		signedFrom: 35,
	}, {
		name:    "signature over the whole script",
		script:  separated,
		wantErr: ErrInvalidSignatureRecord,
	}, {
		name:       "separator inside a branch",
		script:     branching,
		signedFrom: 2,
		wantErr:    ErrInvalidSignatureRecord,
	}, {
		name:       "separator after another key's check",
		script:     checkedFirst,
		signedFrom: 36,
	}, {
		name:       "separator before the branch with the key",
		script:     keyFirst,
		signedFrom: 1,
	}, {
		name:       "separator before the other branch with the key",
		script:     keySecond,
		signedFrom: 1,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a P2WSH output committing to the case's
			// script, and a signature by key 0 over its code from the
			// case's offset.
			hash := sha256.Sum256(tc.script)
			addr, err := address.NewAddressWitnessScriptHash(
				hash[:], &chainParams,
			)
			require.NoError(t, err)
			pkScript, err := txscript.PayToAddrScript(addr)
			require.NoError(t, err)

			utxo := &wire.TxOut{Value: 1000, PkScript: pkScript}
			packet, sigHashes, prevOuts := testAuthPacket(
				t, utxo, txscript.SigHashAll,
			)
			packet.Inputs[0].WitnessScript = tc.script

			sig, err := txscript.RawTxInWitnessSignature(
				packet.UnsignedTx, sigHashes, 0, utxo.Value,
				tc.script[tc.signedFrom:], txscript.SigHashAll,
				keys[0],
			)
			require.NoError(t, err)

			packet.Inputs[0].PartialSigs = []*psbt.PartialSig{{
				PubKey:    key,
				Signature: sig,
			}}

			// Act: authorize the packet's records.
			err = authorizeSignRecords(packet, sigHashes, prevOuts)

			// Assert: only the signature from the separator the
			// script runs passes.
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
		// Well-formed lengths, but R and S are zero.
		name:   "invalid DER",
		pubKey: key,
		signature: []byte{
			0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
			byte(txscript.SigHashAll),
		},
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

// testOneLeafOutput returns a Taproot output committing to a single leaf with
// the given version and script under internal key 1, along with that leaf and
// the leaf script record proving it into the output.
func testOneLeafOutput(t *testing.T, keys [2]*btcec.PrivateKey,
	version txscript.TapscriptLeafVersion, script []byte) (*wire.TxOut,
	txscript.TapLeaf, *psbt.TaprootTapLeafScript) {

	t.Helper()

	leaf := txscript.NewTapLeaf(version, script)
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
		LeafVersion:  version,
	}

	return &wire.TxOut{Value: 1000, PkScript: pkScript}, leaf, leafScript
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

	return testOneLeafOutput(t, keys, txscript.BaseLeafVersion, script)
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

// TestAuthorizeSignRecordsScriptSpendKeyUse verifies that a script-path record
// is kept only when a signature check in its leaf is shown to use its key.
func TestAuthorizeSignRecordsScriptSpendKeyUse(t *testing.T) {
	t.Parallel()

	keys := testAuthKeys()
	key := schnorr.SerializePubKey(keys[0].PubKey())
	other := schnorr.SerializePubKey(keys[1].PubKey())

	build := func(b *txscript.ScriptBuilder) []byte {
		script, err := b.Script()
		require.NoError(t, err)

		return script
	}

	tests := []struct {
		name string

		// script is the leaf the output commits to.
		script []byte

		// wantErr is nil for a record that passes.
		wantErr error
	}{{
		name: "key checked by OP_CHECKSIG",
		script: build(txscript.NewScriptBuilder().
			AddData(key).
			AddOp(txscript.OP_CHECKSIG)),
	}, {
		name: "key committed by hash",
		script: build(txscript.NewScriptBuilder().
			AddOp(txscript.OP_DUP).
			AddOp(txscript.OP_HASH160).
			AddData(address.Hash160(key)).
			AddOp(txscript.OP_EQUALVERIFY).
			AddOp(txscript.OP_CHECKSIG)),
	}, {
		name: "key committed by another hash",
		script: build(txscript.NewScriptBuilder().
			AddOp(txscript.OP_DUP).
			AddOp(txscript.OP_SHA256).
			AddData(address.Hash160(key)).
			AddOp(txscript.OP_EQUALVERIFY).
			AddOp(txscript.OP_CHECKSIG)),
		wantErr: ErrInvalidSignatureRecord,
	}, {
		name: "key checked by OP_CHECKSIGADD",
		script: build(txscript.NewScriptBuilder().
			AddData(other).
			AddOp(txscript.OP_CHECKSIG).
			AddData(key).
			AddOp(txscript.OP_CHECKSIGADD).
			AddOp(txscript.OP_2).
			AddOp(txscript.OP_NUMEQUAL)),
	}, {
		name: "key dropped before another key's check",
		script: build(txscript.NewScriptBuilder().
			AddData(key).
			AddOp(txscript.OP_DROP).
			AddData(other).
			AddOp(txscript.OP_CHECKSIG)),
		wantErr: ErrInvalidSignatureRecord,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: an output committing to the case's leaf, and
			// a valid signature by key 0 over that leaf.
			utxo, leaf, leafScript := testOneLeafOutput(
				t, keys, txscript.BaseLeafVersion, tc.script,
			)
			packet, sigHashes, prevOuts := testAuthPacket(
				t, utxo, txscript.SigHashDefault,
			)
			packet.Inputs[0].TaprootLeafScript =
				[]*psbt.TaprootTapLeafScript{leafScript}

			sig, err := txscript.RawTxInTapscriptSignature(
				packet.UnsignedTx, sigHashes, 0, utxo.Value,
				utxo.PkScript, leaf, txscript.SigHashDefault,
				keys[0],
			)
			require.NoError(t, err)

			leafHash := leaf.TapHash()
			packet.Inputs[0].TaprootScriptSpendSig =
				[]*psbt.TaprootScriptSpendSig{{
					XOnlyPubKey: key,
					LeafHash:    leafHash[:],
					Signature:   sig,
				}}

			// Act: authorize the packet's records.
			err = authorizeSignRecords(packet, sigHashes, prevOuts)

			// Assert: only a key a check is shown to use passes.
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestAuthorizeSignRecordsScriptSpendCodeSeparator verifies that a
// script-path record is checked under the code separator its signature check
// runs, and refused when that separator cannot be told from the leaf alone.
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
	keyFirst := build(txscript.NewScriptBuilder().
		AddOp(txscript.OP_CODESEPARATOR).
		AddOp(txscript.OP_IF).
		AddData(key).
		AddOp(txscript.OP_CHECKSIG).
		AddOp(txscript.OP_ELSE).
		AddData(other).
		AddOp(txscript.OP_CHECKSIG).
		AddOp(txscript.OP_ENDIF))
	keySecond := build(txscript.NewScriptBuilder().
		AddOp(txscript.OP_CODESEPARATOR).
		AddOp(txscript.OP_IF).
		AddData(other).
		AddOp(txscript.OP_CHECKSIG).
		AddOp(txscript.OP_ELSE).
		AddData(key).
		AddOp(txscript.OP_CHECKSIG).
		AddOp(txscript.OP_ENDIF))
	afterBranch := build(txscript.NewScriptBuilder().
		AddOp(txscript.OP_IF).
		AddData(other).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddOp(txscript.OP_ENDIF).
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
		name:       "separator after another key's check",
		script:     checkedFirst,
		codeSepPos: 2,
	}, {
		name:       "separator before the branch with the key",
		script:     keyFirst,
		codeSepPos: 0,
	}, {
		name:       "separator before the other branch with the key",
		script:     keySecond,
		codeSepPos: 0,
	}, {
		name:       "separator after a closed branch",
		script:     afterBranch,
		codeSepPos: 4,
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
				t, keys, txscript.BaseLeafVersion, tc.script,
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

// testBip32Path returns the derivation path the store-routed signer resolves
// for a purpose's account 0, branch 0, index 0.
func testBip32Path(purpose uint32) []uint32 {
	return []uint32{
		hdkeychain.HardenedKeyStart + purpose,
		hdkeychain.HardenedKeyStart + 1,
		hdkeychain.HardenedKeyStart + 0,
		0, 0,
	}
}

// testBip86Output returns a BIP-86 output paying an internal key.
func testBip86Output(t *testing.T, key *btcec.PublicKey) *wire.TxOut {
	t.Helper()

	pkScript, err := txscript.PayToTaprootScript(
		txscript.ComputeTaprootKeyNoScript(key),
	)
	require.NoError(t, err)

	return &wire.TxOut{Value: 1000, PkScript: pkScript}
}

// testTaprootSignPacket returns a packet spending utxo with the wallet's
// BIP-86 derivation record for the given leaf, or for the key path when
// leafScript is nil.
func testTaprootSignPacket(t *testing.T, utxo *wire.TxOut,
	leafScript *psbt.TaprootTapLeafScript) *psbt.Packet {

	t.Helper()

	_, walletPub := deriveLeafKeys(t, testAccountXPrv(t), 0, 0)
	derivation := &psbt.TaprootBip32Derivation{
		XOnlyPubKey: schnorr.SerializePubKey(walletPub),
		Bip32Path:   testBip32Path(86),
	}

	packet, _, _ := testAuthPacket(t, utxo, txscript.SigHashDefault)
	if leafScript != nil {
		leaf := txscript.TapLeaf{
			LeafVersion: leafScript.LeafVersion,
			Script:      leafScript.Script,
		}
		leafHash := leaf.TapHash()

		derivation.LeafHashes = [][]byte{leafHash[:]}
		packet.Inputs[0].TaprootLeafScript =
			[]*psbt.TaprootTapLeafScript{leafScript}
	}

	packet.Inputs[0].TaprootBip32Derivation =
		[]*psbt.TaprootBip32Derivation{derivation}

	return packet
}

// testScript assembles a script from pushes and opcodes, where a []byte is a
// push and an int, as an untyped opcode constant becomes, is an opcode.
func testScript(t *testing.T, parts ...any) []byte {
	t.Helper()

	builder := txscript.NewScriptBuilder()
	for _, part := range parts {
		switch p := part.(type) {
		case []byte:
			builder.AddData(p)
		case int:
			builder.AddOp(byte(p))
		default:
			t.Fatalf("unknown script part %T", part)
		}
	}

	script, err := builder.Script()
	require.NoError(t, err)

	return script
}

// testP2SHScript returns the P2SH output script paying a redeem script.
func testP2SHScript(t *testing.T, redeem []byte) []byte {
	t.Helper()

	return testScript(
		t, txscript.OP_HASH160, address.Hash160(redeem),
		txscript.OP_EQUAL,
	)
}

// testP2WSHScript returns the P2WSH output script paying a witness script.
func testP2WSHScript(t *testing.T, witnessScript []byte) []byte {
	t.Helper()

	hash := sha256.Sum256(witnessScript)

	return testScript(t, txscript.OP_0, hash[:])
}

// requireInputSpends runs the script engine on one input of the packet's
// transaction, unlocked by the given signature script and witness.
func requireInputSpends(t *testing.T, packet *psbt.Packet, idx int,
	sigScript []byte, witness wire.TxWitness) {

	t.Helper()

	tx := packet.UnsignedTx.Copy()
	tx.TxIn[idx].SignatureScript = sigScript
	tx.TxIn[idx].Witness = witness

	prevOuts, err := PsbtPrevOutputFetcher(packet)
	require.NoError(t, err)

	utxo := packet.Inputs[idx].WitnessUtxo
	vm, err := txscript.NewEngine(
		utxo.PkScript, tx, idx, txscript.StandardVerifyFlags, nil,
		txscript.NewTxSigHashes(tx, prevOuts), utxo.Value, prevOuts,
	)
	require.NoError(t, err)
	require.NoError(t, vm.Execute())
}

// testEcdsaSignPacket returns a packet spending pkScript, with the given
// redeem and witness scripts, and the wallet's derivation record for the
// purpose's account 0, branch 0, index 0.
func testEcdsaSignPacket(t *testing.T, pkScript, redeemScript,
	witnessScript []byte, purpose uint32) *psbt.Packet {

	t.Helper()

	_, walletPub := deriveLeafKeys(t, testAccountXPrv(t), 0, 0)

	packet, _, _ := testAuthPacket(
		t, &wire.TxOut{Value: 1000, PkScript: pkScript},
		txscript.SigHashAll,
	)
	packet.Inputs[0].RedeemScript = redeemScript
	packet.Inputs[0].WitnessScript = witnessScript
	packet.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{{
		PubKey:    walletPub.SerializeCompressed(),
		Bip32Path: testBip32Path(purpose),
	}}

	return packet
}

// testTweakCase is a tweak a signing test runs under.
type testTweakCase struct {
	name  string
	tweak KeyTweak
}

// testLndTweaks returns no tweak and the tweaks lnd builds for a base key: a
// single tweak, a revocation derivation, and a revocation followed by a
// single tweak.
func testLndTweaks(t *testing.T, basePub *btcec.PublicKey) []testTweakCase {
	t.Helper()

	commitSecret, commitPoint := btcec.PrivKeyFromBytes(
		bytes.Repeat([]byte{0x42}, 32),
	)

	single := testLndHash(commitPoint, basePub)
	revokeTweak := testLndHash(basePub, commitPoint)

	commitHalf := testLndHash(commitPoint, basePub)
	commitHalf.Mul(&commitSecret.Key)

	combinedAdd := commitHalf
	combinedAdd.Add(&single)

	singleTweak, err := NewAddTweak(testScalarBytes(&single))
	require.NoError(t, err)

	revocationTweak, err := NewMulAddTweak(
		testScalarBytes(&revokeTweak), testScalarBytes(&commitHalf),
	)
	require.NoError(t, err)

	combinedTweak, err := NewMulAddTweak(
		testScalarBytes(&revokeTweak), testScalarBytes(&combinedAdd),
	)
	require.NoError(t, err)

	return []testTweakCase{
		{name: "untweaked"},
		{name: "single tweak", tweak: singleTweak},
		{name: "revocation tweak", tweak: revocationTweak},
		{name: "revocation then single tweak", tweak: combinedTweak},
	}
}

// testTweakedKey returns the key a tweak makes of a base key.
func testTweakedKey(t *testing.T, tweak KeyTweak,
	base *btcec.PublicKey) *btcec.PublicKey {

	t.Helper()

	key, err := tweak.pubKey(base)
	require.NoError(t, err)

	return key
}

// TestSignPsbtKeyHashEffectiveKey tests that SignPsbt signs a key-hash input
// with the derived key plus any tweak, files the record under that key, and
// keeps the base derivation. The signature must spend the input, and a second
// pass must add nothing.
func TestSignPsbtKeyHashEffectiveKey(t *testing.T) {
	t.Parallel()

	_, basePub := deriveLeafKeys(t, testAccountXPrv(t), 0, 0)

	forms := []struct {
		name    string
		purpose uint32

		// nested wraps the key hash program in P2SH.
		nested bool
	}{
		{name: "p2wpkh", purpose: 84},
		{name: "custom scope p2wpkh", purpose: 1017},
		{name: "np2wpkh", purpose: 49, nested: true},
	}

	for _, form := range forms {
		for _, tc := range testLndTweaks(t, basePub) {
			t.Run(form.name+" "+tc.name, func(t *testing.T) {
				t.Parallel()

				// Arrange: an output paying the derived key
				// plus the tweak.
				key := testTweakedKey(t, tc.tweak, basePub).
					SerializeCompressed()
				pkScript := testScript(
					t, txscript.OP_0, address.Hash160(key),
				)

				var redeemScript, sigScript []byte
				if form.nested {
					redeemScript = pkScript
					pkScript = testP2SHScript(t, redeemScript)
					sigScript = testScript(t, redeemScript)
				}

				packet := testEcdsaSignPacket(
					t, pkScript, redeemScript, nil,
					form.purpose,
				)
				derivations := clonePacket(packet).Inputs[0].
					Bip32Derivation

				w, mocks := createUnlockedWalletWithMocks(t)
				_, _ = expectStoreSignerPrivKey(
					t, mocks, w.id, waddrmgr.KeyScope{
						Purpose: form.purpose, Coin: 1,
					},
					waddrmgr.DerivationPath{},
				)
				params := &SignPsbtParams{
					Packet:      packet,
					InputTweaks: map[int]KeyTweak{0: tc.tweak},
				}

				// Act: sign the packet twice.
				first, err := w.SignPsbt(t.Context(), params)
				require.NoError(t, err)

				signed := clonePacket(packet)

				second, err := w.SignPsbt(t.Context(), params)
				require.NoError(t, err)

				// Assert: the first pass filed a record under
				// the tweaked key that spends the input, the
				// derivation is unchanged, and the second
				// pass changed nothing.
				require.Equal(t, []uint32{0}, first.SignedInputs)

				records := packet.Inputs[0].PartialSigs
				require.Len(t, records, 1)
				require.Equal(t, key, records[0].PubKey)
				requireInputSpends(
					t, packet, 0, sigScript,
					wire.TxWitness{records[0].Signature, key},
				)

				require.Equal(
					t, derivations,
					packet.Inputs[0].Bip32Derivation,
				)
				require.Empty(t, second.SignedInputs)
				require.Equal(t, signed, packet)
			})
		}
	}
}

// TestSignPsbtWitnessScriptEffectiveKey tests that SignPsbt signs a witness
// script input that checks the derived key plus any tweak, files the record
// under that key, and adds nothing on a second pass. The signature must spend
// the input.
func TestSignPsbtWitnessScriptEffectiveKey(t *testing.T) {
	t.Parallel()

	_, basePub := deriveLeafKeys(t, testAccountXPrv(t), 0, 0)

	forms := []struct {
		name string

		// nested wraps the witness program in P2SH.
		nested bool
	}{
		{name: "p2wsh"},
		{name: "p2sh-p2wsh", nested: true},
	}

	for _, form := range forms {
		for _, tc := range testLndTweaks(t, basePub) {
			t.Run(form.name+" "+tc.name, func(t *testing.T) {
				t.Parallel()

				// Arrange: a witness script `<tweaked key>
				// OP_CHECKSIG`.
				key := testTweakedKey(t, tc.tweak, basePub).
					SerializeCompressed()
				script := testScript(t, key, txscript.OP_CHECKSIG)
				pkScript := testP2WSHScript(t, script)

				var redeemScript, sigScript []byte
				if form.nested {
					redeemScript = pkScript
					pkScript = testP2SHScript(t, redeemScript)
					sigScript = testScript(t, redeemScript)
				}

				packet := testEcdsaSignPacket(
					t, pkScript, redeemScript, script, 84,
				)

				w, mocks := createUnlockedWalletWithMocks(t)
				_, _ = expectStoreSignerPrivKey(
					t, mocks, w.id,
					waddrmgr.KeyScope{Purpose: 84, Coin: 1},
					waddrmgr.DerivationPath{},
				)
				params := &SignPsbtParams{
					Packet:      packet,
					InputTweaks: map[int]KeyTweak{0: tc.tweak},
				}

				// Act: sign the packet twice.
				first, err := w.SignPsbt(t.Context(), params)
				require.NoError(t, err)

				signed := clonePacket(packet)

				second, err := w.SignPsbt(t.Context(), params)
				require.NoError(t, err)

				// Assert: the first pass filed a record under
				// the tweaked key that spends the input, and
				// the second pass changed nothing.
				require.Equal(t, []uint32{0}, first.SignedInputs)

				records := packet.Inputs[0].PartialSigs
				require.Len(t, records, 1)
				require.Equal(t, key, records[0].PubKey)
				requireInputSpends(
					t, packet, 0, sigScript,
					wire.TxWitness{records[0].Signature, script},
				)

				require.Empty(t, second.SignedInputs)
				require.Equal(t, signed, packet)
			})
		}
	}
}

// TestSignPsbtLegacyEffectiveKey tests that SignPsbt signs a P2PKH input with
// the derived key plus any tweak and files the record under that key. The
// signature must spend the input.
func TestSignPsbtLegacyEffectiveKey(t *testing.T) {
	t.Parallel()

	_, basePub := deriveLeafKeys(t, testAccountXPrv(t), 0, 0)

	for _, tc := range testLndTweaks(t, basePub) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: a P2PKH output paying the derived key plus
			// the tweak.
			key := testTweakedKey(t, tc.tweak, basePub).
				SerializeCompressed()
			pkScript := testScript(
				t, txscript.OP_DUP, txscript.OP_HASH160,
				address.Hash160(key), txscript.OP_EQUALVERIFY,
				txscript.OP_CHECKSIG,
			)
			packet := testEcdsaSignPacket(t, pkScript, nil, nil, 44)

			w, mocks := createUnlockedWalletWithMocks(t)
			_, _ = expectStoreSignerPrivKey(
				t, mocks, w.id,
				waddrmgr.KeyScope{Purpose: 44, Coin: 1},
				waddrmgr.DerivationPath{},
			)

			// Act: sign the packet.
			result, err := w.SignPsbt(t.Context(), &SignPsbtParams{
				Packet:      packet,
				InputTweaks: map[int]KeyTweak{0: tc.tweak},
			})

			// Assert: the record names the tweaked key and its
			// signature spends the input.
			require.NoError(t, err)
			require.Equal(t, []uint32{0}, result.SignedInputs)

			records := packet.Inputs[0].PartialSigs
			require.Len(t, records, 1)
			require.Equal(t, key, records[0].PubKey)
			requireInputSpends(
				t, packet, 0, testScript(t, records[0].Signature, key), nil,
			)
		})
	}
}

// TestSignPsbtUncompressedLegacyKey tests that an untweaked legacy input whose
// derivation record names the derived key uncompressed is signed under those
// record bytes, which its output commits to.
func TestSignPsbtUncompressedLegacyKey(t *testing.T) {
	t.Parallel()

	// Arrange: a P2PKH output paying the uncompressed derived key.
	_, pubKey := deriveLeafKeys(t, testAccountXPrv(t), 0, 0)
	key := pubKey.SerializeUncompressed()

	pkScript := testScript(
		t, txscript.OP_DUP, txscript.OP_HASH160, address.Hash160(key),
		txscript.OP_EQUALVERIFY, txscript.OP_CHECKSIG,
	)
	packet := testEcdsaSignPacket(t, pkScript, nil, nil, 44)
	packet.Inputs[0].Bip32Derivation[0].PubKey = key

	w, mocks := createUnlockedWalletWithMocks(t)
	_, _ = expectStoreSignerPrivKey(
		t, mocks, w.id, waddrmgr.KeyScope{Purpose: 44, Coin: 1},
		waddrmgr.DerivationPath{},
	)

	// Act: sign the packet.
	_, err := w.SignPsbt(t.Context(), &SignPsbtParams{Packet: packet})

	// Assert: the record names the uncompressed key and its signature
	// spends the input.
	require.NoError(t, err)

	records := packet.Inputs[0].PartialSigs
	require.Len(t, records, 1)
	require.Equal(t, key, records[0].PubKey)
	requireInputSpends(
		t, packet, 0, testScript(t, records[0].Signature, key), nil,
	)
}

// testParityIndices returns the first derivation indices, on branch 0 of the
// test account, whose keys have an even and an odd Y coordinate.
func testParityIndices(t *testing.T) (uint32, uint32) {
	t.Helper()

	var (
		even, odd           uint32
		foundEven, foundOdd bool
	)
	for i := uint32(0); !foundEven || !foundOdd; i++ {
		_, pubKey := deriveLeafKeys(t, testAccountXPrv(t), 0, i)

		switch {
		case pubKey.Y().Bit(0) == 0 && !foundEven:
			even, foundEven = i, true

		case pubKey.Y().Bit(0) == 1 && !foundOdd:
			odd, foundOdd = i, true
		}
	}

	return even, odd
}

// TestSignPsbtTaprootKeyPathEffectiveKey tests that SignPsbt signs a Taproot
// key-path input whose internal key is the derived key plus any tweak, for a
// derived key of either parity, and that the signature spends the input. A
// second pass must add nothing.
func TestSignPsbtTaprootKeyPathEffectiveKey(t *testing.T) {
	t.Parallel()

	even, odd := testParityIndices(t)

	tests := []struct {
		name       string
		index      uint32
		merkleRoot []byte
	}{
		{name: "even base key", index: even},
		{name: "odd base key", index: odd},
		{
			name:       "odd base key with merkle root",
			index:      odd,
			merkleRoot: bytes.Repeat([]byte{0x05}, 32),
		},
	}

	for _, tc := range tests {
		_, basePub := deriveLeafKeys(
			t, testAccountXPrv(t), 0, tc.index,
		)

		for _, tw := range testLndTweaks(t, basePub) {
			t.Run(tc.name+" "+tw.name, func(t *testing.T) {
				t.Parallel()

				// Arrange: an output whose internal key is
				// the derived key plus the tweak.
				key := testTweakedKey(t, tw.tweak, basePub)
				pkScript, err := txscript.PayToTaprootScript(
					txscript.ComputeTaprootOutputKey(
						key, tc.merkleRoot,
					),
				)
				require.NoError(t, err)

				packet := testTaprootSignPacket(
					t, &wire.TxOut{
						Value: 1000, PkScript: pkScript,
					}, nil,
				)
				packet.Inputs[0].TaprootMerkleRoot = tc.merkleRoot

				derivation := packet.Inputs[0].
					TaprootBip32Derivation[0]
				derivation.XOnlyPubKey = schnorr.SerializePubKey(
					basePub,
				)
				derivation.Bip32Path[4] = tc.index

				w, mocks := createUnlockedWalletWithMocks(t)
				_, _ = expectStoreSignerPrivKey(
					t, mocks, w.id,
					waddrmgr.KeyScope{Purpose: 86, Coin: 1},
					waddrmgr.DerivationPath{Index: tc.index},
				)
				params := &SignPsbtParams{
					Packet:      packet,
					InputTweaks: map[int]KeyTweak{0: tw.tweak},
				}

				// Act: sign the packet twice.
				first, err := w.SignPsbt(t.Context(), params)
				require.NoError(t, err)

				signed := clonePacket(packet)

				second, err := w.SignPsbt(t.Context(), params)
				require.NoError(t, err)

				// Assert: the signature spends the input, and
				// the second pass changed nothing.
				require.Equal(t, []uint32{0}, first.SignedInputs)
				requireInputSpends(
					t, packet, 0, nil, wire.TxWitness{
						packet.Inputs[0].TaprootKeySpendSig,
					},
				)

				require.Empty(t, second.SignedInputs)
				require.Equal(t, signed, packet)
			})
		}
	}
}

// TestSignPsbtTaprootScriptPathEffectiveKey tests that SignPsbt signs a
// Taproot leaf that checks the derived key plus any tweak, for a derived key
// of either parity, files the record under that key, and adds nothing on a
// second pass. The signature must spend the input.
func TestSignPsbtTaprootScriptPathEffectiveKey(t *testing.T) {
	t.Parallel()

	even, odd := testParityIndices(t)

	tests := []struct {
		name  string
		index uint32
	}{
		{name: "even base key", index: even},
		{name: "odd base key", index: odd},
	}

	for _, tc := range tests {
		_, basePub := deriveLeafKeys(
			t, testAccountXPrv(t), 0, tc.index,
		)

		for _, tw := range testLndTweaks(t, basePub) {
			t.Run(tc.name+" "+tw.name, func(t *testing.T) {
				t.Parallel()

				// Arrange: a leaf `<tweaked key> OP_CHECKSIG`.
				key := schnorr.SerializePubKey(
					testTweakedKey(t, tw.tweak, basePub),
				)
				script := testScript(t, key, txscript.OP_CHECKSIG)
				utxo, _, leafScript := testOneLeafOutput(
					t, testAuthKeys(), txscript.BaseLeafVersion,
					script,
				)

				packet := testTaprootSignPacket(t, utxo, leafScript)

				derivation := packet.Inputs[0].
					TaprootBip32Derivation[0]
				derivation.XOnlyPubKey = schnorr.SerializePubKey(
					basePub,
				)
				derivation.Bip32Path[4] = tc.index

				w, mocks := createUnlockedWalletWithMocks(t)
				_, _ = expectStoreSignerPrivKey(
					t, mocks, w.id,
					waddrmgr.KeyScope{Purpose: 86, Coin: 1},
					waddrmgr.DerivationPath{Index: tc.index},
				)
				params := &SignPsbtParams{
					Packet:      packet,
					InputTweaks: map[int]KeyTweak{0: tw.tweak},
				}

				// Act: sign the packet twice.
				first, err := w.SignPsbt(t.Context(), params)
				require.NoError(t, err)

				signed := clonePacket(packet)

				second, err := w.SignPsbt(t.Context(), params)
				require.NoError(t, err)

				// Assert: the record names the tweaked key and
				// spends the input, and the second pass changed
				// nothing.
				require.Equal(t, []uint32{0}, first.SignedInputs)

				records := packet.Inputs[0].TaprootScriptSpendSig
				require.Len(t, records, 1)
				require.Equal(t, key, records[0].XOnlyPubKey)
				requireInputSpends(t, packet, 0, nil, wire.TxWitness{
					records[0].Signature, script,
					leafScript.ControlBlock,
				})

				require.Empty(t, second.SignedInputs)
				require.Equal(t, signed, packet)
			})
		}
	}
}

// TestSignPsbtTaprootFilesRecordUnderDerivedParity tests that when a leaf
// checks the tweaked key for both parities of the base key, the record is
// filed under the one the derived key actually becomes, and spends the input.
func TestSignPsbtTaprootFilesRecordUnderDerivedParity(t *testing.T) {
	t.Parallel()

	// Arrange: an odd base key under a single tweak, and a leaf checking
	// the tweaked key for the other parity in one branch and for the
	// derived parity in the other.
	_, odd := testParityIndices(t)
	_, basePub := deriveLeafKeys(t, testAccountXPrv(t), 0, odd)

	tweak, err := NewAddTweak([32]byte{31: 7})
	require.NoError(t, err)

	var flipped btcec.JacobianPoint
	basePub.AsJacobian(&flipped)
	flipped.Y.Negate(1).Normalize()
	otherBase := btcec.NewPublicKey(&flipped.X, &flipped.Y)

	derivedKey := schnorr.SerializePubKey(
		testTweakedKey(t, tweak, basePub),
	)
	otherKey := schnorr.SerializePubKey(
		testTweakedKey(t, tweak, otherBase),
	)
	script := testScript(
		t, txscript.OP_IF, otherKey, txscript.OP_CHECKSIG,
		txscript.OP_ELSE, derivedKey, txscript.OP_CHECKSIG,
		txscript.OP_ENDIF,
	)
	utxo, _, leafScript := testOneLeafOutput(
		t, testAuthKeys(), txscript.BaseLeafVersion, script,
	)

	packet := testTaprootSignPacket(t, utxo, leafScript)
	derivation := packet.Inputs[0].TaprootBip32Derivation[0]
	derivation.XOnlyPubKey = schnorr.SerializePubKey(basePub)
	derivation.Bip32Path[4] = odd

	w, mocks := createUnlockedWalletWithMocks(t)
	_, _ = expectStoreSignerPrivKey(
		t, mocks, w.id, waddrmgr.KeyScope{Purpose: 86, Coin: 1},
		waddrmgr.DerivationPath{Index: odd},
	)

	// Act: sign the packet.
	_, err = w.SignPsbt(t.Context(), &SignPsbtParams{
		Packet:      packet,
		InputTweaks: map[int]KeyTweak{0: tweak},
	})

	// Assert: the record names the derived parity's key and spends the
	// input through the branch that checks it.
	require.NoError(t, err)

	records := packet.Inputs[0].TaprootScriptSpendSig
	require.Len(t, records, 1)
	require.Equal(t, derivedKey, records[0].XOnlyPubKey)
	requireInputSpends(t, packet, 0, nil, wire.TxWitness{
		records[0].Signature, nil, script, leafScript.ControlBlock,
	})
}

// TestSignPsbtSkipsWalletCodeSeparatorRecord tests that a valid existing
// signature by the wallet's key stops it signing again even where the wallet
// could not sign itself: a witness script that checks the key after a code
// separator.
func TestSignPsbtSkipsWalletCodeSeparatorRecord(t *testing.T) {
	t.Parallel()

	// Arrange: the witness script `OP_CODESEPARATOR <wallet key>
	// OP_CHECKSIG`, with the wallet's signature over the script after the
	// separator.
	walletKey, walletPub := deriveLeafKeys(t, testAccountXPrv(t), 0, 0)
	key := walletPub.SerializeCompressed()
	script := testScript(
		t, txscript.OP_CODESEPARATOR, key, txscript.OP_CHECKSIG,
	)
	packet := testEcdsaSignPacket(
		t, testP2WSHScript(t, script), nil, script, 84,
	)

	prevOuts, err := PsbtPrevOutputFetcher(packet)
	require.NoError(t, err)

	sig, err := txscript.RawTxInWitnessSignature(
		packet.UnsignedTx,
		txscript.NewTxSigHashes(packet.UnsignedTx, prevOuts), 0, 1000,
		script[1:], txscript.SigHashAll, walletKey,
	)
	require.NoError(t, err)

	packet.Inputs[0].PartialSigs = []*psbt.PartialSig{{
		PubKey: key, Signature: sig,
	}}
	requireInputSpends(t, packet, 0, nil, wire.TxWitness{sig, script})

	before := clonePacket(packet)
	w, mocks := createUnlockedWalletWithMocks(t)

	// Act: sign the packet.
	result, err := w.SignPsbt(t.Context(), &SignPsbtParams{Packet: packet})

	// Assert: the input is skipped, no key was looked up, and the packet
	// is unchanged.
	require.NoError(t, err)
	require.Empty(t, result.SignedInputs)
	mocks.store.AssertNotCalled(
		t, "GetAccountSecret", mock.Anything, mock.Anything,
	)
	require.Equal(t, before, clonePacket(packet))
}

// TestSignPsbtRejectsEcdsaSignerBeforeKeyLookup tests that an ECDSA input whose
// script does not check the key SignPsbt would sign with fails the call before
// any key is looked up and leaves the caller's packet unchanged.
func TestSignPsbtRejectsEcdsaSignerBeforeKeyLookup(t *testing.T) {
	t.Parallel()

	_, walletPub := deriveLeafKeys(t, testAccountXPrv(t), 0, 0)
	walletKey := walletPub.SerializeCompressed()
	uncompressed := walletPub.SerializeUncompressed()

	singleTweak, err := NewAddTweak([32]byte{31: 7})
	require.NoError(t, err)

	checkSig := testScript(t, walletKey, txscript.OP_CHECKSIG)
	separated := testScript(
		t, txscript.OP_CODESEPARATOR, walletKey, txscript.OP_CHECKSIG,
	)

	tests := []struct {
		name          string
		pkScript      []byte
		witnessScript []byte

		// recordKey is the derivation record's key, the wallet's
		// compressed key when nil.
		recordKey []byte
		tweaks    map[int]KeyTweak
		wantErr   error
	}{{
		name:     "output pays another key",
		pkScript: testP2WPKHScript(t, testAuthKeys()[0].PubKey()),
		wantErr:  ErrSigningKeyMismatch,
	}, {
		name:     "tweak the output does not pay",
		pkScript: testP2WPKHScript(t, walletPub),
		tweaks:   map[int]KeyTweak{0: singleTweak},
		wantErr:  ErrSigningKeyMismatch,
	}, {
		name:     "tweak for a missing input",
		pkScript: testP2WPKHScript(t, walletPub),
		tweaks:   map[int]KeyTweak{1: singleTweak},
		wantErr:  ErrInvalidSignParam,
	}, {
		name: "uncompressed segwit key",
		pkScript: testScript(
			t, txscript.OP_0, address.Hash160(uncompressed),
		),
		recordKey: uncompressed,
		wantErr:   ErrSigningKeyMismatch,
	}, {
		name: "witness script the output does not commit to",
		pkScript: testP2WSHScript(
			t, testScript(t, txscript.OP_TRUE),
		),
		witnessScript: checkSig,
		wantErr:       ErrSigningKeyMismatch,
	}, {
		name:          "key checked after a code separator",
		pkScript:      testP2WSHScript(t, separated),
		witnessScript: separated,
		wantErr:       ErrSigningKeyMismatch,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			packet := testEcdsaSignPacket(
				t, tc.pkScript, nil, tc.witnessScript, 84,
			)
			if tc.recordKey != nil {
				packet.Inputs[0].Bip32Derivation[0].PubKey =
					tc.recordKey
			}

			before := clonePacket(packet)
			w, mocks := createUnlockedWalletWithMocks(t)

			// Act: sign the packet.
			_, err := w.SignPsbt(t.Context(), &SignPsbtParams{
				Packet: packet, InputTweaks: tc.tweaks,
			})

			// Assert: the input is refused, no key was looked up,
			// and the caller's packet is unchanged.
			require.ErrorIs(t, err, tc.wantErr)
			mocks.store.AssertNotCalled(
				t, "GetAccountSecret", mock.Anything,
				mock.Anything,
			)
			require.Equal(t, before, clonePacket(packet))
		})
	}
}

// TestSignPsbtRejectsTaprootSignerBeforeKeyLookup tests that a Taproot input
// whose spend does not use the key SignPsbt would sign with fails the call
// before any key is looked up and leaves the caller's packet unchanged.
func TestSignPsbtRejectsTaprootSignerBeforeKeyLookup(t *testing.T) {
	t.Parallel()

	_, walletPub := deriveLeafKeys(t, testAccountXPrv(t), 0, 0)
	walletX := schnorr.SerializePubKey(walletPub)
	keys := testAuthKeys()
	foreign := keys[0].PubKey()
	foreignX := schnorr.SerializePubKey(foreign)

	singleTweak, err := NewAddTweak([32]byte{31: 7})
	require.NoError(t, err)

	walletOutput := testBip86Output(t, walletPub)

	_, _, walletLeaf := testOneLeafOutput(
		t, keys, txscript.BaseLeafVersion,
		testScript(t, walletX, txscript.OP_CHECKSIG),
	)
	foreignLeafOutput, _, foreignLeaf := testOneLeafOutput(
		t, keys, txscript.BaseLeafVersion,
		testScript(t, foreignX, txscript.OP_CHECKSIG),
	)
	separatedOutput, _, separatedLeaf := testOneLeafOutput(
		t, keys, txscript.BaseLeafVersion, testScript(
			t, txscript.OP_CODESEPARATOR, walletX,
			txscript.OP_CHECKSIG,
		),
	)
	versionOutput, _, versionLeaf := testOneLeafOutput(
		t, keys, 0xc2, testScript(t, walletX, txscript.OP_CHECKSIG),
	)

	tests := []struct {
		name        string
		utxo        *wire.TxOut
		leafScript  *psbt.TaprootTapLeafScript
		internalKey []byte
		tweaks      map[int]KeyTweak
		wantErr     error
	}{{
		name:        "internal key is another key",
		utxo:        walletOutput,
		internalKey: foreignX,
		wantErr:     ErrSigningKeyMismatch,
	}, {
		name:    "output pays another key",
		utxo:    testBip86Output(t, foreign),
		wantErr: ErrSigningKeyMismatch,
	}, {
		name:    "tweak the output does not pay",
		utxo:    walletOutput,
		tweaks:  map[int]KeyTweak{0: singleTweak},
		wantErr: ErrSigningKeyMismatch,
	}, {
		name: "non-taproot output",
		utxo: &wire.TxOut{
			Value: 1000, PkScript: testP2WPKHScript(t, walletPub),
		},
		wantErr: ErrSigningKeyMismatch,
	}, {
		name:       "leaf the output does not commit to",
		utxo:       walletOutput,
		leafScript: walletLeaf,
		wantErr:    ErrSigningKeyMismatch,
	}, {
		name:       "leaf does not check the key",
		utxo:       foreignLeafOutput,
		leafScript: foreignLeaf,
		wantErr:    ErrSigningKeyMismatch,
	}, {
		name:       "key checked after a code separator",
		utxo:       separatedOutput,
		leafScript: separatedLeaf,
		wantErr:    ErrSigningKeyMismatch,
	}, {
		name:       "leaf version other than tapscript",
		utxo:       versionOutput,
		leafScript: versionLeaf,
		wantErr:    ErrSigningKeyMismatch,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			packet := testTaprootSignPacket(t, tc.utxo, tc.leafScript)
			packet.Inputs[0].TaprootInternalKey = tc.internalKey

			before := clonePacket(packet)
			w, mocks := createUnlockedWalletWithMocks(t)

			// Act: sign the packet.
			_, err := w.SignPsbt(t.Context(), &SignPsbtParams{
				Packet: packet, InputTweaks: tc.tweaks,
			})

			// Assert: the input is refused, no key was looked up,
			// and the caller's packet is unchanged.
			require.ErrorIs(t, err, tc.wantErr)
			mocks.store.AssertNotCalled(
				t, "GetAccountSecret", mock.Anything,
				mock.Anything,
			)
			require.Equal(t, before, clonePacket(packet))
		})
	}
}

// TestSignPsbtRejectsEcdsaDerivedKeyMismatch tests that an ECDSA record naming
// a key other than the one the wallet derives at its path fails before it is
// signed, and leaves the caller's packet unchanged.
func TestSignPsbtRejectsEcdsaDerivedKeyMismatch(t *testing.T) {
	t.Parallel()

	// Arrange: an input naming a foreign key at a path where the wallet
	// derives its own.
	foreign := testAuthKeys()[0].PubKey()
	packet := testEcdsaSignPacket(
		t, testP2WPKHScript(t, foreign), nil, nil, 84,
	)
	packet.Inputs[0].Bip32Derivation[0].PubKey =
		foreign.SerializeCompressed()
	before := clonePacket(packet)

	w, mocks := createUnlockedWalletWithMocks(t)
	_, _ = expectStoreSignerPrivKey(
		t, mocks, w.id, waddrmgr.KeyScope{Purpose: 84, Coin: 1},
		waddrmgr.DerivationPath{},
	)

	// Act: sign the packet.
	_, err := w.SignPsbt(t.Context(), &SignPsbtParams{Packet: packet})

	// Assert: the mismatch is refused and the caller's packet is
	// unchanged.
	require.ErrorIs(t, err, ErrSigningKeyMismatch)
	require.Equal(t, before, clonePacket(packet))
}

// TestSignPsbtRejectsTaprootDerivedKeyMismatch tests that a Taproot record
// naming a key other than the one the wallet derives at its path fails before
// it is signed, and leaves the caller's packet unchanged.
func TestSignPsbtRejectsTaprootDerivedKeyMismatch(t *testing.T) {
	t.Parallel()

	// Arrange: an input naming a foreign key at a path where the wallet
	// derives its own.
	foreign := testAuthKeys()[0].PubKey()
	packet := testTaprootSignPacket(t, testBip86Output(t, foreign), nil)
	packet.Inputs[0].TaprootBip32Derivation[0].XOnlyPubKey =
		schnorr.SerializePubKey(foreign)
	before := clonePacket(packet)

	w, mocks := createUnlockedWalletWithMocks(t)
	_, _ = expectStoreSignerPrivKey(
		t, mocks, w.id, waddrmgr.KeyScope{Purpose: 86, Coin: 1},
		waddrmgr.DerivationPath{},
	)

	// Act: sign the packet.
	_, err := w.SignPsbt(t.Context(), &SignPsbtParams{Packet: packet})

	// Assert: the mismatch is refused and the caller's packet is
	// unchanged.
	require.ErrorIs(t, err, ErrSigningKeyMismatch)
	require.Equal(t, before, clonePacket(packet))
}

// TestAuthorizeTaprootSignerRejectsOffCurveKey tests that a key-path
// derivation key that is not a curve point is refused rather than used.
// SignPsbt's packet validation refuses such a key first, so the check is
// reached only directly.
func TestAuthorizeTaprootSignerRejectsOffCurveKey(t *testing.T) {
	t.Parallel()

	offCurve := bytes.Repeat([]byte{0xff}, 32)

	_, err := authorizeTaprootSigner(
		&psbt.PInput{}, testBip86Output(t, testAuthKeys()[0].PubKey()),
		&psbt.TaprootBip32Derivation{XOnlyPubKey: offCurve},
		[][]byte{offCurve},
	)

	require.ErrorIs(t, err, ErrSigningKeyMismatch)
}

// testSingleWithoutOutputPacket returns a packet with two inputs and one
// output. Input 1 spends utxo under SIGHASH_SINGLE, so it has no output at its
// index; input 0 is not the wallet's.
func testSingleWithoutOutputPacket(t *testing.T, utxo *wire.TxOut,
	hashType txscript.SigHashType) *psbt.Packet {

	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 1}})
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: 2}})
	tx.AddTxOut(&wire.TxOut{Value: 500, PkScript: []byte{txscript.OP_TRUE}})

	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	packet.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value: 700, PkScript: []byte{txscript.OP_TRUE},
	}
	packet.Inputs[1].WitnessUtxo = utxo
	packet.Inputs[1].SighashType = hashType

	return packet
}

// TestSignPsbtRejectsLegacySingleWithoutOutput tests that a legacy input
// requesting SIGHASH_SINGLE with no output at its index fails before any key
// is looked up. Its signature would sign the constant digest 1, which any
// transaction can reuse.
func TestSignPsbtRejectsLegacySingleWithoutOutput(t *testing.T) {
	t.Parallel()

	_, walletPub := deriveLeafKeys(t, testAccountXPrv(t), 0, 0)
	walletKey := walletPub.SerializeCompressed()
	p2pkh := testScript(
		t, txscript.OP_DUP, txscript.OP_HASH160,
		address.Hash160(walletKey), txscript.OP_EQUALVERIFY,
		txscript.OP_CHECKSIG,
	)

	tests := []struct {
		name     string
		hashType txscript.SigHashType
	}{{
		name:     "single",
		hashType: txscript.SigHashSingle,
	}, {
		name: "single anyonecanpay",
		hashType: txscript.SigHashSingle |
			txscript.SigHashAnyOneCanPay,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			packet := testSingleWithoutOutputPacket(
				t, &wire.TxOut{Value: 1000, PkScript: p2pkh},
				tc.hashType,
			)
			packet.Inputs[1].Bip32Derivation =
				[]*psbt.Bip32Derivation{{
					PubKey:    walletKey,
					Bip32Path: testBip32Path(44),
				}}

			before := clonePacket(packet)
			w, mocks := createUnlockedWalletWithMocks(t)

			// Act: sign the packet.
			_, err := w.SignPsbt(
				t.Context(), &SignPsbtParams{Packet: packet},
			)

			// Assert: the input is refused, no key was looked up,
			// and the caller's packet is unchanged.
			require.ErrorIs(t, err, ErrUnsafeSighash)
			mocks.store.AssertNotCalled(
				t, "GetAccountSecret", mock.Anything,
				mock.Anything,
			)
			require.Equal(t, before, clonePacket(packet))
		})
	}
}

// TestSignPsbtRejectsTaprootSingleWithoutOutput tests that a Taproot input
// requesting SIGHASH_SINGLE with no output at its index fails before any key
// is looked up. BIP 341 defines no digest for it.
func TestSignPsbtRejectsTaprootSingleWithoutOutput(t *testing.T) {
	t.Parallel()

	// Arrange: a BIP-86 input at index 1 of a one-output transaction.
	_, walletPub := deriveLeafKeys(t, testAccountXPrv(t), 0, 0)
	packet := testSingleWithoutOutputPacket(
		t, testBip86Output(t, walletPub), txscript.SigHashSingle,
	)
	packet.Inputs[1].TaprootBip32Derivation =
		[]*psbt.TaprootBip32Derivation{{
			XOnlyPubKey: schnorr.SerializePubKey(walletPub),
			Bip32Path:   testBip32Path(86),
		}}

	before := clonePacket(packet)
	w, mocks := createUnlockedWalletWithMocks(t)

	// Act: sign the packet.
	_, err := w.SignPsbt(t.Context(), &SignPsbtParams{Packet: packet})

	// Assert: the input is refused, no key was looked up, and the
	// caller's packet is unchanged.
	require.ErrorIs(t, err, ErrUnsafeSighash)
	mocks.store.AssertNotCalled(
		t, "GetAccountSecret", mock.Anything, mock.Anything,
	)
	require.Equal(t, before, clonePacket(packet))
}

// TestSignPsbtSegwitSingleWithoutOutput tests that a segwit v0 input
// requesting SIGHASH_SINGLE with no output at its index is still signed: BIP
// 143 defines that digest, and the signature spends the input.
func TestSignPsbtSegwitSingleWithoutOutput(t *testing.T) {
	t.Parallel()

	// Arrange: a P2WPKH input at index 1 of a one-output transaction.
	_, walletPub := deriveLeafKeys(t, testAccountXPrv(t), 0, 0)
	walletKey := walletPub.SerializeCompressed()

	packet := testSingleWithoutOutputPacket(
		t, &wire.TxOut{
			Value: 1000, PkScript: testP2WPKHScript(t, walletPub),
		}, txscript.SigHashSingle,
	)
	packet.Inputs[1].Bip32Derivation = []*psbt.Bip32Derivation{{
		PubKey:    walletKey,
		Bip32Path: testBip32Path(84),
	}}

	w, mocks := createUnlockedWalletWithMocks(t)
	_, _ = expectStoreSignerPrivKey(
		t, mocks, w.id, waddrmgr.KeyScope{Purpose: 84, Coin: 1},
		waddrmgr.DerivationPath{},
	)

	// Act: sign the packet.
	result, err := w.SignPsbt(
		t.Context(), &SignPsbtParams{Packet: packet},
	)

	// Assert: the input is signed and the signature spends it.
	require.NoError(t, err)
	require.Equal(t, []uint32{1}, result.SignedInputs)

	records := packet.Inputs[1].PartialSigs
	require.Len(t, records, 1)
	requireInputSpends(
		t, packet, 1, nil,
		wire.TxWitness{records[0].Signature, walletKey},
	)
}
