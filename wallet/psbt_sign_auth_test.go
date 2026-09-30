// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
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
