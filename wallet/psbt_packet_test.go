// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// testParentTx returns a transaction to be spent, the outpoint naming its only
// output, and that output.
func testParentTx(t *testing.T) (*wire.MsgTx, wire.OutPoint, *wire.TxOut) {
	t.Helper()

	out := &wire.TxOut{
		Value:    100000,
		PkScript: bytes.Repeat([]byte{0x51}, 22),
	}

	parent := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Index: 7},
		}},
		TxOut: []*wire.TxOut{out},
	}

	return parent, wire.OutPoint{Hash: parent.TxHash(), Index: 0}, out
}

// testValidKey and testOtherValidKey return deterministic keys that parse, so
// derivation fixtures carry usable material.
func testValidKey() *btcec.PublicKey {
	priv, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{1}, 32))

	return priv.PubKey()
}

func testOtherValidKey() *btcec.PublicKey {
	priv, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{2}, 32))

	return priv.PubKey()
}

// testPacket returns a packet that passes validatePacket, so that a test can
// make one thing wrong with it and know that is the only thing wrong.
func testPacket(t *testing.T) *psbt.Packet {
	t.Helper()

	parent, outPoint, prevOut := testParentTx(t)

	return &psbt.Packet{
		UnsignedTx: &wire.MsgTx{
			Version: 2,
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: outPoint,
				Sequence:         wire.MaxTxInSequenceNum - 2,
			}},
			TxOut: []*wire.TxOut{{
				Value:    40000,
				PkScript: bytes.Repeat([]byte{0x52}, 22),
			}, {
				Value:    50000,
				PkScript: bytes.Repeat([]byte{0x53}, 22),
			}},
		},
		Inputs: []psbt.PInput{{
			NonWitnessUtxo: parent,
			WitnessUtxo:    prevOut,
			SighashType:    txscript.SigHashAll,
		}},
		Outputs: make([]psbt.POutput, 2),
	}
}

// TestValidatePacketAccepts verifies that a well formed packet is admitted, so
// that the rejection tests below are known to be rejecting the one thing they
// each make wrong.
func TestValidatePacketAccepts(t *testing.T) {
	t.Parallel()

	// Arrange: a packet with nothing wrong with it.
	packet := testPacket(t)

	err := validatePacket(packet)

	require.NoError(t, err)
}

// TestValidatePacketNilPacket verifies that a missing packet is reported
// rather than dereferenced.
func TestValidatePacketNilPacket(t *testing.T) {
	t.Parallel()

	require.ErrorIs(t, validatePacket(nil), ErrPacketNil)
}

// TestValidatePacketNilUnsignedTx verifies that a packet with no transaction
// in it is reported rather than dereferenced.
func TestValidatePacketNilUnsignedTx(t *testing.T) {
	t.Parallel()

	packet := &psbt.Packet{}

	require.ErrorIs(t, validatePacket(packet), ErrPacketNil)
}

// TestValidatePacketRecordCountMismatch verifies that a packet whose record
// lists are a different length than its transaction is refused. The rule
// itself belongs to the psbt package; this checks that its verdict is
// surfaced under the wallet's own error.
func TestValidatePacketRecordCountMismatch(t *testing.T) {
	t.Parallel()

	// Arrange: two outputs but only one output record.
	packet := testPacket(t)
	packet.Outputs = make([]psbt.POutput, 1)

	err := validatePacket(packet)

	require.ErrorIs(t, err, ErrPacketMalformed)
}

// TestValidatePacketNilTxIn verifies that a nil transaction input is refused.
//
// A caller assembles a Packet as a plain struct, so it can hold one. Both
// SanityCheck and the wallet's own loops read through these entries, so this
// has to be caught before either runs.
func TestValidatePacketNilTxIn(t *testing.T) {
	t.Parallel()

	packet := testPacket(t)
	packet.UnsignedTx.TxIn[0] = nil

	err := validatePacket(packet)

	// Assert: refused, rather than panicking.
	require.ErrorIs(t, err, ErrPacketMalformed)
}

// TestValidatePacketNilTxOut verifies that a nil transaction output is
// refused rather than dereferenced by a later stage.
func TestValidatePacketNilTxOut(t *testing.T) {
	t.Parallel()

	packet := testPacket(t)
	packet.UnsignedTx.TxOut[1] = nil

	err := validatePacket(packet)

	require.ErrorIs(t, err, ErrPacketMalformed)
}

// TestValidatePacketNilParentEntries verifies that a nil entry inside the
// caller's parent transaction is refused. Hashing and copying the parent both
// read through its own inputs and outputs.
func TestValidatePacketNilParentEntries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		parent *wire.MsgTx
	}{{
		name: "a nil parent input",
		parent: &wire.MsgTx{
			Version: 2,
			TxIn:    []*wire.TxIn{nil},
			TxOut: []*wire.TxOut{{
				Value: 1, PkScript: []byte{0x51},
			}},
		},
	}, {
		name: "a nil parent output",
		parent: &wire.MsgTx{
			Version: 2,
			TxIn:    []*wire.TxIn{{}},
			TxOut:   []*wire.TxOut{nil},
		},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			packet := testPacket(t)
			packet.Inputs[0].NonWitnessUtxo = tc.parent
			packet.Inputs[0].WitnessUtxo = nil

			err := validatePacket(packet)

			// Assert: refused, rather than panicking.
			require.ErrorIs(t, err, ErrPacketMalformed)
		})
	}
}

// TestValidatePacketNilInputRecords verifies that a nil entry in any of an
// input's pointer-bearing record lists is refused.
func TestValidatePacketNilInputRecords(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input psbt.PInput
	}{{
		name:  "a nil partial signature",
		input: psbt.PInput{PartialSigs: []*psbt.PartialSig{nil}},
	}, {
		name: "a nil taproot script spend signature",
		input: psbt.PInput{
			TaprootScriptSpendSig: []*psbt.TaprootScriptSpendSig{
				nil,
			},
		},
	}, {
		name: "a nil taproot leaf script",
		input: psbt.PInput{
			TaprootLeafScript: []*psbt.TaprootTapLeafScript{nil},
		},
	}, {
		name: "a nil bip32 derivation",
		input: psbt.PInput{
			Bip32Derivation: []*psbt.Bip32Derivation{nil},
		},
	}, {
		name: "a nil taproot derivation",
		input: psbt.PInput{
			TaprootBip32Derivation: []*psbt.TaprootBip32Derivation{
				nil,
			},
		},
	}, {
		name:  "a nil unknown field",
		input: psbt.PInput{Unknowns: []*psbt.Unknown{nil}},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			packet := testPacket(t)
			packet.Inputs[0] = tc.input

			err := validatePacket(packet)

			require.ErrorIs(t, err, ErrPacketMalformed)
		})
	}
}

// TestValidatePacketNilOutputRecords verifies that a nil entry in any of an
// output's pointer-bearing record lists is refused.
func TestValidatePacketNilOutputRecords(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		output psbt.POutput
	}{{
		name: "a nil bip32 derivation",
		output: psbt.POutput{
			Bip32Derivation: []*psbt.Bip32Derivation{nil},
		},
	}, {
		name: "a nil taproot derivation",
		output: psbt.POutput{
			TaprootBip32Derivation: []*psbt.TaprootBip32Derivation{
				nil,
			},
		},
	}, {
		name:   "a nil unknown field",
		output: psbt.POutput{Unknowns: []*psbt.Unknown{nil}},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			packet := testPacket(t)
			packet.Outputs[0] = tc.output

			err := validatePacket(packet)

			require.ErrorIs(t, err, ErrPacketMalformed)
		})
	}
}

// TestValidatePacketDerivationKeys verifies that derivation records carrying
// a key the psbt package could not parse are refused.
//
// A record is only metadata until something reads it, and what reads it parses
// the key. Admitting one that cannot parse would let funding hand back a
// packet the caller could not serialize.
func TestValidatePacketDerivationKeys(t *testing.T) {
	t.Parallel()

	valid := testValidKey()

	tests := []struct {
		name    string
		input   psbt.PInput
		wantErr bool
	}{{
		name: "a usable compressed key",
		input: psbt.PInput{
			Bip32Derivation: []*psbt.Bip32Derivation{{
				PubKey: valid.SerializeCompressed(),
			}},
		},
	}, {
		name: "a usable x-only key",
		input: psbt.PInput{
			TaprootBip32Derivation: []*psbt.TaprootBip32Derivation{{
				XOnlyPubKey: schnorr.SerializePubKey(valid),
			}},
		},
	}, {
		name: "a one byte key",
		input: psbt.PInput{
			Bip32Derivation: []*psbt.Bip32Derivation{{
				PubKey: []byte{0x02},
			}},
		},
		wantErr: true,
	}, {
		name: "a truncated x-only key",
		input: psbt.PInput{
			TaprootBip32Derivation: []*psbt.TaprootBip32Derivation{{
				XOnlyPubKey: bytes.Repeat([]byte{0x02}, 31),
			}},
		},
		wantErr: true,
	}, {
		name: "one key named twice",
		input: psbt.PInput{
			Bip32Derivation: []*psbt.Bip32Derivation{{
				PubKey: valid.SerializeCompressed(),
			}, {
				PubKey: valid.SerializeCompressed(),
			}},
		},
		wantErr: true,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			packet := testPacket(t)
			input := tc.input
			input.NonWitnessUtxo = packet.Inputs[0].NonWitnessUtxo
			input.WitnessUtxo = packet.Inputs[0].WitnessUtxo
			packet.Inputs[0] = input

			err := validatePacket(packet)

			if !tc.wantErr {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrPacketMalformed)
		})
	}
}

// TestValidatePacketAcceptsMultipleDerivations verifies that an input naming
// several keys is admitted. Multisig and coordinator packets carry one record
// per cosigner, and funding preserves them rather than refusing them.
func TestValidatePacketAcceptsMultipleDerivations(t *testing.T) {
	t.Parallel()

	packet := testPacket(t)
	packet.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{{
		PubKey: testValidKey().SerializeCompressed(),
	}, {
		PubKey: testOtherValidKey().SerializeCompressed(),
	}}

	require.NoError(t, validatePacket(packet))
}

// TestValidatePacketSignedTransaction verifies that a transaction carrying its
// unlocking script inline is refused. A PSBT holds those in its per-input
// records, so a packet with one inline is not the unsigned template it claims
// to be.
func TestValidatePacketSignedTransaction(t *testing.T) {
	t.Parallel()

	packet := testPacket(t)
	packet.UnsignedTx.TxIn[0].SignatureScript = []byte{0x51}

	err := validatePacket(packet)

	require.ErrorIs(t, err, ErrPacketMalformed)
}

// TestValidatePacketParentTxMismatch verifies that a parent transaction that
// is not the one the input names is refused. Every later stage reads the spent
// output from these records, so a caller must not be able to substitute one.
func TestValidatePacketParentTxMismatch(t *testing.T) {
	t.Parallel()

	// Arrange: a parent that hashes to something other than the outpoint.
	packet := testPacket(t)
	packet.Inputs[0].NonWitnessUtxo = &wire.MsgTx{
		Version: 2,
		TxIn:    []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{{
			Value: 1, PkScript: []byte{0x51},
		}},
	}

	err := validatePacket(packet)

	require.ErrorIs(t, err, ErrConflictingUtxo)
}

// TestValidatePacketParentIndexOutOfRange verifies that an input spending an
// output its own parent transaction does not have is refused rather than
// indexing past the parent's outputs.
func TestValidatePacketParentIndexOutOfRange(t *testing.T) {
	t.Parallel()

	// Arrange: the parent has one output; name its second.
	parent, outPoint, _ := testParentTx(t)
	outPoint.Index = 1

	packet := testPacket(t)
	packet.UnsignedTx.TxIn[0].PreviousOutPoint = outPoint
	packet.Inputs[0].NonWitnessUtxo = parent
	packet.Inputs[0].WitnessUtxo = nil

	err := validatePacket(packet)

	require.ErrorIs(t, err, ErrConflictingUtxo)
}

// TestValidatePacketUtxoViewsDisagree verifies that a packet carrying both
// views of the spent output is refused when they are not the same output,
// since nothing could tell which one the caller meant.
func TestValidatePacketUtxoViewsDisagree(t *testing.T) {
	t.Parallel()

	// Arrange: a witness UTXO that is not the parent's output.
	packet := testPacket(t)
	packet.Inputs[0].WitnessUtxo = &wire.TxOut{
		Value:    99999,
		PkScript: bytes.Repeat([]byte{0x51}, 22),
	}

	err := validatePacket(packet)

	require.ErrorIs(t, err, ErrConflictingUtxo)
}
