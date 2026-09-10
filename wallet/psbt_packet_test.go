// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"testing"

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

	// Act.
	err := validatePacket(packet)

	// Assert.
	require.NoError(t, err)
}

// TestValidatePacketNilPacket verifies that a missing packet is reported
// rather than dereferenced.
func TestValidatePacketNilPacket(t *testing.T) {
	t.Parallel()

	// Act and assert.
	require.ErrorIs(t, validatePacket(nil), ErrPacketNil)
}

// TestValidatePacketNilUnsignedTx verifies that a packet with no transaction
// in it is reported rather than dereferenced.
func TestValidatePacketNilUnsignedTx(t *testing.T) {
	t.Parallel()

	// Arrange.
	packet := &psbt.Packet{}

	// Act and assert.
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

	// Act.
	err := validatePacket(packet)

	// Assert.
	require.ErrorIs(t, err, ErrPacketMalformed)
}

// TestValidatePacketNilTxIn verifies that a nil transaction input is refused.
//
// A caller assembles a Packet as a plain struct, so it can hold one. Both
// SanityCheck and the wallet's own loops read through these entries, so this
// has to be caught before either runs.
func TestValidatePacketNilTxIn(t *testing.T) {
	t.Parallel()

	// Arrange.
	packet := testPacket(t)
	packet.UnsignedTx.TxIn[0] = nil

	// Act.
	err := validatePacket(packet)

	// Assert: refused, rather than panicking.
	require.ErrorIs(t, err, ErrPacketMalformed)
}

// TestValidatePacketNilTxOut verifies that a nil transaction output is
// refused rather than dereferenced by a later stage.
func TestValidatePacketNilTxOut(t *testing.T) {
	t.Parallel()

	// Arrange.
	packet := testPacket(t)
	packet.UnsignedTx.TxOut[1] = nil

	// Act.
	err := validatePacket(packet)

	// Assert.
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

			// Arrange.
			packet := testPacket(t)
			packet.Inputs[0].NonWitnessUtxo = tc.parent
			packet.Inputs[0].WitnessUtxo = nil

			// Act.
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

			// Arrange.
			packet := testPacket(t)
			packet.Inputs[0] = tc.input

			// Act.
			err := validatePacket(packet)

			// Assert.
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

			// Arrange.
			packet := testPacket(t)
			packet.Outputs[0] = tc.output

			// Act.
			err := validatePacket(packet)

			// Assert.
			require.ErrorIs(t, err, ErrPacketMalformed)
		})
	}
}

// TestValidatePacketSignedTransaction verifies that a transaction carrying its
// unlocking script inline is refused. A PSBT holds those in its per-input
// records, so a packet with one inline is not the unsigned template it claims
// to be.
func TestValidatePacketSignedTransaction(t *testing.T) {
	t.Parallel()

	// Arrange.
	packet := testPacket(t)
	packet.UnsignedTx.TxIn[0].SignatureScript = []byte{0x51}

	// Act.
	err := validatePacket(packet)

	// Assert.
	require.ErrorIs(t, err, ErrPacketMalformed)
}

// TestValidatePacketDuplicateInput verifies that a packet spending one
// outpoint twice is refused: its per-input metadata would be ambiguous and the
// transaction it describes unspendable.
func TestValidatePacketDuplicateInput(t *testing.T) {
	t.Parallel()

	// Arrange: a second input spending the outpoint the first one does.
	packet := testPacket(t)
	outPoint := packet.UnsignedTx.TxIn[0].PreviousOutPoint
	packet.UnsignedTx.TxIn = append(
		packet.UnsignedTx.TxIn, &wire.TxIn{PreviousOutPoint: outPoint},
	)
	packet.Inputs = append(packet.Inputs, psbt.PInput{})

	// Act.
	err := validatePacket(packet)

	// Assert.
	require.ErrorIs(t, err, ErrDuplicateInput)
}

// TestValidatePacketUnclassifiedFields verifies that a packet carrying a field
// the wallet cannot classify is refused at every level it can appear.
//
// Funding cannot promise to preserve a field it cannot even name, so refusing
// is the only honest answer; silently dropping it is not.
func TestValidatePacketUnclassifiedFields(t *testing.T) {
	t.Parallel()

	unknowns := []*psbt.Unknown{{
		Key:   []byte{0xfc},
		Value: []byte{0x01},
	}}

	tests := []struct {
		name   string
		global []*psbt.Unknown
		input  []*psbt.Unknown
		output []*psbt.Unknown
	}{{
		name:   "a global field",
		global: unknowns,
	}, {
		name:  "an input field",
		input: unknowns,
	}, {
		name:   "an output field",
		output: unknowns,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange.
			packet := testPacket(t)
			packet.Unknowns = tc.global
			packet.Inputs[0].Unknowns = tc.input
			packet.Outputs[0].Unknowns = tc.output

			// Act.
			err := validatePacket(packet)

			// Assert.
			require.ErrorIs(t, err, ErrUnclassifiedField)
		})
	}
}
