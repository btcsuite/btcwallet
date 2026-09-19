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

// TestValidateInputSighash verifies which sighash types an input may ask for.
//
// The base type is the low five bits and ANYONECANPAY is the only modifier
// defined on top of it, so the admissible set is small and fully enumerable.
func TestValidateInputSighash(t *testing.T) {
	t.Parallel()

	const (
		unknownModifier = txscript.SigHashType(0x40)
		unknownBase     = txscript.SigHashType(0x05)
	)

	tests := []struct {
		name    string
		sigHash txscript.SigHashType
		wantErr error
	}{{
		// Indistinguishable from an unset field, so it is admitted
		// for every input type.
		name:    "the default type",
		sigHash: txscript.SigHashDefault,
	}, {
		name:    "sighash all",
		sigHash: txscript.SigHashAll,
	}, {
		name:    "sighash none",
		sigHash: txscript.SigHashNone,
	}, {
		// Well formed here. Whether funding can honour it is
		// funding's own question.
		name:    "sighash single",
		sigHash: txscript.SigHashSingle,
	}, {
		name:    "sighash all with anyonecanpay",
		sigHash: txscript.SigHashAll | txscript.SigHashAnyOneCanPay,
	}, {
		name:    "sighash none with anyonecanpay",
		sigHash: txscript.SigHashNone | txscript.SigHashAnyOneCanPay,
	}, {
		name:    "sighash single with anyonecanpay",
		sigHash: txscript.SigHashSingle | txscript.SigHashAnyOneCanPay,
	}, {
		// The default type is the absence of a type, so there is
		// nothing for a modifier to modify. Taproot spells the
		// ANYONECANPAY variant as 0x81, never 0x80.
		name:    "anyonecanpay on its own",
		sigHash: txscript.SigHashAnyOneCanPay,
		wantErr: ErrUnsafeSighash,
	}, {
		name:    "an unknown modifier flag",
		sigHash: txscript.SigHashAll | unknownModifier,
		wantErr: ErrUnsafeSighash,
	}, {
		name:    "an unknown base type",
		sigHash: unknownBase,
		wantErr: ErrUnsafeSighash,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			packet := testPacket(t)
			packet.Inputs[0].SighashType = tc.sigHash

			err := validatePacket(packet)

			if tc.wantErr == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestValidatePacketLeavesPacketUnchanged verifies that validation is
// side-effect free.
//
// It runs before the wallet commits to anything, and callers rely on being
// handed back exactly what they passed in when it refuses, so it must not
// touch the packet even on the paths that accept one.
func TestValidatePacketLeavesPacketUnchanged(t *testing.T) {
	t.Parallel()

	// Arrange: a packet carrying something in every field validation
	// looks at, plus a signature so the funding gate has something to
	// reject.
	packet := testPacket(t)
	packet.Inputs[0].PartialSigs = []*psbt.PartialSig{{
		PubKey:    bytes.Repeat([]byte{0x02}, 33),
		Signature: bytes.Repeat([]byte{0x30}, 71),
	}}
	packet.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{{
		PubKey:               bytes.Repeat([]byte{0x02}, 33),
		MasterKeyFingerprint: 0x11223344,
		Bip32Path:            []uint32{84, 0, 0, 0, 1},
	}}
	packet.Outputs[0].WitnessScript = []byte{0x51, 0x52}

	before, err := packet.B64Encode()
	require.NoError(t, err)

	// Act: run both the structural core and the funding gate, which
	// rejects this packet for its signature.
	require.NoError(t, validatePacket(packet))
	require.ErrorIs(t, validateFundPacket(packet), ErrPacketSigned)

	// Assert: neither call altered a byte of it.
	after, err := packet.B64Encode()
	require.NoError(t, err)
	require.Equal(t, before, after)
}

// TestValidateFundPacketAcceptsUnsigned verifies that an ordinary unsigned
// packet passes the funding gate.
func TestValidateFundPacketAcceptsUnsigned(t *testing.T) {
	t.Parallel()

	packet := testPacket(t)

	err := validateFundPacket(packet)

	require.NoError(t, err)
}

// TestValidateFundPacketRejectsSignatures verifies that funding refuses a
// packet that already carries signature material, in any of the forms a PSBT
// can hold it.
//
// Funding rewrites the very transaction those signatures commit to, so one
// present here is either already void or about to be. Saying so is more use to
// the caller than silently invalidating it.
func TestValidateFundPacketRejectsSignatures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input psbt.PInput
	}{{
		name: "an ecdsa partial signature",
		input: psbt.PInput{
			PartialSigs: []*psbt.PartialSig{{
				PubKey:    bytes.Repeat([]byte{0x02}, 33),
				Signature: bytes.Repeat([]byte{0x30}, 71),
			}},
		},
	}, {
		name: "a taproot key spend signature",
		input: psbt.PInput{
			TaprootKeySpendSig: bytes.Repeat([]byte{0x01}, 64),
		},
	}, {
		name: "a taproot script spend signature",
		input: psbt.PInput{
			TaprootScriptSpendSig: []*psbt.TaprootScriptSpendSig{{
				XOnlyPubKey: bytes.Repeat([]byte{0x02}, 32),
				LeafHash:    bytes.Repeat([]byte{0x03}, 32),
				Signature:   bytes.Repeat([]byte{0x01}, 64),
			}},
		},
	}, {
		name: "a finalized script signature",
		input: psbt.PInput{
			FinalScriptSig: []byte{0x51},
		},
	}, {
		name: "a finalized witness",
		input: psbt.PInput{
			FinalScriptWitness: []byte{0x01, 0x01, 0x51},
		},
	}, {
		// Present but empty still marks the input finalized, which is
		// what the psbt package's own check asks.
		name: "an empty but present script signature",
		input: psbt.PInput{
			FinalScriptSig: []byte{},
		},
	}, {
		name: "an empty but present witness",
		input: psbt.PInput{
			FinalScriptWitness: []byte{},
		},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: keep the input's UTXO records, so the only
			// thing wrong with the packet is the signature.
			packet := testPacket(t)
			input := tc.input
			input.NonWitnessUtxo = packet.Inputs[0].NonWitnessUtxo
			input.WitnessUtxo = packet.Inputs[0].WitnessUtxo
			packet.Inputs[0] = input

			err := validateFundPacket(packet)

			require.ErrorIs(t, err, ErrPacketSigned)
		})
	}
}

// TestValidateFundPacketRejectsSighashSingle verifies that funding refuses
// SIGHASH_SINGLE, with or without ANYONECANPAY.
//
// It commits an input to the output at its own index, and funding appends a
// change output and re-sorts, so it cannot keep outputs where the caller put
// them.
func TestValidateFundPacketRejectsSighashSingle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sigHash txscript.SigHashType
	}{{
		name:    "on its own",
		sigHash: txscript.SigHashSingle,
	}, {
		name:    "with anyonecanpay",
		sigHash: txscript.SigHashSingle | txscript.SigHashAnyOneCanPay,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			packet := testPacket(t)
			packet.Inputs[0].SighashType = tc.sigHash

			err := validateFundPacket(packet)

			require.ErrorIs(t, err, ErrUnsafeSighash)
		})
	}
}
