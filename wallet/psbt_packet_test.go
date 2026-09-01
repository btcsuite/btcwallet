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

// allPsbtOperations lists every operation a packet can be admitted for, so
// that rules which must hold everywhere are exercised everywhere.
var allPsbtOperations = []psbtOperation{
	psbtOpFund, psbtOpSign, psbtOpFinalize,
}

// testParentTx returns a parent transaction with a single spendable output,
// along with the outpoint that spends it. Using a real parent keeps the
// outpoint hash and the non-witness UTXO consistent, which is exactly what the
// validator checks.
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

// testPacket returns a structurally valid packet with one input and two
// outputs, ready for a test to bend out of shape.
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

// TestValidatePacketAccepts verifies that a well formed packet is admitted for
// every operation.
func TestValidatePacketAccepts(t *testing.T) {
	t.Parallel()

	for _, op := range allPsbtOperations {
		t.Run(op.String(), func(t *testing.T) {
			t.Parallel()

			require.NoError(t, validatePacket(testPacket(t), op))
		})
	}
}

// TestValidatePacketRejects verifies the structural rules that hold for every
// operation, whatever the wallet is about to do with the packet.
func TestValidatePacketRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		// mutate bends an otherwise valid packet out of shape. A nil
		// mutate means the case supplies the packet itself.
		mutate func(*psbt.Packet)

		// packet supplies a packet outright, for cases that cannot be
		// expressed as a mutation.
		packet *psbt.Packet

		wantErr error
	}{{
		name:    "a nil packet is rejected",
		wantErr: ErrPacketNil,
	}, {
		name:    "a packet without a transaction is rejected",
		packet:  &psbt.Packet{},
		wantErr: ErrPacketNil,
	}, {
		// Input metadata is addressed by position, so a short list
		// cannot be read at all.
		name: "input records short of the inputs are rejected",
		mutate: func(p *psbt.Packet) {
			p.Inputs = nil
		},
		wantErr: ErrPacketMalformed,
	}, {
		name: "output records short of the outputs are rejected",
		mutate: func(p *psbt.Packet) {
			p.Outputs = p.Outputs[:1]
		},
		wantErr: ErrPacketMalformed,
	}, {
		// A PSBT keeps unlocking scripts in its per-input records, so
		// an inline one means this is not an unsigned template.
		name: "an inline script signature is rejected",
		mutate: func(p *psbt.Packet) {
			p.UnsignedTx.TxIn[0].SignatureScript = []byte{0x01}
		},
		wantErr: ErrPacketMalformed,
	}, {
		name: "an inline witness is rejected",
		mutate: func(p *psbt.Packet) {
			p.UnsignedTx.TxIn[0].Witness = wire.TxWitness{{0x01}}
		},
		wantErr: ErrPacketMalformed,
	}, {
		// Spending one outpoint twice makes the packet's own per-input
		// metadata ambiguous.
		name: "a duplicate input outpoint is rejected",
		mutate: func(p *psbt.Packet) {
			tx := p.UnsignedTx
			tx.TxIn = append(tx.TxIn, &wire.TxIn{
				PreviousOutPoint: tx.TxIn[0].PreviousOutPoint,
			})
			p.Inputs = append(p.Inputs, psbt.PInput{})
		},
		wantErr: ErrDuplicateInput,
	}, {
		name: "a global unclassified field is rejected",
		mutate: func(p *psbt.Packet) {
			p.Unknowns = []*psbt.Unknown{{
				Key:   []byte{0xfc},
				Value: []byte{0x01},
			}}
		},
		wantErr: ErrUnclassifiedField,
	}, {
		name: "an input unclassified field is rejected",
		mutate: func(p *psbt.Packet) {
			p.Inputs[0].Unknowns = []*psbt.Unknown{{
				Key:   []byte{0xfc},
				Value: []byte{0x01},
			}}
		},
		wantErr: ErrUnclassifiedField,
	}, {
		name: "an output unclassified field is rejected",
		mutate: func(p *psbt.Packet) {
			p.Outputs[1].Unknowns = []*psbt.Unknown{{
				Key:   []byte{0xfc},
				Value: []byte{0x01},
			}}
		},
		wantErr: ErrUnclassifiedField,
	}, {
		// This is the record that decides what the input is worth and
		// what script it pays, so a parent for some other transaction
		// cannot be let through.
		name: "a parent transaction for another outpoint is rejected",
		mutate: func(p *psbt.Packet) {
			p.Inputs[0].NonWitnessUtxo.TxOut[0].Value = 1
		},
		wantErr: ErrConflictingUtxo,
	}, {
		name: "an outpoint past the parent's outputs is rejected",
		mutate: func(p *psbt.Packet) {
			p.UnsignedTx.TxIn[0].PreviousOutPoint.Index = 5
		},
		wantErr: ErrConflictingUtxo,
	}, {
		// Two records describing different outputs leave the value
		// being spent up to whichever stage reads it first.
		name: "disagreeing utxo records are rejected",
		mutate: func(p *psbt.Packet) {
			p.Inputs[0].WitnessUtxo = &wire.TxOut{
				Value:    999,
				PkScript: bytes.Repeat([]byte{0x51}, 22),
			}
		},
		wantErr: ErrConflictingUtxo,
	}, {
		name: "ambiguous derivation information is rejected",
		mutate: func(p *psbt.Packet) {
			p.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{{
				PubKey: bytes.Repeat([]byte{0x02}, 33),
			}}
			p.Inputs[0].TaprootBip32Derivation =
				[]*psbt.TaprootBip32Derivation{{
					XOnlyPubKey: bytes.Repeat(
						[]byte{0x02}, 32,
					),
				}}
		},
		wantErr: ErrAmbiguousDerivation,
	}, {
		name: "an unknown sighash flag is rejected",
		mutate: func(p *psbt.Packet) {
			p.Inputs[0].SighashType = 0x40
		},
		wantErr: ErrUnsafeSighash,
	}, {
		name: "an unknown sighash base type is rejected",
		mutate: func(p *psbt.Packet) {
			p.Inputs[0].SighashType = 0x04
		},
		wantErr: ErrUnsafeSighash,
	}}

	for _, tc := range tests {
		for _, op := range allPsbtOperations {
			t.Run(tc.name+"/"+op.String(), func(t *testing.T) {
				t.Parallel()

				packet := tc.packet
				if tc.mutate != nil {
					packet = testPacket(t)
					tc.mutate(packet)
				}

				err := validatePacket(packet, op)
				require.ErrorIs(t, err, tc.wantErr)
			})
		}
	}
}

// TestValidatePacketSighashSingle verifies that SIGHASH_SINGLE is refused for
// funding outright, while outside funding it is admitted only when the output
// it commits to actually exists.
//
// Funding cannot honour the form at all: it appends a change output and
// re-sorts, which is precisely the input-to-output pairing SIGHASH_SINGLE
// depends on.
func TestValidatePacketSighashSingle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		// dropOutputs leaves the packet with fewer outputs than
		// inputs, so the paired output is missing.
		dropOutputs bool

		anyoneCanPay bool

		op      psbtOperation
		wantErr error
	}{{
		name:    "funding refuses sighash single",
		op:      psbtOpFund,
		wantErr: ErrUnsafeSighash,
	}, {
		name:         "funding refuses sighash single anyonecanpay",
		anyoneCanPay: true,
		op:           psbtOpFund,
		wantErr:      ErrUnsafeSighash,
	}, {
		name: "signing admits a paired sighash single",
		op:   psbtOpSign,
	}, {
		name:         "signing admits a paired anyonecanpay form",
		anyoneCanPay: true,
		op:           psbtOpSign,
	}, {
		name: "finalizing admits a paired sighash single",
		op:   psbtOpFinalize,
	}, {
		name:        "signing refuses an unpaired sighash single",
		dropOutputs: true,
		op:          psbtOpSign,
		wantErr:     ErrUnsafeSighash,
	}, {
		name:        "finalizing refuses an unpaired sighash single",
		dropOutputs: true,
		op:          psbtOpFinalize,
		wantErr:     ErrUnsafeSighash,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			packet := testPacket(t)

			sigHash := txscript.SigHashSingle
			if tc.anyoneCanPay {
				sigHash |= txscript.SigHashAnyOneCanPay
			}
			packet.Inputs[0].SighashType = sigHash

			if tc.dropOutputs {
				packet.UnsignedTx.TxOut = nil
				packet.Outputs = nil
			}

			err := validatePacket(packet, tc.op)
			if tc.wantErr == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// TestValidatePacketSignatureAdmission verifies that signature material is
// admitted for exactly the operations that are defined on signed packets.
//
// Funding rewrites the very transaction an existing signature commits to, so a
// signature present at that point is already void. Signing and finalization
// are the opposite case: other parties' signatures are the whole point, and
// the authorization checks that own them run later.
func TestValidatePacketSignatureAdmission(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sign func(*psbt.PInput)
	}{{
		name: "a partial signature",
		sign: func(in *psbt.PInput) {
			in.PartialSigs = []*psbt.PartialSig{{
				PubKey:    bytes.Repeat([]byte{0x02}, 33),
				Signature: bytes.Repeat([]byte{0x01}, 71),
			}}
		},
	}, {
		name: "a taproot key spend signature",
		sign: func(in *psbt.PInput) {
			in.TaprootKeySpendSig = bytes.Repeat(
				[]byte{0x01}, schnorrSigLen,
			)
		},
	}, {
		name: "a taproot script spend signature",
		sign: func(in *psbt.PInput) {
			in.TaprootScriptSpendSig =
				[]*psbt.TaprootScriptSpendSig{{
					XOnlyPubKey: bytes.Repeat(
						[]byte{0x02}, schnorrPubKeyLen,
					),
					Signature: bytes.Repeat(
						[]byte{0x01}, schnorrSigLen,
					),
				}}
		},
	}, {
		name: "a final script signature",
		sign: func(in *psbt.PInput) {
			in.FinalScriptSig = []byte{0x01}
		},
	}, {
		name: "a final script witness",
		sign: func(in *psbt.PInput) {
			in.FinalScriptWitness = []byte{0x01}
		},
	}}

	for _, tc := range tests {
		for _, op := range allPsbtOperations {
			t.Run(tc.name+"/"+op.String(), func(t *testing.T) {
				t.Parallel()

				packet := testPacket(t)
				tc.sign(&packet.Inputs[0])

				err := validatePacket(packet, op)
				if op == psbtOpFund {
					require.ErrorIs(t, err, ErrPacketSigned)

					return
				}

				require.NoError(t, err)
			})
		}
	}
}

// TestValidatePacketMalformedSignatures verifies that an admitted signature
// record still has to be structurally well formed. A truncated or empty record
// can never be authorized, and rejecting it here says so while the packet is
// still the thing being talked about.
func TestValidatePacketMalformedSignatures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sign func(*psbt.PInput)
	}{{
		name: "an empty partial signature record",
		sign: func(in *psbt.PInput) {
			in.PartialSigs = []*psbt.PartialSig{nil}
		},
	}, {
		name: "a partial signature without a key",
		sign: func(in *psbt.PInput) {
			in.PartialSigs = []*psbt.PartialSig{{
				Signature: bytes.Repeat([]byte{0x01}, 71),
			}}
		},
	}, {
		name: "a partial signature without a signature",
		sign: func(in *psbt.PInput) {
			in.PartialSigs = []*psbt.PartialSig{{
				PubKey: bytes.Repeat([]byte{0x02}, 33),
			}}
		},
	}, {
		name: "a truncated taproot key spend signature",
		sign: func(in *psbt.PInput) {
			in.TaprootKeySpendSig = bytes.Repeat([]byte{0x01}, 32)
		},
	}, {
		name: "an empty taproot script spend record",
		sign: func(in *psbt.PInput) {
			in.TaprootScriptSpendSig =
				[]*psbt.TaprootScriptSpendSig{nil}
		},
	}, {
		name: "a taproot script spend key of the wrong length",
		sign: func(in *psbt.PInput) {
			in.TaprootScriptSpendSig =
				[]*psbt.TaprootScriptSpendSig{{
					XOnlyPubKey: bytes.Repeat(
						[]byte{0x02}, 33,
					),
					Signature: bytes.Repeat(
						[]byte{0x01}, schnorrSigLen,
					),
				}}
		},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			packet := testPacket(t)
			tc.sign(&packet.Inputs[0])

			err := validatePacket(packet, psbtOpSign)
			require.ErrorIs(t, err, ErrMalformedSignature)
		})
	}
}

// TestValidatePacketSighashByteSignature verifies that a taproot signature
// carrying an explicit sighash byte is admitted, since that is the encoding
// any non-default sighash type uses.
func TestValidatePacketSighashByteSignature(t *testing.T) {
	t.Parallel()

	packet := testPacket(t)
	packet.Inputs[0].TaprootKeySpendSig = bytes.Repeat(
		[]byte{0x01}, schnorrSigLenWithSighash,
	)

	require.NoError(t, validatePacket(packet, psbtOpSign))
}

// TestValidatePacketLeavesPacketUnchanged verifies that validation is side
// effect free, on the accepting path as well as on every rejecting one. This
// is what lets it run first, before the wallet has committed to anything.
func TestValidatePacketLeavesPacketUnchanged(t *testing.T) {
	t.Parallel()

	mutations := map[string]func(*psbt.Packet){
		"valid": func(*psbt.Packet) {},
		"duplicate input": func(p *psbt.Packet) {
			tx := p.UnsignedTx
			tx.TxIn = append(tx.TxIn, &wire.TxIn{
				PreviousOutPoint: tx.TxIn[0].PreviousOutPoint,
			})
			p.Inputs = append(p.Inputs, psbt.PInput{})
		},
		"unclassified field": func(p *psbt.Packet) {
			p.Inputs[0].Unknowns = []*psbt.Unknown{{
				Key:   []byte{0xfc},
				Value: []byte{0x01},
			}}
		},
		"conflicting utxo": func(p *psbt.Packet) {
			p.UnsignedTx.TxIn[0].PreviousOutPoint.Index = 5
		},
		"unsafe sighash": func(p *psbt.Packet) {
			p.Inputs[0].SighashType = txscript.SigHashSingle
		},
		"signed": func(p *psbt.Packet) {
			p.Inputs[0].FinalScriptSig = []byte{0x01}
		},
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			packet := testPacket(t)
			mutate(packet)

			// The comparison packet is built the same way rather
			// than copied from the first, so that this test does
			// not lean on the very copying it is meant to police.
			before := testPacket(t)
			mutate(before)

			// The result is deliberately ignored: whether the
			// packet is admitted or refused, it must come back
			// exactly as it went in.
			_ = validatePacket(packet, psbtOpFund)

			require.Equal(t, before, packet)
		})
	}
}

// TestPsbtOperationString verifies that every operation names itself, since
// the names appear in errors a caller has to act on.
func TestPsbtOperationString(t *testing.T) {
	t.Parallel()

	require.Equal(t, "fund", psbtOpFund.String())
	require.Equal(t, "sign", psbtOpSign.String())
	require.Equal(t, "finalize", psbtOpFinalize.String())
	require.Contains(t, psbtOperation(99).String(), "unknown")

	require.False(t, psbtOpFund.admitsSignatures())
	require.True(t, psbtOpSign.admitsSignatures())
	require.True(t, psbtOpFinalize.admitsSignatures())
}
