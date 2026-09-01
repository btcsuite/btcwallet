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

// testWalletUtxo is the output the wallet is taken to have looked up for the
// input the funding helpers are exercised against.
func testWalletUtxo() *wire.TxOut {
	return &wire.TxOut{
		Value:    100000,
		PkScript: bytes.Repeat([]byte{0x51}, 22),
	}
}

// testWalletDerivation is the derivation the wallet is taken to have derived
// for that same input.
func testWalletDerivation() []*psbt.Bip32Derivation {
	return []*psbt.Bip32Derivation{{
		PubKey:               bytes.Repeat([]byte{0x02}, 33),
		MasterKeyFingerprint: 7,
		Bip32Path:            []uint32{84, 0, 0, 0, 1},
	}}
}

// testDecoratedInput returns an input record as the wallet's own decoration
// would leave it.
func testDecoratedInput() psbt.PInput {
	return psbt.PInput{
		WitnessUtxo:     testWalletUtxo(),
		SighashType:     txscript.SigHashAll,
		Bip32Derivation: testWalletDerivation(),
	}
}

// TestIndexCallerInputs verifies that a caller's inputs are keyed by the
// outpoint each spends, carrying the sequence number and metadata across.
//
// The outpoint is the key because it is the only thing about an input that
// survives authoring and sorting; its position does not.
func TestIndexCallerInputs(t *testing.T) {
	t.Parallel()

	firstOutPoint := wire.OutPoint{Index: 1}
	secondOutPoint := wire.OutPoint{Index: 2}

	packet := &psbt.Packet{
		UnsignedTx: &wire.MsgTx{
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: firstOutPoint,
				Sequence:         11,
			}, {
				PreviousOutPoint: secondOutPoint,
				Sequence:         22,
			}},
		},
		Inputs: []psbt.PInput{{
			WitnessScript: []byte{0xaa},
		}, {
			WitnessScript: []byte{0xbb},
		}},
	}

	index := indexCallerInputs(packet)
	require.Len(t, index, 2)

	require.Equal(t, uint32(11), index[firstOutPoint].sequence)
	require.Equal(
		t, []byte{0xaa}, index[firstOutPoint].pInput.WitnessScript,
	)

	require.Equal(t, uint32(22), index[secondOutPoint].sequence)
	require.Equal(
		t, []byte{0xbb}, index[secondOutPoint].pInput.WitnessScript,
	)
}

// TestRestoreInputMetadataKeepsCallerFields verifies that the fields the
// wallet never derives survive funding, which is the whole point of keying the
// caller's records by outpoint in the first place.
func TestRestoreInputMetadataKeepsCallerFields(t *testing.T) {
	t.Parallel()

	outPoint := wire.OutPoint{Index: 3}

	caller := psbt.PInput{
		WitnessScript:     []byte{0x53, 0x54},
		TaprootMerkleRoot: bytes.Repeat([]byte{0x09}, 32),
		TaprootLeafScript: []*psbt.TaprootTapLeafScript{{
			ControlBlock: bytes.Repeat([]byte{0xc0}, 33),
			Script:       []byte{0x51},
			LeafVersion:  txscript.BaseLeafVersion,
		}},
		TaprootInternalKey: bytes.Repeat([]byte{0x02}, 32),
	}

	packet := &psbt.Packet{
		UnsignedTx: &wire.MsgTx{
			TxIn: []*wire.TxIn{{PreviousOutPoint: outPoint}},
		},
		Inputs: []psbt.PInput{testDecoratedInput()},
	}

	err := restoreInputMetadata(packet, map[wire.OutPoint]callerInput{
		outPoint: {pInput: caller},
	})
	require.NoError(t, err)

	restored := packet.Inputs[0]

	// The caller's own fields come back untouched.
	require.Equal(t, caller.WitnessScript, restored.WitnessScript)
	require.Equal(t, caller.TaprootMerkleRoot, restored.TaprootMerkleRoot)
	require.Equal(t, caller.TaprootLeafScript, restored.TaprootLeafScript)
	require.Equal(
		t, caller.TaprootInternalKey, restored.TaprootInternalKey,
	)

	// The wallet's own facts about the coin stay the wallet's.
	require.Equal(t, testWalletUtxo(), restored.WitnessUtxo)
	require.Equal(t, testWalletDerivation(), restored.Bip32Derivation)
}

// TestRestoreInputMetadataRejectsConflicts verifies that a caller telling the
// wallet something untrue about the wallet's own coin is refused rather than
// silently overruled.
//
// Silently overruling would be the more forgiving choice, but it hides from
// the caller that the packet it gets back does not say what it asked for, and
// these are exactly the fields the signing path reads.
func TestRestoreInputMetadataRejectsConflicts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		caller psbt.PInput
	}{{
		name: "a different spent output",
		caller: psbt.PInput{
			WitnessUtxo: &wire.TxOut{
				Value:    999,
				PkScript: bytes.Repeat([]byte{0x51}, 22),
			},
		},
	}, {
		name: "a different spending key",
		caller: psbt.PInput{
			Bip32Derivation: []*psbt.Bip32Derivation{{
				PubKey:               bytes.Repeat([]byte{0x03}, 33),
				MasterKeyFingerprint: 7,
				Bip32Path:            []uint32{84, 0, 0, 0, 1},
			}},
		},
	}, {
		name: "a different derivation path",
		caller: psbt.PInput{
			Bip32Derivation: []*psbt.Bip32Derivation{{
				PubKey:               bytes.Repeat([]byte{0x02}, 33),
				MasterKeyFingerprint: 7,
				Bip32Path:            []uint32{84, 0, 0, 1, 1},
			}},
		},
	}, {
		name: "a different master fingerprint",
		caller: psbt.PInput{
			Bip32Derivation: []*psbt.Bip32Derivation{{
				PubKey:               bytes.Repeat([]byte{0x02}, 33),
				MasterKeyFingerprint: 8,
				Bip32Path:            []uint32{84, 0, 0, 0, 1},
			}},
		},
	}, {
		name: "an extra derivation record",
		caller: psbt.PInput{
			Bip32Derivation: append(
				testWalletDerivation(),
				&psbt.Bip32Derivation{
					PubKey: bytes.Repeat([]byte{0x03}, 33),
				},
			),
		},
	}, {
		name: "a different redeem script",
		caller: psbt.PInput{
			RedeemScript: []byte{0x99},
		},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			outPoint := wire.OutPoint{Index: 3}

			decorated := testDecoratedInput()

			// A nested witness input is the case where the wallet
			// states a redeem script of its own, so the conflict
			// has something to be a conflict with.
			decorated.RedeemScript = []byte{0x00, 0x14}

			packet := &psbt.Packet{
				UnsignedTx: &wire.MsgTx{
					TxIn: []*wire.TxIn{{
						PreviousOutPoint: outPoint,
					}},
				},
				Inputs: []psbt.PInput{decorated},
			}

			err := restoreInputMetadata(
				packet, map[wire.OutPoint]callerInput{
					outPoint: {pInput: tc.caller},
				},
			)
			require.ErrorIs(t, err, ErrConflictingInputMetadata)
		})
	}
}

// TestRestoreInputMetadataRejectsTaprootConflict verifies that the taproot
// derivation is held to the same rule as the BIP32 one.
func TestRestoreInputMetadataRejectsTaprootConflict(t *testing.T) {
	t.Parallel()

	outPoint := wire.OutPoint{Index: 3}

	decorated := psbt.PInput{
		WitnessUtxo: testWalletUtxo(),
		TaprootBip32Derivation: []*psbt.TaprootBip32Derivation{{
			XOnlyPubKey: bytes.Repeat([]byte{0x02}, 32),
			Bip32Path:   []uint32{86, 0, 0, 0, 1},
		}},
	}

	caller := psbt.PInput{
		TaprootBip32Derivation: []*psbt.TaprootBip32Derivation{{
			XOnlyPubKey: bytes.Repeat([]byte{0x03}, 32),
			Bip32Path:   []uint32{86, 0, 0, 0, 1},
		}},
	}

	packet := &psbt.Packet{
		UnsignedTx: &wire.MsgTx{
			TxIn: []*wire.TxIn{{PreviousOutPoint: outPoint}},
		},
		Inputs: []psbt.PInput{decorated},
	}

	err := restoreInputMetadata(packet, map[wire.OutPoint]callerInput{
		outPoint: {pInput: caller},
	})
	require.ErrorIs(t, err, ErrConflictingInputMetadata)
}

// TestRestoreInputMetadataAgreeingValues verifies that a caller which repeats
// back exactly what the wallet knows is not treated as a conflict. Callers
// that decorated a packet before funding it are in this position.
func TestRestoreInputMetadataAgreeingValues(t *testing.T) {
	t.Parallel()

	outPoint := wire.OutPoint{Index: 3}

	caller := psbt.PInput{
		WitnessUtxo:     testWalletUtxo(),
		Bip32Derivation: testWalletDerivation(),
	}

	packet := &psbt.Packet{
		UnsignedTx: &wire.MsgTx{
			TxIn: []*wire.TxIn{{PreviousOutPoint: outPoint}},
		},
		Inputs: []psbt.PInput{testDecoratedInput()},
	}

	err := restoreInputMetadata(packet, map[wire.OutPoint]callerInput{
		outPoint: {pInput: caller},
	})
	require.NoError(t, err)
	require.Equal(t, testDecoratedInput(), packet.Inputs[0])
}

// TestRestoreInputMetadataSighash verifies that an explicit sighash request
// from the caller survives funding, while a caller that asked for nothing
// keeps the default the wallet wrote.
func TestRestoreInputMetadataSighash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		caller txscript.SigHashType
		want   txscript.SigHashType
	}{{
		name:   "an explicit request is kept",
		caller: txscript.SigHashNone,
		want:   txscript.SigHashNone,
	}, {
		name: "an explicit anyonecanpay request is kept",
		caller: txscript.SigHashNone |
			txscript.SigHashAnyOneCanPay,
		want: txscript.SigHashNone | txscript.SigHashAnyOneCanPay,
	}, {
		// SigHashDefault is zero, so it cannot be told apart from an
		// absent field. The wallet's default stands.
		name:   "no request keeps the wallet default",
		caller: txscript.SigHashDefault,
		want:   txscript.SigHashAll,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			outPoint := wire.OutPoint{Index: 3}

			packet := &psbt.Packet{
				UnsignedTx: &wire.MsgTx{
					TxIn: []*wire.TxIn{{
						PreviousOutPoint: outPoint,
					}},
				},
				Inputs: []psbt.PInput{testDecoratedInput()},
			}

			err := restoreInputMetadata(
				packet, map[wire.OutPoint]callerInput{
					outPoint: {pInput: psbt.PInput{
						SighashType: tc.caller,
					}},
				},
			)
			require.NoError(t, err)
			require.Equal(
				t, tc.want, packet.Inputs[0].SighashType,
			)
		})
	}
}

// TestRestoreInputMetadataSkipsWalletInputs verifies that an input the wallet
// selected itself is left exactly as decoration produced it. There is no
// caller record for it, and inventing one would be inventing caller intent.
func TestRestoreInputMetadataSkipsWalletInputs(t *testing.T) {
	t.Parallel()

	packet := &psbt.Packet{
		UnsignedTx: &wire.MsgTx{
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{Index: 3},
			}},
		},
		Inputs: []psbt.PInput{testDecoratedInput()},
	}

	// The index describes some other outpoint entirely.
	err := restoreInputMetadata(packet, map[wire.OutPoint]callerInput{
		{Index: 9}: {pInput: psbt.PInput{
			WitnessScript: []byte{0xff},
		}},
	})
	require.NoError(t, err)
	require.Equal(t, testDecoratedInput(), packet.Inputs[0])
}
