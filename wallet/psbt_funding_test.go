// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/txauthor"
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

// TestRestoreOutputMetadata verifies that each caller output's metadata lands
// with the output it describes, wherever authoring moved that output to, and
// that the change output starts with none of its own.
func TestRestoreOutputMetadata(t *testing.T) {
	t.Parallel()

	// Three caller outputs, each recognisable by its redeem script alone,
	// so a misplaced record is visible rather than merely wrong.
	callerOutputs := []psbt.POutput{
		{RedeemScript: []byte{0xa0}},
		{RedeemScript: []byte{0xa1}},
		{RedeemScript: []byte{0xa2}},
	}

	tests := []struct {
		name   string
		origin []int
		want   [][]byte
	}{{
		name:   "caller order preserved",
		origin: []int{0, 1, 2},
		want:   [][]byte{{0xa0}, {0xa1}, {0xa2}},
	}, {
		name:   "change appended last",
		origin: []int{0, 1, 2, txauthor.ChangeOutputOrigin},
		want:   [][]byte{{0xa0}, {0xa1}, {0xa2}, nil},
	}, {
		// The shape RandomizeChangePosition produces: change swapped
		// into an interior position, and the output that stood there
		// moved to the end.
		name:   "change randomized into the middle",
		origin: []int{0, txauthor.ChangeOutputOrigin, 2, 1},
		want:   [][]byte{{0xa0}, nil, {0xa2}, {0xa1}},
	}, {
		name:   "change randomized to the front",
		origin: []int{txauthor.ChangeOutputOrigin, 1, 2, 0},
		want:   [][]byte{nil, {0xa1}, {0xa2}, {0xa0}},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			outputs, err := restoreOutputMetadata(
				callerOutputs, tc.origin,
			)
			require.NoError(t, err)
			require.Len(t, outputs, len(tc.origin))

			for i, want := range tc.want {
				require.Equal(
					t, want, outputs[i].RedeemScript,
					"output %d", i,
				)
			}
		})
	}
}

// TestRestoreOutputMetadataDuplicateOutputs verifies that two outputs paying
// the same amount to the same script keep their own metadata. This is the case
// value-and-script matching cannot get right, and the reason provenance is
// carried explicitly.
func TestRestoreOutputMetadataDuplicateOutputs(t *testing.T) {
	t.Parallel()

	// Identical outputs as far as the transaction is concerned, told apart
	// only by the metadata the caller attached to each.
	callerOutputs := []psbt.POutput{
		{RedeemScript: []byte{0xa0}},
		{RedeemScript: []byte{0xa1}},
	}

	outputs, err := restoreOutputMetadata(
		callerOutputs, []int{1, txauthor.ChangeOutputOrigin, 0},
	)
	require.NoError(t, err)

	require.Equal(t, []byte{0xa1}, outputs[0].RedeemScript)
	require.Nil(t, outputs[1].RedeemScript)
	require.Equal(t, []byte{0xa0}, outputs[2].RedeemScript)
}

// TestRestoreOutputMetadataRejectsBadOrigin verifies that provenance naming an
// output the caller never supplied is refused rather than read out of bounds.
func TestRestoreOutputMetadataRejectsBadOrigin(t *testing.T) {
	t.Parallel()

	callerOutputs := []psbt.POutput{{RedeemScript: []byte{0xa0}}}

	tests := []struct {
		name   string
		origin []int
	}{{
		name:   "an origin past the caller's outputs",
		origin: []int{0, 1},
	}, {
		name:   "an origin below the change marker",
		origin: []int{0, -2},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := restoreOutputMetadata(
				callerOutputs, tc.origin,
			)
			require.ErrorIs(t, err, ErrPacketMalformed)
		})
	}
}

// randomPacket builds a packet with a random set of inputs and outputs, some
// of them deliberately identical, for the sort to be exercised against.
func randomPacket(t *testing.T, rng *rand.Rand) (*psbt.Packet, []int) {
	t.Helper()

	numInputs := rng.Intn(6) + 1
	numOutputs := rng.Intn(6) + 1

	tx := &wire.MsgTx{}
	inputs := make([]psbt.PInput, 0, numInputs)
	for i := 0; i < numInputs; i++ {
		var hash chainhash.Hash

		// A small alphabet of hashes, so that duplicate transaction
		// IDs and index-only ordering come up rather than being drowned
		// out by random ones.
		hash[0] = byte(rng.Intn(3))
		hash[31] = byte(rng.Intn(3))

		tx.TxIn = append(tx.TxIn, &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  hash,
				Index: uint32(rng.Intn(3)),
			},
		})
		inputs = append(inputs, psbt.PInput{
			WitnessScript: []byte{byte(i)},
		})
	}

	outputs := make([]psbt.POutput, 0, numOutputs)
	origin := make([]int, 0, numOutputs)
	for i := 0; i < numOutputs; i++ {
		tx.TxOut = append(tx.TxOut, &wire.TxOut{
			Value: int64(rng.Intn(3) * 1000),
			PkScript: bytes.Repeat(
				[]byte{byte(rng.Intn(3))}, 22,
			),
		})
		outputs = append(outputs, psbt.POutput{
			RedeemScript: []byte{byte(i)},
		})
		origin = append(origin, i)
	}

	return &psbt.Packet{
		UnsignedTx: tx,
		Inputs:     inputs,
		Outputs:    outputs,
	}, origin
}

// TestSortPacketMatchesLibrarySort verifies that the wallet's own sort puts a
// packet in the same BIP69 order the psbt library does.
//
// The wallet sorts through a permutation of its own so that it can carry
// provenance along, which is a reimplementation of an ordering someone else
// already defines. This test is what keeps the two from drifting apart.
func TestSortPacketMatchesLibrarySort(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewSource(1))

	for i := 0; i < 200; i++ {
		packet, origin := randomPacket(t, rng)
		reference := clonePacket(packet)

		_, err := sortPacket(packet, origin)
		require.NoError(t, err)

		require.NoError(t, psbt.InPlaceSort(reference))

		require.Equal(
			t, reference.UnsignedTx.TxIn, packet.UnsignedTx.TxIn,
		)
		require.Equal(
			t, reference.UnsignedTx.TxOut, packet.UnsignedTx.TxOut,
		)
	}
}

// TestSortPacketCarriesRecords verifies that the per-input and per-output
// records move with the inputs and outputs they describe, rather than being
// left behind at their old positions.
func TestSortPacketCarriesRecords(t *testing.T) {
	t.Parallel()

	rng := rand.New(rand.NewSource(2))

	for i := 0; i < 200; i++ {
		packet, origin := randomPacket(t, rng)

		// Each record names the position it started at, so a record
		// that failed to move with its input or output is visible.
		inputFor := make(map[byte]wire.OutPoint)
		for i, txIn := range packet.UnsignedTx.TxIn {
			inputFor[packet.Inputs[i].WitnessScript[0]] =
				txIn.PreviousOutPoint
		}

		outputFor := make(map[byte]*wire.TxOut)
		for i, txOut := range packet.UnsignedTx.TxOut {
			outputFor[packet.Outputs[i].RedeemScript[0]] = txOut
		}

		_, err := sortPacket(packet, origin)
		require.NoError(t, err)

		for i, txIn := range packet.UnsignedTx.TxIn {
			tag := packet.Inputs[i].WitnessScript[0]
			require.Equal(
				t, inputFor[tag], txIn.PreviousOutPoint,
			)
		}

		for i, txOut := range packet.UnsignedTx.TxOut {
			tag := packet.Outputs[i].RedeemScript[0]
			require.Equal(t, outputFor[tag], txOut)
		}
	}
}

// TestSortPacketFindsChange verifies that the change output is located after
// sorting even when another output pays exactly the same amount to exactly the
// same script.
//
// This is the case that value-and-script matching gets wrong, and it is not a
// contrived one: a caller paying itself the same amount it receives as change
// produces it.
func TestSortPacketFindsChange(t *testing.T) {
	t.Parallel()

	script := bytes.Repeat([]byte{0x51}, 22)

	// Three outputs of the same value and script, of which the second is
	// the change. Nothing about the outputs themselves tells them apart.
	packet := &psbt.Packet{
		UnsignedTx: &wire.MsgTx{
			TxOut: []*wire.TxOut{
				{Value: 1000, PkScript: script},
				{Value: 1000, PkScript: script},
				{Value: 1000, PkScript: script},
			},
		},
		Outputs: []psbt.POutput{
			{RedeemScript: []byte{0xa0}},
			{RedeemScript: []byte{0xa1}},
			{RedeemScript: []byte{0xa2}},
		},
	}

	origin := []int{0, txauthor.ChangeOutputOrigin, 1}

	changeIndex, err := sortPacket(packet, origin)
	require.NoError(t, err)

	// The sort is stable, so the identical outputs keep their order and
	// the change output is still the second one, carrying its own record.
	require.Equal(t, int32(1), changeIndex)
	require.Equal(
		t, []byte{0xa1}, packet.Outputs[changeIndex].RedeemScript,
	)
}

// TestSortPacketWithoutChange verifies that a packet with no change output
// reports no change index rather than pointing at an arbitrary output.
func TestSortPacketWithoutChange(t *testing.T) {
	t.Parallel()

	packet, origin := randomPacket(t, rand.New(rand.NewSource(3)))

	changeIndex, err := sortPacket(packet, origin)
	require.NoError(t, err)
	require.Equal(t, int32(-1), changeIndex)
}

// TestSortPacketRejectsMismatchedRecords verifies that a packet whose records
// do not line up with its transaction is refused rather than sorted into an
// arrangement where they line up by accident.
func TestSortPacketRejectsMismatchedRecords(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*psbt.Packet, *[]int)
	}{{
		name: "too few input records",
		mutate: func(p *psbt.Packet, _ *[]int) {
			p.Inputs = nil
		},
	}, {
		name: "too few output records",
		mutate: func(p *psbt.Packet, _ *[]int) {
			p.Outputs = nil
		},
	}, {
		name: "provenance short of the outputs",
		mutate: func(_ *psbt.Packet, origin *[]int) {
			*origin = nil
		},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			packet, origin := randomPacket(
				t, rand.New(rand.NewSource(4)),
			)
			tc.mutate(packet, &origin)

			_, err := sortPacket(packet, origin)
			require.ErrorIs(t, err, ErrPacketMalformed)
		})
	}
}
