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

// TestClonePacketIsIndependent verifies that a clone shares no memory with the
// packet it came from, so that transforming the clone cannot reach back into a
// caller's own packet.
func TestClonePacketIsIndependent(t *testing.T) {
	t.Parallel()

	packet := testPacket(t)

	// Fill in every field a caller can set, so the clone is exercised
	// across the whole record rather than the handful of fields the
	// funding path happens to touch.
	packet.XPubs = []psbt.XPub{{
		ExtendedKey:          bytes.Repeat([]byte{0x04}, 78),
		MasterKeyFingerprint: 0xdeadbeef,
		Bip32Path:            []uint32{1, 2, 3},
	}}
	packet.Inputs[0].RedeemScript = []byte{0x51, 0x52}
	packet.Inputs[0].WitnessScript = []byte{0x53, 0x54}
	packet.Inputs[0].PartialSigs = []*psbt.PartialSig{{
		PubKey:    bytes.Repeat([]byte{0x02}, 33),
		Signature: bytes.Repeat([]byte{0x01}, 71),
	}}
	packet.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{{
		PubKey:               bytes.Repeat([]byte{0x02}, 33),
		MasterKeyFingerprint: 7,
		Bip32Path:            []uint32{4, 5, 6},
	}}
	packet.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: bytes.Repeat([]byte{0xc0}, 33),
		Script:       []byte{0x51},
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	packet.Inputs[0].TaprootMerkleRoot = bytes.Repeat([]byte{0x09}, 32)
	packet.Outputs[0].RedeemScript = []byte{0x55}
	packet.Outputs[0].TaprootTapTree = []byte{0x56}
	packet.Outputs[1].Bip32Derivation = []*psbt.Bip32Derivation{{
		PubKey:    bytes.Repeat([]byte{0x03}, 33),
		Bip32Path: []uint32{7, 8, 9},
	}}
	packet.Outputs[1].TaprootBip32Derivation =
		[]*psbt.TaprootBip32Derivation{{
			XOnlyPubKey: bytes.Repeat([]byte{0x03}, 32),
			LeafHashes: [][]byte{
				bytes.Repeat([]byte{0x0a}, 32),
			},
			Bip32Path: []uint32{10},
		}}

	clone := clonePacket(packet)
	require.Equal(t, packet, clone)

	// A snapshot to compare the original against once the clone has been
	// scribbled over.
	before := clonePacket(packet)

	clone.UnsignedTx.Version = 99
	clone.UnsignedTx.LockTime = 42
	clone.UnsignedTx.TxIn[0].Sequence = 0
	clone.UnsignedTx.TxIn[0].PreviousOutPoint.Index = 99
	clone.UnsignedTx.TxOut[0].Value = 1
	clone.UnsignedTx.TxOut[0].PkScript[0] = 0xff
	clone.Inputs[0].SighashType = txscript.SigHashNone
	clone.Inputs[0].RedeemScript[0] = 0xff
	clone.Inputs[0].WitnessScript[0] = 0xff
	clone.Inputs[0].NonWitnessUtxo.TxOut[0].Value = 1
	clone.Inputs[0].WitnessUtxo.PkScript[0] = 0xff
	clone.Inputs[0].PartialSigs[0].Signature[0] = 0xff
	clone.Inputs[0].Bip32Derivation[0].Bip32Path[0] = 99
	clone.Inputs[0].TaprootLeafScript[0].Script[0] = 0xff
	clone.Inputs[0].TaprootMerkleRoot[0] = 0xff
	clone.Outputs[0].RedeemScript[0] = 0xff
	clone.Outputs[0].TaprootTapTree[0] = 0xff
	clone.Outputs[1].Bip32Derivation[0].PubKey[0] = 0xff
	clone.Outputs[1].TaprootBip32Derivation[0].LeafHashes[0][0] = 0xff
	clone.XPubs[0].ExtendedKey[0] = 0xff
	clone.XPubs[0].Bip32Path[0] = 99

	require.Equal(t, before, packet)
	require.NotEqual(t, packet, clone)
}

// TestClonePacketNil verifies that a nil packet clones to nil, leaving it to
// validation rather than cloning to decide what a missing packet means.
func TestClonePacketNil(t *testing.T) {
	t.Parallel()

	require.Nil(t, clonePacket(nil))
}

// TestClonePacketRoundTrip verifies that a clone serializes to the same bytes
// as the packet it came from, which is the property callers depend on when
// they compare a returned packet against the one they handed in.
func TestClonePacketRoundTrip(t *testing.T) {
	t.Parallel()

	packet := testPacket(t)

	var original, cloned bytes.Buffer
	require.NoError(t, packet.Serialize(&original))
	require.NoError(t, clonePacket(packet).Serialize(&cloned))

	require.Equal(t, original.Bytes(), cloned.Bytes())
}

// TestClonePacketPreservesAbsentFields verifies that a clone compares equal to
// what it was copied from even where one of the packet's record lists is
// absent rather than empty.
//
// Callers compare a packet they got back against the one they handed over, so
// a clone that turned an absent list into an empty one would report a change
// that never happened.
func TestClonePacketPreservesAbsentFields(t *testing.T) {
	t.Parallel()

	// A packet whose record lists are absent entirely, as one that failed
	// the length checks would be.
	packet := &psbt.Packet{UnsignedTx: wire.NewMsgTx(2)}
	require.Equal(t, packet, clonePacket(packet))

	// And one where a list is present but empty, which must stay empty
	// rather than becoming absent.
	packet = testPacket(t)
	packet.Inputs[0].PartialSigs = []*psbt.PartialSig{}
	packet.Outputs[0].Bip32Derivation = []*psbt.Bip32Derivation{}
	require.Equal(t, packet, clonePacket(packet))
}
