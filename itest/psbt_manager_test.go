//go:build itest

package itest

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// psbtTestPacket builds an independent unsigned transaction and its packet.
// Nondefault locktime and sequences make unintended template changes visible.
func psbtTestPacket(t *testing.T, inputs ...wire.OutPoint) *psbt.Packet {
	t.Helper()

	tx := wire.NewMsgTx(2)
	tx.LockTime = 123

	for _, input := range inputs {
		txIn := wire.NewTxIn(&input, nil, nil)
		txIn.Sequence = wire.MaxTxInSequenceNum - 2
		tx.AddTxIn(txIn)
	}

	tx.AddTxOut(wire.NewTxOut(1000, []byte{txscript.OP_TRUE}))
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)

	return packet
}

// psbtTestUnknown supplies distinct opaque metadata without signing semantics.
func psbtTestUnknown(tag byte) []*psbt.Unknown {
	return []*psbt.Unknown{{Key: []byte{0xfc, tag}, Value: []byte{tag}}}
}

// psbtTestSnapshot records a serializable packet independently of the wallet's
// private clone implementation, so source mutation cannot hide behind it.
func psbtTestSnapshot(t *testing.T, packet *psbt.Packet) string {
	t.Helper()

	encoded, err := packet.B64Encode()
	require.NoError(t, err)

	return encoded
}

// psbtOutputDerivation reads the public origin of a funded wallet output for
// comparison with the packet transform's metadata.
func psbtOutputDerivation(h *bwtest.HarnessTest, w *wallet.Wallet,
	output *wire.TxOut) *psbt.Bip32Derivation {

	h.Helper()

	_, addrs, _, err := txscript.ExtractPkScriptAddrs(
		output.PkScript, h.NetParams(),
	)
	require.NoError(h, err)
	require.Len(h, addrs, 1)
	derivation, err := w.GetDerivationInfo(h.Context(), addrs[0])
	require.NoError(h, err)

	return derivation
}

// psbtMalformedCase describes an unreadable packet and its public errors when
// submitted alone or after a well-shaped packet of the same transaction.
type psbtMalformedCase struct {
	name     string
	packet   *psbt.Packet
	err      error
	laterErr error
}

// psbtMalformedCases constructs independent malformed values. Calling it twice
// provides a structural oracle even for packets that cannot be serialized.
func psbtMalformedCases(t *testing.T) []psbtMalformedCase {
	t.Helper()

	input := wire.OutPoint{Hash: chainhash.Hash{1}}
	missingInputs := psbtTestPacket(t, input)
	missingInputs.Inputs = nil
	extraInputs := psbtTestPacket(t, input)
	extraInputs.Inputs = append(extraInputs.Inputs, psbt.PInput{})
	missingOutputs := psbtTestPacket(t, input)
	missingOutputs.Outputs = nil
	nilInput := psbtTestPacket(t, input)
	nilInput.UnsignedTx.TxIn[0] = nil
	nilDerivation := psbtTestPacket(t, input)
	nilDerivation.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{nil}

	return []psbtMalformedCase{
		{
			name: "nil packet", err: wallet.ErrPacketNil,
			laterErr: wallet.ErrPacketNil,
		},
		{
			name: "missing transaction", packet: &psbt.Packet{},
			err: wallet.ErrPacketNil, laterErr: wallet.ErrPacketNil,
		},
		{
			name: "missing inputs", packet: missingInputs,
			err:      wallet.ErrPacketMalformed,
			laterErr: wallet.ErrInputCountMismatch,
		},
		{
			name: "extra inputs", packet: extraInputs,
			err:      wallet.ErrPacketMalformed,
			laterErr: wallet.ErrInputCountMismatch,
		},
		{
			name: "missing outputs", packet: missingOutputs,
			err:      wallet.ErrPacketMalformed,
			laterErr: wallet.ErrOutputCountMismatch,
		},
		{
			name: "nil transaction input", packet: nilInput,
			err:      wallet.ErrPacketMalformed,
			laterErr: wallet.ErrPacketMalformed,
		},
		{
			name: "nil derivation", packet: nilDerivation,
			err:      wallet.ErrPacketMalformed,
			laterErr: wallet.ErrPacketMalformed,
		},
	}
}

// testPsbtManagerDecorateOwnedInputs proves that real wallet UTXOs and public
// origins enrich both supported witness families without rewriting the
// caller's transaction or unrelated packet records. The wallet stays locked.
func testPsbtManagerDecorateOwnedInputs(h *bwtest.HarnessTest) {
	w, native := h.NewWallet(bwtest.WalletFixture{
		Seed:     h.SeedFromTestName(),
		AddrType: waddrmgr.WitnessPubKey,
		Amounts:  []btcutil.Amount{100_000},
	})
	taproot := h.FundWalletOfType(w, waddrmgr.TaprootPubKey, 100_000)
	nativeOp, taprootOp := native.WalletOutpoints[0], taproot.WalletOutpoints[0]
	nativeOutput := native.Tx.TxOut[nativeOp.Index]
	taprootOutput := taproot.Tx.TxOut[taprootOp.Index]
	nativeOrigin := psbtOutputDerivation(h, w, nativeOutput)
	taprootOrigin := psbtOutputDerivation(h, w, taprootOutput)
	packet := psbtTestPacket(h.T, nativeOp, taprootOp)
	packet.Unknowns = psbtTestUnknown(1)
	packet.Inputs[0].Unknowns = psbtTestUnknown(2)
	packet.Inputs[1].Unknowns = psbtTestUnknown(3)
	packet.Outputs[0].Unknowns = psbtTestUnknown(4)
	tx := packet.UnsignedTx
	want := psbtTestPacket(h.T, nativeOp, taprootOp)
	want.Unknowns = psbtTestUnknown(1)
	want.Outputs[0].Unknowns = psbtTestUnknown(4)
	want.Inputs[0] = psbt.PInput{
		NonWitnessUtxo: native.Tx,
		WitnessUtxo:    nativeOutput,
		SighashType:    txscript.SigHashAll,
		Bip32Derivation: []*psbt.Bip32Derivation{
			nativeOrigin,
		},
		Unknowns: psbtTestUnknown(2),
	}
	want.Inputs[1] = psbt.PInput{
		WitnessUtxo:        taprootOutput,
		TaprootInternalKey: taprootOrigin.PubKey[1:],
		TaprootBip32Derivation: []*psbt.TaprootBip32Derivation{{
			XOnlyPubKey:          taprootOrigin.PubKey[1:],
			MasterKeyFingerprint: taprootOrigin.MasterKeyFingerprint,
			Bip32Path:            taprootOrigin.Bip32Path,
		}},
		Unknowns: psbtTestUnknown(3),
	}

	result, err := w.DecorateInputs(h.Context(), packet, false)

	require.NoError(h, err)
	require.Same(h, packet, result)
	require.Same(h, tx, packet.UnsignedTx)
	require.Equal(h, want, packet)
}

// testPsbtManagerDecorateSkipUnknown proves that a foreign input and its
// metadata are left alone while a subsequent owned input is still enriched.
func testPsbtManagerDecorateSkipUnknown(h *bwtest.HarnessTest) {
	w, funding := h.NewWallet(bwtest.WalletFixture{
		Seed:     h.SeedFromTestName(),
		AddrType: waddrmgr.WitnessPubKey,
		Amounts:  []btcutil.Amount{100_000},
	})
	require.NotEmpty(h, funding.ForeignOutpoints)
	foreign, owned := funding.ForeignOutpoints[0], funding.WalletOutpoints[0]
	output := funding.Tx.TxOut[owned.Index]
	origin := psbtOutputDerivation(h, w, output)
	packet := psbtTestPacket(h.T, foreign, owned)
	packet.Inputs[0].Unknowns = psbtTestUnknown(1)
	packet.Inputs[0].WitnessUtxo = funding.Tx.TxOut[foreign.Index]
	want := psbtTestPacket(h.T, foreign, owned)
	want.Inputs[0].Unknowns = psbtTestUnknown(1)
	want.Inputs[0].WitnessUtxo = funding.Tx.TxOut[foreign.Index]
	want.Inputs[1] = psbt.PInput{
		NonWitnessUtxo:  funding.Tx,
		WitnessUtxo:     output,
		SighashType:     txscript.SigHashAll,
		Bip32Derivation: []*psbt.Bip32Derivation{origin},
	}

	result, err := w.DecorateInputs(h.Context(), packet, true)

	require.NoError(h, err)
	require.Same(h, packet, result)
	require.Equal(h, want, packet)
}

// testPsbtManagerDecorateRejectUnknown protects decoration's partial in-place
// contract: an ownership error retains earlier enrichment and stops traversal.
func testPsbtManagerDecorateRejectUnknown(h *bwtest.HarnessTest) {
	w, funding := h.NewWallet(bwtest.WalletFixture{
		Seed:     h.SeedFromTestName(),
		AddrType: waddrmgr.WitnessPubKey,
		Amounts:  []btcutil.Amount{100_000, 200_000},
	})
	require.NotEmpty(h, funding.ForeignOutpoints)
	first, last := funding.WalletOutpoints[0], funding.WalletOutpoints[1]
	foreign := funding.ForeignOutpoints[0]
	output := funding.Tx.TxOut[first.Index]
	origin := psbtOutputDerivation(h, w, output)
	packet := psbtTestPacket(h.T, first, foreign, last)
	packet.Inputs[0].Unknowns = psbtTestUnknown(1)
	packet.Inputs[1].Unknowns = psbtTestUnknown(2)
	packet.Inputs[2].Unknowns = psbtTestUnknown(3)
	want := psbtTestPacket(h.T, first, foreign, last)
	want.Inputs[0] = psbt.PInput{
		NonWitnessUtxo:  funding.Tx,
		WitnessUtxo:     output,
		SighashType:     txscript.SigHashAll,
		Bip32Derivation: []*psbt.Bip32Derivation{origin},
		Unknowns:        psbtTestUnknown(1),
	}
	want.Inputs[1].Unknowns = psbtTestUnknown(2)
	want.Inputs[2].Unknowns = psbtTestUnknown(3)

	result, err := w.DecorateInputs(h.Context(), packet, false)

	require.ErrorIs(h, err, wallet.ErrNotMine)
	require.Nil(h, result)
	require.Equal(h, want, packet)
}

// testPsbtManagerDecorateRejectMalformed proves malformed packets are rejected
// before in-place enrichment, regardless of the unknown-input policy.
func testPsbtManagerDecorateRejectMalformed(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{})

	policies := []struct {
		name        string
		skipUnknown bool
	}{
		{name: "require known inputs"},
		{name: "skip unknown inputs", skipUnknown: true},
	}
	for _, policy := range policies {
		cases, before := psbtMalformedCases(h.T), psbtMalformedCases(h.T)
		for i, tc := range cases {
			h.Run(policy.name+"/"+tc.name, func(t *testing.T) {
				result, err := w.DecorateInputs(
					h.Context(), tc.packet, policy.skipUnknown,
				)

				require.ErrorIs(t, err, tc.err)
				require.Nil(t, result)
				require.Equal(t, before[i].packet, tc.packet)
			})
		}
	}
}

// testPsbtManagerCombinePackets proves metadata from independent participants
// is combined for the same transaction, including owned witness inputs and a
// foreign coin. Neither the call nor later result edits may change a source.
func testPsbtManagerCombinePackets(h *bwtest.HarnessTest) {
	w, native := h.NewWallet(bwtest.WalletFixture{
		Seed:     h.SeedFromTestName(),
		AddrType: waddrmgr.WitnessPubKey,
		Amounts:  []btcutil.Amount{100_000},
	})
	taproot := h.FundWalletOfType(w, waddrmgr.TaprootPubKey, 100_000)
	require.NotEmpty(h, native.ForeignOutpoints)
	inputs := []wire.OutPoint{
		native.WalletOutpoints[0], taproot.WalletOutpoints[0],
		native.ForeignOutpoints[0],
	}
	foreign := psbtTestPacket(h.T, inputs...)
	foreign.Inputs[2].WitnessUtxo = native.Tx.TxOut[inputs[2].Index]
	foreign.Unknowns = psbtTestUnknown(1)
	foreign.Inputs[0].Unknowns = psbtTestUnknown(2)
	foreign.Outputs[0].Unknowns = psbtTestUnknown(3)
	owned := psbtTestPacket(h.T, inputs...)
	_, err := w.DecorateInputs(h.Context(), owned, true)
	require.NoError(h, err)

	owned.Unknowns = psbtTestUnknown(4)
	owned.Inputs[0].Unknowns = psbtTestUnknown(5)
	owned.Outputs[0].Unknowns = psbtTestUnknown(6)
	beforeForeign := psbtTestSnapshot(h.T, foreign)
	beforeOwned := psbtTestSnapshot(h.T, owned)
	want := psbtTestPacket(h.T, inputs...)
	want.Inputs[0] = owned.Inputs[0]
	want.Inputs[1] = owned.Inputs[1]
	want.Inputs[2] = foreign.Inputs[2]

	want.Unknowns = append(psbtTestUnknown(1), psbtTestUnknown(4)...)
	want.Inputs[0].Unknowns = append(psbtTestUnknown(2), psbtTestUnknown(5)...)
	want.Outputs[0].Unknowns = append(psbtTestUnknown(3), psbtTestUnknown(6)...)

	result, err := w.CombinePsbt(h.Context(), foreign, owned)

	require.NoError(h, err)
	require.NotSame(h, foreign, result)
	require.NotSame(h, owned, result)
	require.Equal(
		h, psbtTestSnapshot(h.T, want), psbtTestSnapshot(h.T, result),
	)
	require.Equal(h, beforeForeign, psbtTestSnapshot(h.T, foreign))
	require.Equal(h, beforeOwned, psbtTestSnapshot(h.T, owned))

	// Exercise nested ownership as well as top-level packet identity.
	result.UnsignedTx.LockTime++
	result.Inputs[0].WitnessUtxo.PkScript[0] ^= 1
	result.Inputs[1].TaprootInternalKey[0] ^= 1
	result.Unknowns[0].Value[0]++
	result.Inputs[0].Unknowns[1].Value[0]++
	result.Outputs[0].Unknowns[1].Value[0]++

	require.Equal(h, beforeForeign, psbtTestSnapshot(h.T, foreign))
	require.Equal(h, beforeOwned, psbtTestSnapshot(h.T, owned))
}

// testPsbtManagerCombineRejectTransactions proves that combination cannot
// merge metadata across distinct unsigned transaction commitments.
func testPsbtManagerCombineRejectTransactions(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{})
	input := wire.OutPoint{Hash: chainhash.Hash{1}}
	first, second := psbtTestPacket(h.T, input), psbtTestPacket(h.T, input)
	second.UnsignedTx.TxOut[0].Value++
	first.Unknowns = psbtTestUnknown(1)
	second.Unknowns = psbtTestUnknown(2)
	beforeFirst := psbtTestSnapshot(h.T, first)
	beforeSecond := psbtTestSnapshot(h.T, second)

	result, err := w.CombinePsbt(h.Context(), first, second)

	require.ErrorIs(h, err, wallet.ErrDifferentTransactions)
	require.Nil(h, result)
	require.Equal(h, beforeFirst, psbtTestSnapshot(h.T, first))
	require.Equal(h, beforeSecond, psbtTestSnapshot(h.T, second))
}

// testPsbtManagerCombineRejectEmpty protects the no-contributions boundary
// through a real Wallet rather than the private merge validator.
func testPsbtManagerCombineRejectEmpty(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{})

	result, err := w.CombinePsbt(h.Context())

	require.ErrorIs(h, err, wallet.ErrNoPsbtsToCombine)
	require.Nil(h, result)
}

// testPsbtManagerCombineRejectMalformed proves shape checks cover the base and
// later contributions without panicking or changing either source. Existing
// cross-packet count errors remain distinct from a malformed base packet.
func testPsbtManagerCombineRejectMalformed(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{})
	cases, before := psbtMalformedCases(h.T), psbtMalformedCases(h.T)
	input := wire.OutPoint{Hash: chainhash.Hash{1}}

	for i, tc := range cases {
		h.Run(tc.name+" first", func(t *testing.T) {
			result, err := w.CombinePsbt(h.Context(), tc.packet)

			require.ErrorIs(t, err, tc.err)
			require.Nil(t, result)
			require.Equal(t, before[i].packet, tc.packet)
		})

		h.Run(tc.name+" later", func(t *testing.T) {
			first := psbtTestPacket(t, input)
			beforeFirst := psbtTestSnapshot(t, first)

			result, err := w.CombinePsbt(h.Context(), first, tc.packet)

			require.ErrorIs(t, err, tc.laterErr)
			require.Nil(t, result)
			require.Equal(t, before[i].packet, tc.packet)
			require.Equal(t, beforeFirst, psbtTestSnapshot(t, first))
		})
	}
}

// testPsbtManagerCombineRejectConflict proves a merge rejection after partial
// construction cannot publish that work back into either caller packet.
func testPsbtManagerCombineRejectConflict(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{})
	addrs := h.NewWalletAddressesOfType(w, waddrmgr.TaprootPubKey, 2)
	firstOrigin, err := w.GetDerivationInfo(h.Context(), addrs[0])
	require.NoError(h, err)
	secondOrigin, err := w.GetDerivationInfo(h.Context(), addrs[1])
	require.NoError(h, err)

	input := wire.OutPoint{Hash: chainhash.Hash{1}}
	cases := []struct {
		name          string
		first, second psbt.PInput
	}{
		{
			name:   "sighash",
			first:  psbt.PInput{SighashType: txscript.SigHashAll},
			second: psbt.PInput{SighashType: txscript.SigHashNone},
		},
		{
			name: "internal key",
			first: psbt.PInput{
				TaprootInternalKey: firstOrigin.PubKey[1:],
			},
			second: psbt.PInput{
				TaprootInternalKey: secondOrigin.PubKey[1:],
			},
		},
	}

	for _, tc := range cases {
		h.Run(tc.name, func(t *testing.T) {
			first := psbtTestPacket(t, input)
			second := psbtTestPacket(t, input)
			first.Unknowns = psbtTestUnknown(1)
			second.Unknowns = psbtTestUnknown(2)
			first.Inputs[0], second.Inputs[0] = tc.first, tc.second
			beforeFirst := psbtTestSnapshot(t, first)
			beforeSecond := psbtTestSnapshot(t, second)

			result, err := w.CombinePsbt(h.Context(), first, second)

			require.ErrorIs(t, err, wallet.ErrPsbtMergeConflict)
			require.Nil(t, result)
			require.Equal(t, beforeFirst, psbtTestSnapshot(t, first))
			require.Equal(t, beforeSecond, psbtTestSnapshot(t, second))
		})
	}
}
