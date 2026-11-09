//go:build itest

package itest

import (
	"encoding/json"
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

// psbtTestPacket builds an unsigned template for decoration and combination.
// It stays local to these transform cases: a fixed script-only output and
// nondefault locktime and sequences expose changes to caller transaction
// fields. The funding fixture newPaymentPacket instead accepts a caller's
// payment output and uses default transaction fields.
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

// psbtTestUnknown uses BIP174's proprietary key type (0xfc) for opaque tags.
func psbtTestUnknown(tag byte) []*psbt.Unknown {
	return []*psbt.Unknown{{Key: []byte{0xfc, tag}, Value: []byte{tag}}}
}

// psbtTestSnapshot records public packet structure without PSBT serialization,
// which sorts record slices in place. JSON preserves order, nil records, and
// nil versus empty slices, including shapes that cannot encode as a PSBT.
func psbtTestSnapshot(t *testing.T, packets ...*psbt.Packet) string {
	t.Helper()

	encoded, err := json.Marshal(packets)
	require.NoError(t, err)

	return string(encoded)
}

// testPsbtManagerCombinePackets proves metadata from independent participants
// is combined for the same transaction, including owned witness inputs and a
// foreign coin, without changing either source.
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
	wantNative := owned.Inputs[0]

	wantNative.Unknowns = append(psbtTestUnknown(2), psbtTestUnknown(5)...)
	wantOutput := psbt.POutput{
		Unknowns: append(psbtTestUnknown(3), psbtTestUnknown(6)...),
	}
	wantGlobals := append(psbtTestUnknown(1), psbtTestUnknown(4)...)

	result, err := w.CombinePsbt(h.Context(), foreign, owned)

	require.NoError(h, err)
	require.Equal(h, foreign.UnsignedTx, result.UnsignedTx)
	require.Len(h, result.Inputs, len(inputs))
	require.Len(h, result.Outputs, 1)
	require.Equal(h, wantNative, result.Inputs[0])
	require.Equal(h, foreign.Inputs[2], result.Inputs[2])
	require.Equal(h, owned.Inputs[1], result.Inputs[1])
	require.Equal(h, wantGlobals, result.Unknowns)
	require.Equal(h, wantOutput, result.Outputs[0])
	require.Equal(h, beforeForeign, psbtTestSnapshot(h.T, foreign))
	require.Equal(h, beforeOwned, psbtTestSnapshot(h.T, owned))
}

// testPsbtManagerCombineResultOwnership proves the result owns representative
// nested records and byte slices. Pointer assertions observe independence
// without editing either the result or the sources during Assert.
func testPsbtManagerCombineResultOwnership(h *bwtest.HarnessTest) {
	w, funding := h.NewWallet(bwtest.WalletFixture{
		Seed:     h.SeedFromTestName(),
		AddrType: waddrmgr.TaprootPubKey,
		Amounts:  []btcutil.Amount{100_000},
	})
	source := psbtTestPacket(h.T, funding.WalletOutpoints[0])
	_, err := w.DecorateInputs(h.Context(), source, false)
	require.NoError(h, err)

	source.Unknowns = psbtTestUnknown(1)
	source.Inputs[0].Unknowns = psbtTestUnknown(2)
	source.Outputs[0].Unknowns = psbtTestUnknown(3)
	before := psbtTestSnapshot(h.T, source)

	result, err := w.CombinePsbt(h.Context(), source)

	require.NoError(h, err)
	require.NotSame(h, source, result)
	require.NotSame(h, source.UnsignedTx, result.UnsignedTx)
	require.Len(h, result.Inputs, len(source.Inputs))
	require.Len(h, result.Outputs, len(source.Outputs))
	sourceInput, resultInput := &source.Inputs[0], &result.Inputs[0]
	sourceOutput, resultOutput := &source.Outputs[0], &result.Outputs[0]

	require.Equal(h, sourceInput.WitnessUtxo, resultInput.WitnessUtxo)
	require.NotSame(h, sourceInput.WitnessUtxo, resultInput.WitnessUtxo)
	require.NotSame(
		h, &sourceInput.WitnessUtxo.PkScript[0],
		&resultInput.WitnessUtxo.PkScript[0],
	)
	require.Equal(
		h, sourceInput.TaprootInternalKey, resultInput.TaprootInternalKey,
	)
	require.NotSame(
		h, &sourceInput.TaprootInternalKey[0],
		&resultInput.TaprootInternalKey[0],
	)
	require.Equal(h, source.Unknowns, result.Unknowns)
	require.NotSame(h, source.Unknowns[0], result.Unknowns[0])
	require.NotSame(
		h, &source.Unknowns[0].Value[0], &result.Unknowns[0].Value[0],
	)
	require.Equal(h, sourceInput.Unknowns, resultInput.Unknowns)
	require.NotSame(h, sourceInput.Unknowns[0], resultInput.Unknowns[0])
	require.NotSame(
		h, &sourceInput.Unknowns[0].Value[0],
		&resultInput.Unknowns[0].Value[0],
	)
	require.Equal(h, sourceOutput.Unknowns, resultOutput.Unknowns)
	require.NotSame(h, sourceOutput.Unknowns[0], resultOutput.Unknowns[0])
	require.NotSame(
		h, &sourceOutput.Unknowns[0].Value[0],
		&resultOutput.Unknowns[0].Value[0],
	)
	require.Equal(h, before, psbtTestSnapshot(h.T, source))
}

// testPsbtManagerCombineRejectTransactions proves that combination cannot
// merge metadata across distinct unsigned transaction commitments.
func testPsbtManagerCombineRejectTransactions(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{})
	input := wire.OutPoint{Hash: chainhash.Hash{1}}
	first, second := psbtTestPacket(h.T, input), psbtTestPacket(h.T, input)
	second.UnsignedTx.TxOut[0].Value++
	// Distinct unknown fields make source merges visible in the snapshots.
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

// testPsbtManagerCombineRejectNil rejects a missing packet or transaction both
// as the only contribution and after a valid one. Each subtest owns its
// argument list and mutation baseline.
func testPsbtManagerCombineRejectNil(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{})
	input := wire.OutPoint{Hash: chainhash.Hash{1}}

	for position, name := range []string{"only", "later"} {
		cases := []struct {
			name   string
			packet *psbt.Packet
		}{
			{name: "nil packet"},
			{name: "missing transaction", packet: &psbt.Packet{}},
		}
		for _, tc := range cases {
			h.Run(name+"/"+tc.name, func(t *testing.T) {
				packets := make([]*psbt.Packet, 0, position+1)
				for range position {
					packets = append(packets, psbtTestPacket(t, input))
				}

				packets = append(packets, tc.packet)
				before := psbtTestSnapshot(t, packets...)

				result, err := w.CombinePsbt(h.Context(), packets...)

				require.ErrorIs(t, err, wallet.ErrPacketNil)
				require.Nil(t, result)
				require.Equal(t, before, psbtTestSnapshot(t, packets...))
			})
		}
	}
}

// testPsbtManagerCombineRejectMalformed rejects unreadable contributions
// without changing any argument. The only-contribution rows cover individual
// packet shape validation; later-contribution rows also cover cross-packet
// compatibility, whose count-mismatch errors take precedence over shape errors.
func testPsbtManagerCombineRejectMalformed(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{})
	input := wire.OutPoint{Hash: chainhash.Hash{1}}

	for position, name := range []string{"only", "later"} {
		cases := []struct {
			name       string
			txInputs   []*wire.TxIn
			inputs     []psbt.PInput
			outputs    []psbt.POutput
			wantErrors [2]error
		}{
			{
				name:     "missing inputs",
				txInputs: psbtTestPacket(h.T, input).UnsignedTx.TxIn,
				outputs:  []psbt.POutput{{}},
				wantErrors: [2]error{
					wallet.ErrPacketMalformed,
					wallet.ErrInputCountMismatch,
				},
			},
			{
				name:     "extra inputs",
				txInputs: psbtTestPacket(h.T, input).UnsignedTx.TxIn,
				inputs:   []psbt.PInput{{}, {}},
				outputs:  []psbt.POutput{{}},
				wantErrors: [2]error{
					wallet.ErrPacketMalformed,
					wallet.ErrInputCountMismatch,
				},
			},
			{
				name:     "missing outputs",
				txInputs: psbtTestPacket(h.T, input).UnsignedTx.TxIn,
				inputs:   []psbt.PInput{{}},
				wantErrors: [2]error{
					wallet.ErrPacketMalformed,
					wallet.ErrOutputCountMismatch,
				},
			},
			{
				name:     "nil transaction input",
				txInputs: []*wire.TxIn{nil},
				inputs:   []psbt.PInput{{}},
				outputs:  []psbt.POutput{{}},
				wantErrors: [2]error{
					wallet.ErrPacketMalformed,
					wallet.ErrPacketMalformed,
				},
			},
			{
				name:     "nil derivation",
				txInputs: psbtTestPacket(h.T, input).UnsignedTx.TxIn,
				inputs: []psbt.PInput{{
					Bip32Derivation: []*psbt.Bip32Derivation{nil},
				}},
				outputs: []psbt.POutput{{}},
				wantErrors: [2]error{
					wallet.ErrPacketMalformed,
					wallet.ErrPacketMalformed,
				},
			},
		}
		for _, tc := range cases {
			h.Run(name+"/"+tc.name, func(t *testing.T) {
				packet := psbtTestPacket(t, input)
				packet.UnsignedTx.TxIn = tc.txInputs
				packet.Inputs, packet.Outputs = tc.inputs, tc.outputs

				packets := make([]*psbt.Packet, 0, position+1)
				for range position {
					packets = append(packets, psbtTestPacket(t, input))
				}

				packets = append(packets, packet)
				before := psbtTestSnapshot(t, packets...)

				result, err := w.CombinePsbt(h.Context(), packets...)

				require.ErrorIs(t, err, tc.wantErrors[position])
				require.Nil(t, result)
				require.Equal(t, before, psbtTestSnapshot(t, packets...))
			})
		}
	}
}

// testPsbtManagerCombineRejectSighash proves disagreeing sighash fields reject
// the merge after partial construction without publishing it to either source.
func testPsbtManagerCombineRejectSighash(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{})
	input := wire.OutPoint{Hash: chainhash.Hash{1}}
	first, second := psbtTestPacket(h.T, input), psbtTestPacket(h.T, input)
	// Distinct unknown fields make source merges visible in the snapshots.
	first.Unknowns = psbtTestUnknown(1)
	second.Unknowns = psbtTestUnknown(2)
	first.Inputs[0].SighashType = txscript.SigHashAll
	second.Inputs[0].SighashType = txscript.SigHashNone
	before := psbtTestSnapshot(h.T, first, second)

	result, err := w.CombinePsbt(h.Context(), first, second)

	require.ErrorIs(h, err, wallet.ErrPsbtMergeConflict)
	require.Nil(h, result)
	require.Equal(h, before, psbtTestSnapshot(h.T, first, second))
}

// testPsbtManagerCombineRejectInternalKey proves conflicting internal keys fail
// with no source mutation. Wallet keys keep both records valid, so only the
// conflict differs.
func testPsbtManagerCombineRejectInternalKey(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{})
	addrs := h.NewWalletAddressesOfType(w, waddrmgr.TaprootPubKey, 2)
	firstOrigin, err := w.GetDerivationInfo(h.Context(), addrs[0])
	require.NoError(h, err)
	secondOrigin, err := w.GetDerivationInfo(h.Context(), addrs[1])
	require.NoError(h, err)

	input := wire.OutPoint{Hash: chainhash.Hash{1}}
	first, second := psbtTestPacket(h.T, input), psbtTestPacket(h.T, input)
	// Distinct unknown fields make source merges visible in the snapshots.
	first.Unknowns = psbtTestUnknown(1)
	second.Unknowns = psbtTestUnknown(2)
	first.Inputs[0].TaprootInternalKey = firstOrigin.PubKey[1:]
	second.Inputs[0].TaprootInternalKey = secondOrigin.PubKey[1:]
	before := psbtTestSnapshot(h.T, first, second)

	result, err := w.CombinePsbt(h.Context(), first, second)

	require.ErrorIs(h, err, wallet.ErrPsbtMergeConflict)
	require.Nil(h, result)
	require.Equal(h, before, psbtTestSnapshot(h.T, first, second))
}
