//go:build itest

package itest

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// psbtTestPacket builds an unsigned template for the PsbtManager cases. It
// stays local to them: a fixed script-only output and nondefault locktime and
// sequences expose changes to caller transaction fields. The funding fixture
// newPaymentPacket instead accepts a caller's payment output and uses default
// transaction fields.
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

// psbtFundedCoinDerivation reads the wallet origin of a funded coin being
// spent, for comparison with the decorated input's metadata.
func psbtFundedCoinDerivation(h *bwtest.HarnessTest, w *wallet.Wallet,
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
	nativeOrigin := psbtFundedCoinDerivation(h, w, nativeOutput)
	taprootOrigin := psbtFundedCoinDerivation(h, w, taprootOutput)
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
	origin := psbtFundedCoinDerivation(h, w, output)
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
	// last is owned; its bare record proves we stopped at the foreign input.
	first, last := funding.WalletOutpoints[0], funding.WalletOutpoints[1]
	foreign := funding.ForeignOutpoints[0]
	output := funding.Tx.TxOut[first.Index]
	origin := psbtFundedCoinDerivation(h, w, output)
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

// testPsbtManagerDecorateRejectNil proves a missing packet or unsigned
// transaction is rejected before ownership handling.
func testPsbtManagerDecorateRejectNil(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{})

	cases := []struct {
		name   string
		packet *psbt.Packet
	}{
		{name: "nil packet"},
		{name: "missing transaction", packet: &psbt.Packet{}},
	}
	for _, tc := range cases {
		h.Run(tc.name, func(t *testing.T) {
			before := psbtTestSnapshot(t, tc.packet)

			result, err := w.DecorateInputs(
				h.Context(), tc.packet, false,
			)

			require.ErrorIs(t, err, wallet.ErrPacketNil)
			require.Nil(t, result)
			require.Equal(t, before, psbtTestSnapshot(t, tc.packet))
		})
	}
}

// testPsbtManagerDecorateRejectMalformed proves unreadable packet structure is
// rejected before enrichment or ownership handling. Each row owns its records
// and takes its baseline inside the subtest.
func testPsbtManagerDecorateRejectMalformed(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{})
	input := wire.OutPoint{Hash: chainhash.Hash{1}}

	cases := []struct {
		name     string
		txInputs []*wire.TxIn
		inputs   []psbt.PInput
		outputs  []psbt.POutput
	}{
		{
			name:     "missing inputs",
			txInputs: psbtTestPacket(h.T, input).UnsignedTx.TxIn,
			outputs:  []psbt.POutput{{}},
		},
		{
			name:     "extra inputs",
			txInputs: psbtTestPacket(h.T, input).UnsignedTx.TxIn,
			inputs:   []psbt.PInput{{}, {}},
			outputs:  []psbt.POutput{{}},
		},
		{
			name:     "missing outputs",
			txInputs: psbtTestPacket(h.T, input).UnsignedTx.TxIn,
			inputs:   []psbt.PInput{{}},
		},
		{
			name:     "nil transaction input",
			txInputs: []*wire.TxIn{nil},
			inputs:   []psbt.PInput{{}},
			outputs:  []psbt.POutput{{}},
		},
	}
	for _, tc := range cases {
		h.Run(tc.name, func(t *testing.T) {
			packet := psbtTestPacket(t, input)
			packet.UnsignedTx.TxIn = tc.txInputs
			packet.Inputs, packet.Outputs = tc.inputs, tc.outputs
			before := psbtTestSnapshot(t, packet)

			result, err := w.DecorateInputs(
				h.Context(), packet, false,
			)

			require.ErrorIs(t, err, wallet.ErrPacketMalformed)
			require.Nil(t, result)
			require.Equal(t, before, psbtTestSnapshot(t, packet))
		})
	}
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

// newDecoratedPsbt builds a packet spending the outpoints, with the Wallet's
// own records on the inputs it owns and nothing on the others.
func newDecoratedPsbt(h *bwtest.HarnessTest, w *wallet.Wallet,
	inputs ...wire.OutPoint) *psbt.Packet {

	h.Helper()

	packet, err := w.DecorateInputs(
		h.Context(), psbtTestPacket(h.T, inputs...), true,
	)
	require.NoError(h, err)

	return packet
}

// psbtExternalKey returns the key of another signer, which no Wallet holds.
func psbtExternalKey() *btcec.PrivateKey {
	key, _ := btcec.PrivKeyFromBytes(
		chainhash.HashB([]byte("psbt external signer")),
	)

	return key
}

// addExternalPsbtInput gives an input the other signer's P2WPKH previous output
// and returns the script code that signer commits to.
func addExternalPsbtInput(h *bwtest.HarnessTest, input *psbt.PInput) []byte {
	h.Helper()

	hash := address.Hash160(psbtExternalKey().PubKey().SerializeCompressed())
	witnessAddr, err := address.NewAddressWitnessPubKeyHash(hash, h.NetParams())
	require.NoError(h, err)

	pkScript, err := txscript.PayToAddrScript(witnessAddr)
	require.NoError(h, err)

	keyAddr, err := address.NewAddressPubKeyHash(hash, h.NetParams())
	require.NoError(h, err)

	scriptCode, err := txscript.PayToAddrScript(keyAddr)
	require.NoError(h, err)

	input.WitnessUtxo = wire.NewTxOut(int64(oneBTC), pkScript)
	input.SighashType = txscript.SigHashAll

	return scriptCode
}

// addExternalPsbtSig adds the other signer's partial signature to an input.
// The signature is computed here, without any Wallet code.
func addExternalPsbtSig(h *bwtest.HarnessTest, packet *psbt.Packet, idx int,
	scriptCode []byte) {

	h.Helper()

	prevOut := packet.Inputs[idx].WitnessUtxo
	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)

	key := psbtExternalKey()
	sig, err := txscript.RawTxInWitnessSignature(
		packet.UnsignedTx, txscript.NewTxSigHashes(packet.UnsignedTx, fetcher),
		idx, prevOut.Value, scriptCode,
		txscript.SigHashAll, key,
	)
	require.NoError(h, err)

	packet.Inputs[idx].PartialSigs = append(
		packet.Inputs[idx].PartialSigs, &psbt.PartialSig{
			PubKey:    key.PubKey().SerializeCompressed(),
			Signature: sig,
		},
	)
}

// newMultisigPsbt builds a packet spending a 2-of-2 P2WSH output shared by the
// Wallet and the other signer, and returns the witness script. Only the
// Wallet's key has a derivation record.
func newMultisigPsbt(h *bwtest.HarnessTest, w *wallet.Wallet) (*psbt.Packet,
	[]byte) {

	h.Helper()

	addr := h.NewWalletAddressOfType(w, waddrmgr.WitnessPubKey)
	origin, err := w.GetDerivationInfo(h.Context(), addr)
	require.NoError(h, err)

	script, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_2).
		AddData(origin.PubKey).
		AddData(psbtExternalKey().PubKey().SerializeCompressed()).
		AddOp(txscript.OP_2).
		AddOp(txscript.OP_CHECKMULTISIG).
		Script()
	require.NoError(h, err)

	witnessHash := sha256.Sum256(script)
	witnessAddr, err := address.NewAddressWitnessScriptHash(
		witnessHash[:], h.NetParams(),
	)
	require.NoError(h, err)

	pkScript, err := txscript.PayToAddrScript(witnessAddr)
	require.NoError(h, err)

	packet := psbtTestPacket(h.T, unknownOutpoint())
	packet.Inputs[0].WitnessUtxo = wire.NewTxOut(int64(oneBTC), pkScript)
	packet.Inputs[0].WitnessScript = script
	packet.Inputs[0].SighashType = txscript.SigHashAll
	packet.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{origin}

	return packet, script
}

// newTapscriptPsbt builds a packet spending a one-leaf Taproot output through
// its CHECKSIG leaf, which commits to a Wallet key. The internal key is the
// other signer's, so the leaf is the only path the Wallet's key can spend.
func newTapscriptPsbt(h *bwtest.HarnessTest, w *wallet.Wallet) *psbt.Packet {
	h.Helper()

	addr := h.NewWalletAddressOfType(w, waddrmgr.TaprootPubKey)
	origin, err := w.GetDerivationInfo(h.Context(), addr)
	require.NoError(h, err)

	walletKey, err := btcec.ParsePubKey(origin.PubKey)
	require.NoError(h, err)

	internalKey := psbtExternalKey().PubKey()
	xOnlyKey := schnorr.SerializePubKey(walletKey)
	script, err := txscript.NewScriptBuilder().
		AddData(xOnlyKey).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(h, err)

	leaf := txscript.NewBaseTapLeaf(script)
	leafHash := leaf.TapHash()
	tree := txscript.AssembleTaprootScriptTree(leaf)
	root := tree.RootNode.TapHash()
	outputKey := txscript.ComputeTaprootOutputKey(internalKey, root[:])

	pkScript, err := txscript.PayToTaprootScript(outputKey)
	require.NoError(h, err)

	control := tree.LeafMerkleProofs[0].ToControlBlock(internalKey)
	controlBytes, err := control.ToBytes()
	require.NoError(h, err)

	packet := psbtTestPacket(h.T, unknownOutpoint())
	packet.Inputs[0].WitnessUtxo = wire.NewTxOut(int64(oneBTC), pkScript)
	packet.Inputs[0].TaprootInternalKey = schnorr.SerializePubKey(internalKey)
	packet.Inputs[0].TaprootMerkleRoot = root[:]
	packet.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		ControlBlock: controlBytes,
		Script:       script,
		LeafVersion:  txscript.BaseLeafVersion,
	}}
	packet.Inputs[0].TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{{
		XOnlyPubKey:          xOnlyKey,
		LeafHashes:           [][]byte{leafHash[:]},
		MasterKeyFingerprint: origin.MasterKeyFingerprint,
		Bip32Path:            origin.Bip32Path,
	}}

	return packet
}

// testPsbtManagerSignOwnedInputs verifies that the Wallet signs every input it
// owns, without finalizing, and that the signatures alone satisfy the scripts.
func testPsbtManagerSignOwnedInputs(h *bwtest.HarnessTest) {
	// Arrange: Own one coin of each spend type in a single packet.
	w, legacy := h.NewWallet(bwtest.WalletFixture{
		AddrType: waddrmgr.PubKeyHash,
		Amounts:  []btcutil.Amount{oneBTC},
		Unlocked: true,
	})
	nested := h.FundWalletOfType(w, waddrmgr.NestedWitnessPubKey, oneBTC)
	segwit := h.FundWalletOfType(w, waddrmgr.WitnessPubKey, oneBTC)
	taproot := h.FundWalletOfType(w, waddrmgr.TaprootPubKey, oneBTC)
	packet := newDecoratedPsbt(
		h, w, legacy.WalletOutpoints[0], nested.WalletOutpoints[0],
		segwit.WalletOutpoints[0], taproot.WalletOutpoints[0],
	)
	original := psbtTestSnapshot(h.T, packet)

	// Act: Sign without finalizing.
	result, err := w.SignPsbt(
		h.Context(), &wallet.SignPsbtParams{Packet: packet},
	)

	// Assert: Without the signature each spend type expects, the packet is
	// the caller's, so no input is final and the transaction and previous
	// outputs are unchanged. The library finalizer and script engine then
	// check the signatures without Wallet code.
	require.NoError(h, err)
	require.Equal(h, []uint32{0, 1, 2, 3}, result.SignedInputs)
	require.Same(h, packet, result.Packet)

	unsigned := *packet
	unsigned.Inputs = slices.Clone(packet.Inputs)
	unsigned.Inputs[0].PartialSigs = nil
	unsigned.Inputs[1].PartialSigs = nil
	unsigned.Inputs[2].PartialSigs = nil
	unsigned.Inputs[3].TaprootKeySpendSig = nil
	require.Equal(h, original, psbtTestSnapshot(h.T, &unsigned))

	// The library finalizer is the oracle, not the subject. It treats any
	// input with a witness UTXO as SegWit, and decoration records one on
	// the legacy input too, so the oracle needs it cleared.
	packet.Inputs[0].WitnessUtxo = nil

	require.NoError(h, psbt.MaybeFinalizeAll(packet))
	h.AssertPsbtExecutes(packet)
}

// testPsbtManagerSignAlreadySigned verifies that signing a signed packet again
// adds nothing and reports no input as signed.
func testPsbtManagerSignAlreadySigned(h *bwtest.HarnessTest) {
	// Arrange: Hold the Wallet's records on a SegWit and a Taproot input.
	ctx := h.Context()
	w, segwit := h.NewWallet(bwtest.WalletFixture{
		AddrType: waddrmgr.WitnessPubKey,
		Amounts:  []btcutil.Amount{oneBTC},
		Unlocked: true,
	})
	taproot := h.FundWalletOfType(w, waddrmgr.TaprootPubKey, oneBTC)
	packet := newDecoratedPsbt(
		h, w, segwit.WalletOutpoints[0], taproot.WalletOutpoints[0],
	)

	first, err := w.SignPsbt(ctx, &wallet.SignPsbtParams{Packet: packet})
	require.NoError(h, err)
	require.Equal(h, []uint32{0, 1}, first.SignedInputs)

	original := psbtTestSnapshot(h.T, packet)

	// Act: Sign the same packet a second time.
	result, err := w.SignPsbt(ctx, &wallet.SignPsbtParams{Packet: packet})

	// Assert: The packet keeps its records byte for byte.
	require.NoError(h, err)
	require.Empty(h, result.SignedInputs)

	require.Equal(h, original, psbtTestSnapshot(h.T, packet))
}

// testPsbtManagerSignFinalizedPacket verifies that signing a final packet adds
// nothing and reports no input as signed.
func testPsbtManagerSignFinalizedPacket(h *bwtest.HarnessTest) {
	// Arrange: Finalize a legacy and a SegWit Wallet spend, then restore
	// the derivation records the finalizer clears, so only the final
	// scripts mark the inputs done.
	ctx := h.Context()
	w, legacy := h.NewWallet(bwtest.WalletFixture{
		AddrType: waddrmgr.PubKeyHash,
		Amounts:  []btcutil.Amount{oneBTC},
		Unlocked: true,
	})
	segwit := h.FundWalletOfType(w, waddrmgr.WitnessPubKey, oneBTC)
	packet := newDecoratedPsbt(
		h, w, legacy.WalletOutpoints[0], segwit.WalletOutpoints[0],
	)
	legacyOrigins := packet.Inputs[0].Bip32Derivation
	segwitOrigins := packet.Inputs[1].Bip32Derivation
	require.NoError(h, w.FinalizePsbt(ctx, packet))

	packet.Inputs[0].Bip32Derivation = legacyOrigins
	packet.Inputs[1].Bip32Derivation = segwitOrigins
	original := psbtTestSnapshot(h.T, packet)

	// Act: Sign the final packet.
	result, err := w.SignPsbt(ctx, &wallet.SignPsbtParams{Packet: packet})

	// Assert: No input is signed and the packet is byte for byte the same.
	require.NoError(h, err)
	require.Empty(h, result.SignedInputs)

	require.Equal(h, original, psbtTestSnapshot(h.T, packet))
}

// testPsbtManagerSignPartialOwnership verifies that the Wallet signs only its
// own input, skips inputs it does not own, and keeps another signer's
// signatures.
func testPsbtManagerSignPartialOwnership(h *bwtest.HarnessTest) {
	// Arrange: One Wallet coin and two inputs of the other signer: one already
	// signed with no origin, and one unsigned whose origin names an account
	// the Wallet lacks in a scope it holds.
	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: waddrmgr.WitnessPubKey,
		Amounts:  []btcutil.Amount{oneBTC},
		Unlocked: true,
	})
	packet := newDecoratedPsbt(
		h, w, funding.WalletOutpoints[0], unknownOutpoint(),
		wire.OutPoint{Hash: chainhash.Hash{0xbb}},
	)

	scriptCode := addExternalPsbtInput(h, &packet.Inputs[1])
	addExternalPsbtInput(h, &packet.Inputs[2])
	addExternalPsbtSig(h, packet, 1, scriptCode)

	missingAccount := *packet.Inputs[0].Bip32Derivation[0]
	missingAccount.PubKey = psbtExternalKey().PubKey().SerializeCompressed()
	missingAccount.Bip32Path = slices.Clone(missingAccount.Bip32Path)
	missingAccount.Bip32Path[2] = hdkeychain.HardenedKeyStart + 55
	packet.Inputs[2].Bip32Derivation = []*psbt.Bip32Derivation{&missingAccount}
	original := psbtTestSnapshot(h.T, packet)

	// Act: Sign as the owner of the first input only.
	result, err := w.SignPsbt(
		h.Context(), &wallet.SignPsbtParams{Packet: packet},
	)

	// Assert: The Wallet added only a signature on its input, so the other
	// signer's inputs, signed and unsigned, are unchanged. The script engine
	// accepts the signature as that input's P2WPKH witness.
	require.NoError(h, err)
	require.Equal(h, []uint32{0}, result.SignedInputs)
	require.Len(h, packet.Inputs[0].PartialSigs, 1)

	partial := packet.Inputs[0].PartialSigs[0]
	prevOut := packet.Inputs[0].WitnessUtxo
	tx := packet.UnsignedTx.Copy()
	tx.TxIn[0].Witness = wire.TxWitness{partial.Signature, partial.PubKey}
	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	engine, err := txscript.NewEngine(
		prevOut.PkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		txscript.NewTxSigHashes(tx, fetcher), prevOut.Value, fetcher,
	)
	require.NoError(h, err)
	require.NoError(h, engine.Execute())

	unsigned := *packet
	unsigned.Inputs = slices.Clone(packet.Inputs)
	unsigned.Inputs[0].PartialSigs = nil
	require.Equal(h, original, psbtTestSnapshot(h.T, &unsigned))
}

// testPsbtManagerSignMultisigPartial verifies that the Wallet adds its partial
// signature to a shared script without disturbing the other signer's.
func testPsbtManagerSignMultisigPartial(h *bwtest.HarnessTest) {
	// Arrange: The other signer has already signed the 2-of-2 input.
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	packet, script := newMultisigPsbt(h, w)
	addExternalPsbtSig(h, packet, 0, script)
	walletKey := packet.Inputs[0].Bip32Derivation[0].PubKey
	original := psbtTestSnapshot(h.T, packet)

	// Act: Add the Wallet's signature.
	result, err := w.SignPsbt(
		h.Context(), &wallet.SignPsbtParams{Packet: packet},
	)

	// Assert: The Wallet added only its own signature, so the input is not
	// final, and the two signatures together satisfy the script.
	require.NoError(h, err)
	require.Equal(h, []uint32{0}, result.SignedInputs)

	unsigned := *packet
	unsigned.Inputs = slices.Clone(packet.Inputs)
	unsigned.Inputs[0].PartialSigs = slices.DeleteFunc(
		slices.Clone(packet.Inputs[0].PartialSigs),
		func(sig *psbt.PartialSig) bool {
			return bytes.Equal(sig.PubKey, walletKey)
		},
	)
	require.Equal(h, original, psbtTestSnapshot(h.T, &unsigned))

	require.NoError(h, psbt.MaybeFinalizeAll(packet))
	h.AssertPsbtExecutes(packet)
}

// testPsbtManagerSignUnrecognizedScript verifies that the Wallet signs its
// key's input even when it does not recognize the output script, leaving the
// script to the script engine.
func testPsbtManagerSignUnrecognizedScript(h *bwtest.HarnessTest) {
	// Arrange: A Wallet record on a legacy output whose nonstandard script
	// checks a signature by the Wallet key.
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	addr := h.NewWalletAddressOfType(w, waddrmgr.WitnessPubKey)
	origin, err := w.GetDerivationInfo(h.Context(), addr)
	require.NoError(h, err)

	pkScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_DUP).
		AddOp(txscript.OP_DROP).
		AddData(origin.PubKey).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(h, err)

	parentIn := unknownOutpoint()
	parent := wire.NewMsgTx(2)
	parent.AddTxIn(wire.NewTxIn(&parentIn, nil, nil))
	parent.AddTxOut(wire.NewTxOut(int64(oneBTC), pkScript))

	packet := psbtTestPacket(h.T, wire.OutPoint{Hash: parent.TxHash()})
	packet.Inputs[0].NonWitnessUtxo = parent
	packet.Inputs[0].SighashType = txscript.SigHashAll
	packet.Inputs[0].Bip32Derivation = []*psbt.Bip32Derivation{origin}
	original := psbtTestSnapshot(h.T, packet)

	// Act: Sign the input.
	result, err := w.SignPsbt(
		h.Context(), &wallet.SignPsbtParams{Packet: packet},
	)

	// Assert: The Wallet added only a signature, and the script engine
	// accepts it as the script's one push.
	require.NoError(h, err)
	require.Equal(h, []uint32{0}, result.SignedInputs)
	require.Len(h, packet.Inputs[0].PartialSigs, 1)

	unsigned := *packet
	unsigned.Inputs = slices.Clone(packet.Inputs)
	unsigned.Inputs[0].PartialSigs = nil
	require.Equal(h, original, psbtTestSnapshot(h.T, &unsigned))

	partial := packet.Inputs[0].PartialSigs[0]
	require.Equal(h, origin.PubKey, partial.PubKey)

	sigLen := len(partial.Signature) - 1
	require.Equal(
		h, byte(txscript.SigHashAll), partial.Signature[sigLen],
	)

	sigScript, err := txscript.NewScriptBuilder().
		AddData(partial.Signature).
		Script()
	require.NoError(h, err)

	packet.Inputs[0].FinalScriptSig = sigScript
	h.AssertPsbtExecutes(packet)
}

// testPsbtManagerSignTapscript verifies that a Taproot script-path input
// receives a signature that spends its leaf.
func testPsbtManagerSignTapscript(h *bwtest.HarnessTest) {
	// Arrange: The packet commits to one leaf checking a Wallet key.
	w, _ := h.NewWallet(bwtest.WalletFixture{Unlocked: true})
	packet := newTapscriptPsbt(h, w)
	original := psbtTestSnapshot(h.T, packet)

	// Act: Sign the script-path input.
	result, err := w.SignPsbt(
		h.Context(), &wallet.SignPsbtParams{Packet: packet},
	)

	// Assert: The Wallet added only a script-path signature, so the input
	// is not final, and that signature spends the output through the leaf.
	require.NoError(h, err)
	require.Equal(h, []uint32{0}, result.SignedInputs)

	unsigned := *packet
	unsigned.Inputs = slices.Clone(packet.Inputs)
	unsigned.Inputs[0].TaprootScriptSpendSig = nil
	require.Equal(h, original, psbtTestSnapshot(h.T, &unsigned))

	require.NoError(h, psbt.MaybeFinalizeAll(packet))
	h.AssertPsbtExecutes(packet)
}
