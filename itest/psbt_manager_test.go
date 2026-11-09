//go:build itest

package itest

import (
	"encoding/json"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/bwtest"
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

// psbtTestSnapshot records public packet structure without PSBT serialization,
// which sorts record slices in place. JSON preserves order, nil records, and
// nil versus empty slices, including shapes that cannot encode as a PSBT.
func psbtTestSnapshot(t *testing.T, packets ...*psbt.Packet) string {
	t.Helper()

	encoded, err := json.Marshal(packets)
	require.NoError(t, err)

	return string(encoded)
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
