// Copyright (c) 2020 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
	"github.com/stretchr/testify/require"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

var (
	testScriptP2WSH, _ = hex.DecodeString(
		"0020d554616badeb46ccd4ce4b115e1c8d098e942d1387212d0af9ff93a1" +
			"9c8f100e",
	)
	testScriptP2WKH, _ = hex.DecodeString(
		"0014e7a43aa41ef6d72dc6baeeaad8362cedf63b79a3",
	)
)

// TestFundPsbt tests that a given PSBT packet is funded correctly.
func TestFundPsbt(t *testing.T) {
	t.Parallel()

	w, cleanup := testWallet(t)
	defer cleanup()

	// Create a P2WKH address we can use to send some coins to.
	addr, err := w.CurrentAddress(0, waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)
	p2wkhAddr, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// Also create a nested P2WKH address we can use to send some coins to.
	addr, err = w.CurrentAddress(0, waddrmgr.KeyScopeBIP0049Plus)
	require.NoError(t, err)
	np2wkhAddr, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	// Register two big UTXO that will be used when funding the PSBT.
	const utxo1Amount = 1000000
	incomingTx1 := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{wire.NewTxOut(utxo1Amount, p2wkhAddr)},
	}
	addUtxo(t, w, incomingTx1)
	utxo1 := wire.OutPoint{
		Hash:  incomingTx1.TxHash(),
		Index: 0,
	}

	const utxo2Amount = 900000
	incomingTx2 := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{wire.NewTxOut(utxo2Amount, np2wkhAddr)},
	}
	addUtxo(t, w, incomingTx2)
	utxo2 := wire.OutPoint{
		Hash:  incomingTx2.TxHash(),
		Index: 0,
	}

	testCases := []struct {
		name                    string
		packet                  *psbt.Packet
		feeRateSatPerKB         btcutil.Amount
		changeKeyScope          *waddrmgr.KeyScope
		expectedErr             string
		validatePackage         bool
		expectedChangeBeforeFee int64
		expectedInputs          []wire.OutPoint
		additionalChecks        func(*testing.T, *psbt.Packet, int32)
	}{{
		name: "no outputs provided",
		packet: &psbt.Packet{
			UnsignedTx: &wire.MsgTx{},
		},
		feeRateSatPerKB: 0,
		expectedErr: "PSBT packet must contain at least one " +
			"input or output",
	}, {
		name: "single input, no outputs",
		packet: &psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxIn: []*wire.TxIn{{
					PreviousOutPoint: utxo1,
				}},
			},
			Inputs: []psbt.PInput{{}},
		},
		feeRateSatPerKB:         20000,
		validatePackage:         true,
		expectedInputs:          []wire.OutPoint{utxo1},
		expectedChangeBeforeFee: utxo1Amount,
	}, {
		name: "no dust outputs",
		packet: &psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxOut: []*wire.TxOut{{
					PkScript: []byte("foo"),
					Value:    100,
				}},
			},
			Outputs: []psbt.POutput{{}},
		},
		feeRateSatPerKB: 0,
		expectedErr:     "transaction output is dust",
	}, {
		name: "two outputs, no inputs",
		packet: &psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxOut: []*wire.TxOut{{
					PkScript: testScriptP2WSH,
					Value:    100000,
				}, {
					PkScript: testScriptP2WKH,
					Value:    50000,
				}},
			},
			Outputs: []psbt.POutput{{}, {}},
		},
		feeRateSatPerKB:         2000, // 2 sat/byte
		expectedErr:             "",
		validatePackage:         true,
		expectedChangeBeforeFee: utxo1Amount - 150000,
		expectedInputs:          []wire.OutPoint{utxo1},
	}, {
		name: "large output, no inputs",
		packet: &psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxOut: []*wire.TxOut{{
					PkScript: testScriptP2WSH,
					Value:    1500000,
				}},
			},
			Outputs: []psbt.POutput{{}},
		},
		feeRateSatPerKB:         4000, // 4 sat/byte
		expectedErr:             "",
		validatePackage:         true,
		expectedChangeBeforeFee: (utxo1Amount + utxo2Amount) - 1500000,
		expectedInputs:          []wire.OutPoint{utxo1, utxo2},
	}, {
		name: "two outputs, two inputs",
		packet: &psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxIn: []*wire.TxIn{{
					PreviousOutPoint: utxo1,
				}, {
					PreviousOutPoint: utxo2,
				}},
				TxOut: []*wire.TxOut{{
					PkScript: testScriptP2WSH,
					Value:    100000,
				}, {
					PkScript: testScriptP2WKH,
					Value:    50000,
				}},
			},
			Inputs:  []psbt.PInput{{}, {}},
			Outputs: []psbt.POutput{{}, {}},
		},
		feeRateSatPerKB:         2000, // 2 sat/byte
		expectedErr:             "",
		validatePackage:         true,
		expectedChangeBeforeFee: (utxo1Amount + utxo2Amount) - 150000,
		expectedInputs:          []wire.OutPoint{utxo1, utxo2},
		additionalChecks: func(t *testing.T, packet *psbt.Packet,
			changeIndex int32) {

			// Check outputs, find index for each of the 3 expected.
			txOuts := packet.UnsignedTx.TxOut
			require.Len(t, txOuts, 3, "tx outputs")

			p2wkhIndex := -1
			p2wshIndex := -1
			totalOut := int64(0)
			for idx, txOut := range txOuts {
				script := txOut.PkScript
				totalOut += txOut.Value

				switch {
				case bytes.Equal(script, testScriptP2WKH):
					p2wkhIndex = idx

				case bytes.Equal(script, testScriptP2WSH):
					p2wshIndex = idx

				}
			}
			totalIn := int64(0)
			for _, txIn := range packet.Inputs {
				totalIn += txIn.WitnessUtxo.Value
			}

			// All outputs must be found.
			require.Greater(t, p2wkhIndex, -1)
			require.Greater(t, p2wshIndex, -1)
			require.Greater(t, changeIndex, int32(-1))

			// After BIP 69 sorting, the P2WKH output should be
			// before the P2WSH output because the PK script is
			// lexicographically smaller.
			require.Less(
				t, p2wkhIndex, p2wshIndex,
				"index after sorting",
			)
		},
	}, {
		name: "one input and a custom change scope: BIP0084",
		packet: &psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxIn: []*wire.TxIn{{
					PreviousOutPoint: utxo1,
				}},
			},
			Inputs: []psbt.PInput{{}},
		},
		feeRateSatPerKB:         20000,
		validatePackage:         true,
		changeKeyScope:          &waddrmgr.KeyScopeBIP0084,
		expectedInputs:          []wire.OutPoint{utxo1},
		expectedChangeBeforeFee: utxo1Amount,
	}, {
		name: "no inputs and a custom change scope: BIP0084",
		packet: &psbt.Packet{
			UnsignedTx: &wire.MsgTx{
				TxOut: []*wire.TxOut{{
					PkScript: testScriptP2WSH,
					Value:    100000,
				}, {
					PkScript: testScriptP2WKH,
					Value:    50000,
				}},
			},
			Outputs: []psbt.POutput{{}, {}},
		},
		feeRateSatPerKB:         2000, // 2 sat/byte
		expectedErr:             "",
		validatePackage:         true,
		changeKeyScope:          &waddrmgr.KeyScopeBIP0084,
		expectedChangeBeforeFee: utxo1Amount - 150000,
		expectedInputs:          []wire.OutPoint{utxo1},
	}}

	calcFee := func(feeRateSatPerKB btcutil.Amount,
		packet *psbt.Packet) btcutil.Amount {

		var numP2WKHInputs, numNP2WKHInputs int
		for _, txin := range packet.UnsignedTx.TxIn {
			if txin.PreviousOutPoint == utxo1 {
				numP2WKHInputs++
			}
			if txin.PreviousOutPoint == utxo2 {
				numNP2WKHInputs++
			}
		}
		estimatedSize := txsizes.EstimateVirtualSize(
			0, 0, numP2WKHInputs, numNP2WKHInputs,
			packet.UnsignedTx.TxOut, 0,
		)
		return txrules.FeeForSerializeSize(
			feeRateSatPerKB, estimatedSize,
		)
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			changeIndex, err := w.FundPsbt(
				tc.packet, nil, 1, 0,
				tc.feeRateSatPerKB, CoinSelectionLargest,
				WithCustomChangeScope(tc.changeKeyScope),
			)

			// In any case, unlock the UTXO before continuing, we
			// don't want to pollute other test iterations.
			for _, in := range tc.packet.UnsignedTx.TxIn {
				w.UnlockOutpoint(in.PreviousOutPoint)
			}

			// Make sure the error is what we expected.
			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
				return
			}

			require.NoError(t, err)

			if !tc.validatePackage {
				return
			}

			// Check wire inputs.
			packet := tc.packet
			assertTxInputs(t, packet, tc.expectedInputs)

			// Run any additional tests if available.
			if tc.additionalChecks != nil {
				tc.additionalChecks(t, packet, changeIndex)
			}

			// Finally, check the change output size and fee.
			txOuts := packet.UnsignedTx.TxOut
			totalOut := int64(0)
			for _, txOut := range txOuts {
				totalOut += txOut.Value
			}
			totalIn := int64(0)
			for _, txIn := range packet.Inputs {
				totalIn += txIn.WitnessUtxo.Value
			}
			fee := totalIn - totalOut

			expectedFee := calcFee(tc.feeRateSatPerKB, packet)
			require.EqualValues(t, expectedFee, fee, "fee")
			require.EqualValues(
				t, tc.expectedChangeBeforeFee,
				txOuts[changeIndex].Value+int64(expectedFee),
			)

			changeTxOut := txOuts[changeIndex]
			changeOutput := packet.Outputs[changeIndex]

			require.NotEmpty(t, changeOutput.Bip32Derivation)
			b32d := changeOutput.Bip32Derivation[0]
			require.Len(t, b32d.Bip32Path, 5, "derivation path len")
			require.Len(t, b32d.PubKey, 33, "pubkey len")

			// The third item should be the branch and should belong
			// to a change output.
			require.EqualValues(t, 1, b32d.Bip32Path[3])

			assertChangeOutputScope(
				t, changeTxOut.PkScript, tc.changeKeyScope,
			)

			if txscript.IsPayToTaproot(changeTxOut.PkScript) {
				require.NotEmpty(
					t, changeOutput.TaprootInternalKey,
				)
				require.Len(
					t, changeOutput.TaprootInternalKey, 32,
					"internal key len",
				)
				require.NotEmpty(
					t, changeOutput.TaprootBip32Derivation,
				)

				trb32d := changeOutput.TaprootBip32Derivation[0]
				require.Equal(
					t, b32d.Bip32Path, trb32d.Bip32Path,
				)
				require.Len(
					t, trb32d.XOnlyPubKey, 32,
					"schnorr pubkey len",
				)
				require.Equal(
					t, changeOutput.TaprootInternalKey,
					trb32d.XOnlyPubKey,
				)
			}
		})
	}
}

func assertTxInputs(t *testing.T, packet *psbt.Packet,
	expected []wire.OutPoint) {

	require.Len(t, packet.UnsignedTx.TxIn, len(expected))

	// The order of the UTXOs is random, we need to loop through each of
	// them to make sure they're found. We also check that no signature data
	// was added yet.
	for _, txIn := range packet.UnsignedTx.TxIn {
		if !containsUtxo(expected, txIn.PreviousOutPoint) {
			t.Fatalf("outpoint %v not found in list of expected "+
				"UTXOs", txIn.PreviousOutPoint)
		}

		require.Empty(t, txIn.SignatureScript)
		require.Empty(t, txIn.Witness)
	}
}

// assertChangeOutputScope checks if the pkScript has the right type.
func assertChangeOutputScope(t *testing.T, pkScript []byte,
	changeScope *waddrmgr.KeyScope) {

	// By default (changeScope == nil), the script should
	// be a pay-to-taproot one.
	switch changeScope {
	case nil, &waddrmgr.KeyScopeBIP0086:
		require.True(t, txscript.IsPayToTaproot(pkScript))

	case &waddrmgr.KeyScopeBIP0049Plus, &waddrmgr.KeyScopeBIP0084:
		require.True(t, txscript.IsPayToWitnessPubKeyHash(pkScript))

	case &waddrmgr.KeyScopeBIP0044:
		require.True(t, txscript.IsPayToPubKeyHash(pkScript))

	default:
		require.Fail(t, "assertChangeOutputScope error",
			"change scope: %s", changeScope.String())
	}
}

func containsUtxo(list []wire.OutPoint, candidate wire.OutPoint) bool {
	for _, utxo := range list {
		if utxo == candidate {
			return true
		}
	}

	return false
}

// TestFinalizePsbt tests that a given PSBT packet can be finalized.
func TestFinalizePsbt(t *testing.T) {
	t.Parallel()

	w, cleanup := testWallet(t)
	defer cleanup()

	// Create a P2WKH address we can use to send some coins to.
	addr, err := w.CurrentAddress(0, waddrmgr.KeyScopeBIP0084)
	if err != nil {
		t.Fatalf("unable to get current address: %v", addr)
	}
	p2wkhAddr, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("unable to convert wallet address to p2wkh: %v", err)
	}

	// Also create a nested P2WKH address we can send coins to.
	addr, err = w.CurrentAddress(0, waddrmgr.KeyScopeBIP0049Plus)
	if err != nil {
		t.Fatalf("unable to get current address: %v", addr)
	}
	np2wkhAddr, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("unable to convert wallet address to np2wkh: %v", err)
	}

	// Register two big UTXO that will be used when funding the PSBT.
	utxOutP2WKH := wire.NewTxOut(1000000, p2wkhAddr)
	utxOutNP2WKH := wire.NewTxOut(1000000, np2wkhAddr)
	incomingTx := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{utxOutP2WKH, utxOutNP2WKH},
	}
	addUtxo(t, w, incomingTx)

	// Create the packet that we want to sign.
	packet := &psbt.Packet{
		UnsignedTx: &wire.MsgTx{
			TxIn: []*wire.TxIn{{
				PreviousOutPoint: wire.OutPoint{
					Hash:  incomingTx.TxHash(),
					Index: 0,
				},
			}, {
				PreviousOutPoint: wire.OutPoint{
					Hash:  incomingTx.TxHash(),
					Index: 1,
				},
			}},
			TxOut: []*wire.TxOut{{
				PkScript: testScriptP2WKH,
				Value:    50000,
			}, {
				PkScript: testScriptP2WSH,
				Value:    100000,
			}, {
				PkScript: testScriptP2WKH,
				Value:    849632,
			}},
		},
		Inputs: []psbt.PInput{{
			WitnessUtxo: utxOutP2WKH,
			SighashType: txscript.SigHashAll,
		}, {
			NonWitnessUtxo: incomingTx,
			SighashType:    txscript.SigHashAll,
		}},
		Outputs: []psbt.POutput{{}, {}, {}},
	}

	// Finalize it to add all witness data then extract the final TX.
	err = w.FinalizePsbt(nil, 0, packet)
	if err != nil {
		t.Fatalf("error finalizing PSBT packet: %v", err)
	}
	finalTx, err := psbt.Extract(packet)
	if err != nil {
		t.Fatalf("error extracting final TX from PSBT: %v", err)
	}

	// Finally verify that the created witness is valid.
	err = validateMsgTx(
		finalTx, [][]byte{utxOutP2WKH.PkScript, utxOutNP2WKH.PkScript},
		[]btcutil.Amount{1000000, 1000000},
	)
	if err != nil {
		t.Fatalf("error validating tx: %v", err)
	}
}
