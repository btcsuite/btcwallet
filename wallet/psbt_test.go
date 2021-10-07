// Copyright (c) 2020 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/psbt"
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

	// Also create a nested P2WKH address we can use to send some coins to.
	addr, err = w.CurrentAddress(0, waddrmgr.KeyScopeBIP0049Plus)
	if err != nil {
		t.Fatalf("unable to get current address: %v", addr)
	}
	np2wkhAddr, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("unable to convert wallet address to np2wkh: %v", err)
	}

	// Register two big UTXO that will be used when funding the PSBT.
	incomingTx1 := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{wire.NewTxOut(1000000, p2wkhAddr)},
	}
	addUtxo(t, w, incomingTx1)
	utxo1 := wire.OutPoint{
		Hash:  incomingTx1.TxHash(),
		Index: 0,
	}

	incomingTx2 := &wire.MsgTx{
		TxIn:  []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{wire.NewTxOut(900000, np2wkhAddr)},
	}
	addUtxo(t, w, incomingTx2)
	utxo2 := wire.OutPoint{
		Hash:  incomingTx2.TxHash(),
		Index: 0,
	}

	testCases := []struct {
		name             string
		packet           *psbt.Packet
		feeRateSatPerKB  btcutil.Amount
		expectedErr      string
		validatePackage  bool
		expectedFee      int64
		expectedChange   int64
		expectedInputs   []wire.OutPoint
		additionalChecks func(*testing.T, *psbt.Packet, int32)
	}{{
		name: "no outputs provided",
		packet: &psbt.Packet{
			UnsignedTx: &wire.MsgTx{},
		},
		feeRateSatPerKB: 0,
		expectedErr:     "PSBT packet must contain at least one input or output",
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
		feeRateSatPerKB: 20000,
		validatePackage: true,
		expectedInputs:  []wire.OutPoint{utxo1},
		expectedFee:     2200,
		expectedChange:  997800,
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
		feeRateSatPerKB: 2000, // 2 sat/byte
		expectedErr:     "",
		validatePackage: true,
		expectedFee:     368,
		expectedChange:  1000000 - 150000 - 368,
		expectedInputs:  []wire.OutPoint{utxo1},
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
		feeRateSatPerKB: 4000, // 4 sat/byte
		expectedErr:     "",
		validatePackage: true,
		expectedFee:     980,
		expectedChange:  1900000 - 1500000 - 980,
		expectedInputs:  []wire.OutPoint{utxo1, utxo2},
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
		feeRateSatPerKB: 2000, // 2 sat/byte
		expectedErr:     "",
		validatePackage: true,
		expectedFee:     552,
		expectedChange:  1900000 - 150000 - 552,
		expectedInputs:  []wire.OutPoint{utxo1, utxo2},
		additionalChecks: func(t *testing.T, packet *psbt.Packet,
			changeIndex int32) {

			// Check outputs, find index for each of the 3 expected.
			txOuts := packet.UnsignedTx.TxOut
			if len(txOuts) != 3 {
				t.Fatalf("unexpected outputs, got %d wanted 3",
					len(txOuts))
			}
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
			if p2wkhIndex < 0 || p2wshIndex < 0 || changeIndex < 0 {
				t.Fatalf("not all outputs found, got indices "+
					"p2wkh=%d, p2wsh=%d, change=%d",
					p2wkhIndex, p2wshIndex, changeIndex)
			}

			// After BIP 69 sorting, the P2WKH output should be
			// before the P2WSH output because the PK script is
			// lexicographically smaller.
			if p2wkhIndex > p2wshIndex {
				t.Fatalf("expected output with script %x to "+
					"be before script %x",
					txOuts[p2wkhIndex].PkScript,
					txOuts[p2wshIndex].PkScript)
			}
		},
	}}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			changeIndex, err := w.FundPsbt(
				tc.packet, nil, 1, 0, tc.feeRateSatPerKB,
				CoinSelectionLargest,
			)

			// In any case, unlock the UTXO before continuing, we
			// don't want to pollute other test iterations.
			for _, in := range tc.packet.UnsignedTx.TxIn {
				w.UnlockOutpoint(in.PreviousOutPoint)
			}

			// Make sure the error is what we expected.
			if err == nil && tc.expectedErr != "" {
				t.Fatalf("expected error '%s' but got nil",
					tc.expectedErr)
			}
			if err != nil && tc.expectedErr == "" {
				t.Fatalf("expected nil error but got '%v'", err)
			}
			if err != nil &&
				!strings.Contains(err.Error(), tc.expectedErr) {

				t.Fatalf("expected error '%s' but got '%v'",
					tc.expectedErr, err)
			}

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
			if fee != tc.expectedFee {
				t.Fatalf("unexpected fee, got %d wanted %d",
					fee, tc.expectedFee)
			}
			if txOuts[changeIndex].Value != tc.expectedChange {
				t.Fatalf("unexpected change output size, got "+
					"%d wanted %d",
					txOuts[changeIndex].Value,
					tc.expectedChange)
			}
		})
	}
}

func assertTxInputs(t *testing.T, packet *psbt.Packet,
	expected []wire.OutPoint) {

	if len(packet.UnsignedTx.TxIn) != len(expected) {
		t.Fatalf("expected %d inputs to be added, got %d",
			len(expected), len(packet.UnsignedTx.TxIn))
	}

	// The order of the UTXOs is random, we need to loop through each of
	// them to make sure they're found. We also check that no signature data
	// was added yet.
	for _, txIn := range packet.UnsignedTx.TxIn {
		if !containsUtxo(expected, txIn.PreviousOutPoint) {
			t.Fatalf("outpoint %v not found in list of expected "+
				"UTXOs", txIn.PreviousOutPoint)
		}

		if len(txIn.SignatureScript) > 0 {
			t.Fatalf("expected scriptSig to be empty on "+
				"txin, got %x instead",
				txIn.SignatureScript)
		}
		if len(txIn.Witness) > 0 {
			t.Fatalf("expected witness to be empty on "+
				"txin, got %v instead",
				txIn.Witness)
		}
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
