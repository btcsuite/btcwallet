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
	addr, err = w.CurrentAddress(0, waddrmgr.KeyScopeBIP0084)
	if err != nil {
		t.Fatalf("unable to get current address: %v", addr)
	}
	np2wkhAddr, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("unable to convert wallet address to np2wkh: %v", err)
	}

	// Register two big UTXO that will be used when funding the PSBT.
	incomingTx := &wire.MsgTx{
		TxIn: []*wire.TxIn{{}},
		TxOut: []*wire.TxOut{
			wire.NewTxOut(1000000, p2wkhAddr),
			wire.NewTxOut(1000000, np2wkhAddr),
		},
	}
	addUtxo(t, w, incomingTx)

	testCases := []struct {
		name              string
		packet            *psbt.Packet
		feeRateSatPerKB   btcutil.Amount
		expectedErr       string
		validatePackage   bool
		numExpectedInputs int
	}{{
		name: "no outputs provided",
		packet: &psbt.Packet{
			UnsignedTx: &wire.MsgTx{},
		},
		feeRateSatPerKB: 0,
		expectedErr:     "must contain at least one output",
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
		feeRateSatPerKB:   2000, // 2 sat/byte
		expectedErr:       "",
		validatePackage:   true,
		numExpectedInputs: 1,
	}, {
		name: "two outputs, two inputs",
		packet: &psbt.Packet{
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
		feeRateSatPerKB:   2000, // 2 sat/byte
		expectedErr:       "",
		validatePackage:   true,
		numExpectedInputs: 2,
	}}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			changeIndex, err := w.FundPsbt(
				tc.packet, 0, tc.feeRateSatPerKB,
			)

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
			if len(packet.UnsignedTx.TxIn) != tc.numExpectedInputs {
				t.Fatalf("expected %d inputs to be added, got "+
					"%d", tc.numExpectedInputs,
					len(packet.UnsignedTx.TxIn))
			}
			txIn := packet.UnsignedTx.TxIn[0]
			if txIn.PreviousOutPoint.Hash != incomingTx.TxHash() {
				t.Fatalf("unexpected UTXO prev outpoint "+
					"hash, got %v wanted %v",
					txIn.PreviousOutPoint.Hash,
					incomingTx.TxHash())
			}
			if tc.numExpectedInputs > 1 {
				txIn2 := packet.UnsignedTx.TxIn[1]
				if txIn2.PreviousOutPoint.Hash != incomingTx.TxHash() {
					t.Fatalf("unexpected UTXO prev outpoint "+
						"hash, got %v wanted %v",
						txIn2.PreviousOutPoint.Hash,
						incomingTx.TxHash())
				}
			}

			// Check partial inputs.
			if len(packet.Inputs) != tc.numExpectedInputs {
				t.Fatalf("expected %d partial input to be "+
					"added, got %d", tc.numExpectedInputs,
					len(packet.Inputs))
			}
			in := packet.Inputs[0]
			if in.WitnessUtxo == nil {
				t.Fatalf("partial input witness UTXO not set")
			}
			if !bytes.Equal(in.WitnessUtxo.PkScript, p2wkhAddr) {
				t.Fatalf("unexpected witness UTXO script, "+
					"got %x wanted %x",
					in.WitnessUtxo.PkScript, p2wkhAddr)
			}
			if in.NonWitnessUtxo == nil {
				t.Fatalf("partial input non-witness UTXO not " +
					"set")
			}
			prevIdx := txIn.PreviousOutPoint.Index
			nonWitnessOut := in.NonWitnessUtxo.TxOut[prevIdx]
			if !bytes.Equal(nonWitnessOut.PkScript, p2wkhAddr) {
				t.Fatalf("unexpected witness UTXO script, "+
					"got %x wanted %x",
					nonWitnessOut.PkScript, p2wkhAddr)
			}
			if in.SighashType != txscript.SigHashAll {
				t.Fatalf("unexpected sighash flag, got %d "+
					"wanted %d", in.SighashType,
					txscript.SigHashAll)
			}
			if tc.numExpectedInputs > 1 {
				in2 := packet.Inputs[1]
				if in2.WitnessUtxo == nil {
					t.Fatalf("partial input witness UTXO " +
						"not set")
				}
				if !bytes.Equal(in2.WitnessUtxo.PkScript, np2wkhAddr) {
					t.Fatalf("unexpected witness UTXO "+
						"script, got %x wanted %x",
						in2.WitnessUtxo.PkScript,
						np2wkhAddr)
				}
				if in2.NonWitnessUtxo == nil {
					t.Fatalf("partial input non-witness " +
						"UTXO not set")
				}
				txIn2 := packet.UnsignedTx.TxIn[1]
				prevIdx2 := txIn2.PreviousOutPoint.Index
				nonWitnessOut2 := in2.NonWitnessUtxo.TxOut[prevIdx2]
				if !bytes.Equal(nonWitnessOut2.PkScript, p2wkhAddr) {
					t.Fatalf("unexpected witness UTXO script, "+
						"got %x wanted %x",
						nonWitnessOut2.PkScript, p2wkhAddr)
				}
				if in2.SighashType != txscript.SigHashAll {
					t.Fatalf("unexpected sighash flag, "+
						"got %d wanted %d",
						in2.SighashType,
						txscript.SigHashAll)
				}
			}

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

			// Finally, check the change output size and that it
			// belongs to the wallet.
			expectedFee := int64(368)
			expectedChange := 1000000 - 150000 - expectedFee
			if txOuts[changeIndex].Value != expectedChange {
				t.Fatalf("unexpected change output size, got "+
					"%d wanted %d",
					txOuts[changeIndex].Value,
					expectedChange)
			}
		})
	}
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
	err = w.FinalizePsbt(packet)
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
