// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txauthor

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

type inputType uint8

const (
	p2pkh inputType = iota
	p2wkh
	p2npkh
	p2tr
)

type testOutput struct {
	amount    btcutil.Amount
	inputType inputType
}

// createOutput creates outputs of a transaction depending on their
// output script.
func createOutput(testOutputs ...testOutput) []*wire.TxOut {
	outputs := make([]*wire.TxOut, 0, len(testOutputs))
	var outScript []byte

	for _, output := range testOutputs {
		switch output.inputType {

		case p2pkh:
			outScript = make([]byte, txsizes.P2PKHPkScriptSize)

		case p2wkh:
			outScript = make([]byte, txsizes.P2WPKHPkScriptSize)

		case p2npkh:
			outScript = make([]byte,
				txsizes.NestedP2WPKHPkScriptSize)

		case p2tr:
			outScript = make([]byte, txsizes.P2TRPkScriptSize)

		}
		outputs = append(outputs, wire.NewTxOut(
			int64(output.amount), outScript),
		)
	}
	return outputs
}

// createCredit creates the unspent outputs for the transaction in the right format.
func createCredit(txIn ...testOutput) []wtxmgr.Credit {
	credits := make([]wtxmgr.Credit, len(txIn))

	var (
		zeroV1KeyPush = [34]byte{
			txscript.OP_1, txscript.OP_DATA_32,
		}

		zeroV0KeyPush = [22]byte{
			txscript.OP_0, txscript.OP_DATA_20,
		}

		zeroScriptPush = [23]byte{txscript.OP_0, txscript.OP_DATA_20,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			txscript.OP_EQUAL}

		zeroLegacyKeyPush = [25]byte{txscript.OP_DUP,
			txscript.OP_HASH160,
			txscript.OP_DATA_20,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			txscript.OP_EQUALVERIFY, txscript.OP_CHECKSIG}
	)

	var pkScript []byte

	for idx, in := range txIn {
		switch in.inputType {

		case p2pkh:
			pkScript = zeroLegacyKeyPush[:]

		case p2wkh:
			pkScript = zeroV0KeyPush[:]

		case p2npkh:
			pkScript = zeroScriptPush[:]

		case p2tr:
			pkScript = zeroV1KeyPush[:]
		}

		credits[idx] = wtxmgr.Credit{
			OutPoint: wire.OutPoint{},
			Amount:   btcutil.Amount(in.amount),
			PkScript: pkScript,
		}
	}
	return credits
}

func TestNewUnsignedTransaction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		Credit            []testOutput
		Outputs           []testOutput
		RelayFee          btcutil.Amount
		ChangeAmount      btcutil.Amount
		InputSourceError  bool
		InputCount        int
		SelectionStrategy InputSelectionStrategy
	}{
		0: {
			name: "insufficient funds",
			Credit: []testOutput{{
				amount: 1e8, inputType: p2wkh},
			},
			Outputs: []testOutput{{
				amount: 1e8, inputType: p2wkh},
			},
			RelayFee:          1e3,
			InputSourceError:  true,
			SelectionStrategy: PositiveYieldingSelection,
		},
		1: {
			name: "1 input and 1 output + change",
			Credit: []testOutput{{
				amount: 1e8, inputType: p2wkh},
			},
			Outputs: []testOutput{{
				amount: 1e6, inputType: p2wkh},
			},
			RelayFee: 1e3,
			// 141 is the txsize in vbytes of a transaction
			// with 1 P2WKH input and 1 P2WKH output plus
			// P2WKH change.
			ChangeAmount:      1e8 - 1e6 - 141,
			InputCount:        1,
			SelectionStrategy: PositiveYieldingSelection,
		},
		2: {
			name: "1 input and 1 output but no change paying " +
				"exactly 10 sat/vbyte",
			Credit: []testOutput{{
				amount: 1e8, inputType: p2wkh},
			},
			// 110 is the txsize in vbytes of a transaction
			// with 1 P2WKH input and 1 P2WKH output.
			Outputs: []testOutput{{
				amount: 1e8 - 1100, inputType: p2wkh},
			},
			RelayFee:     1e4,
			ChangeAmount: 0,
			InputCount:   1,
		},
		3: {
			name: "1 input and 1 output plus change which is " +
				"exactly the dustlimit(p2wkh)",
			Credit: []testOutput{{
				amount: 1e8, inputType: p2wkh},
			},
			// 110 is the txsize in vbytes of a transaction
			// with 1 P2WKH input and 1 P2WKH output.
			// 31 is the size of the additional P2WKH change output.
			Outputs: []testOutput{{
				amount: 1e8 - 110 - 31 - 294, inputType: p2wkh},
			},
			RelayFee:     1e3,
			ChangeAmount: 294,
			InputCount:   1,
		},
		4: {
			name: "1 input and 1 output aiming for 1 sat/vbyte " +
				"but Changeoutput is below dustlimit 294" +
				"leading to a higher feerate because the " +
				"change gets purged",
			Credit: []testOutput{{
				amount: 1e8, inputType: p2wkh},
			},
			// 122 is the txsize in vbytes of a transaction with
			// 1 P2WKH input and 1 P2TR output.
			// 31 is the size of the P2WKH output and
			// 294 is the Dustlimit for a P2WKH.
			Outputs: []testOutput{{
				amount: 1e8 - 122 - 31 - 293, inputType: p2tr},
			},
			RelayFee:     1e3,
			ChangeAmount: 0,
			InputCount:   1,
		},
		5: {
			name: "2 inputs with the first input negative " +
				"yielding and 1 output plus change",
			Credit: []testOutput{
				{amount: 1530, inputType: p2wkh},
				{amount: 1e6, inputType: p2wkh},
			},
			Outputs: []testOutput{{
				amount: 1e4, inputType: p2tr},
			},
			RelayFee: 1e4,
			// 1530 sat is the fee when spending 1 P2WKH input
			// and 1 P2TR output + P2WKH change at the defined
			//  fee-level.
			ChangeAmount:      1e6 - 1530 - 1e4,
			InputCount:        1,
			SelectionStrategy: RandomSelection,
		},
		6: {
			name: "2 inputs with the first input slightly " +
				"positive yielding and 1 output plus change",
			Credit: []testOutput{
				{amount: 1531, inputType: p2wkh},
				{amount: 1e6, inputType: p2wkh},
			},
			Outputs: []testOutput{{
				amount: 1e4, inputType: p2tr},
			},
			RelayFee: 1e4,
			// 2220 sat is the fee when spending 2 P2WKH input
			// and 1 P2TR output + P2WKH change at the defined
			// fee-level.
			// 1530 sat is the fee when spending 1 P2WKH input
			// and 1 P2TR output + P2WKH change at the defined
			// fee-level.
			ChangeAmount:      1e6 + 1531 - 2220 - 1e4,
			InputCount:        2,
			SelectionStrategy: RandomSelection,
		},
		7: {
			name: "2 inputs with the first input negative " +
				"yielding but constant input selection" +
				"plus change",
			Credit: []testOutput{
				{amount: 330, inputType: p2wkh},
				{amount: 1e6, inputType: p2wkh},
			},
			Outputs:  []testOutput{},
			RelayFee: 1e4,
			// 1790 sat is the fee when spending 2 P2WKH input
			// and a P2WKH change at the defined fee-level.
			ChangeAmount:      1e6 - 1790 + 330,
			InputCount:        2,
			SelectionStrategy: ConstantSelection,
		},
		8: {
			name: "2 initial inputs but only 1 input is " +
				"sufficient (postive yielding)",
			Credit: []testOutput{
				{amount: 1e6, inputType: p2wkh},
				{amount: 1e6, inputType: p2wkh},
			},
			Outputs: []testOutput{
				{amount: 1e4, inputType: p2tr},
			},
			RelayFee: 1e3,
			// 153 is the tx size in vbytes with 1 P2WKH input
			// and 1 P2TR output plus 1 P2WKH change output.
			ChangeAmount:      1e6 - 153 - 1e4,
			InputCount:        1,
			SelectionStrategy: PositiveYieldingSelection,
		},
		9: {
			name: "3 inputs with a constant input selection" +
				"1 output plus change",
			Credit: []testOutput{
				{amount: 100, inputType: p2wkh},
				{amount: 100, inputType: p2wkh},
				{amount: 1e6, inputType: p2wkh},
			},
			Outputs: []testOutput{
				{amount: 1e4, inputType: p2tr},
			},
			RelayFee: 1e3,
			// 290 is the tx size in vbytes with 3 P2WKH Inputs
			// and 1 P2TR output plus 1 P2WKH change output.
			ChangeAmount:      1e6 + 200 - 290 - 1e4,
			InputCount:        3,
			SelectionStrategy: ConstantSelection,
		},
		10: {
			name: "2 initial inputs with a positive yielding " +
				"selection failing because first input is " +
				"negative yielding",
			Credit: []testOutput{
				{amount: 100, inputType: p2wkh},
				{amount: 1e6, inputType: p2wkh},
			},
			Outputs: []testOutput{
				{amount: 1e4, inputType: p2tr},
			},
			RelayFee:          1e3,
			InputSourceError:  true,
			SelectionStrategy: PositiveYieldingSelection,
		},
		11: {
			name: "2 initial inputs with a positive yielding " +
				"selection where both are needed",
			Credit: []testOutput{
				{amount: 1e6, inputType: p2wkh},
				{amount: 1e6, inputType: p2wkh},
			},
			Outputs: []testOutput{
				{amount: 1.1e6, inputType: p2tr},
			},
			RelayFee: 1e3,
			// 222 is the tx size in vbytes with 2 P2WKH Inputs
			// and 1 P2TR output plus 1 P2WKH change output.
			ChangeAmount:      2*1e6 - 222 - (1.1e6),
			InputCount:        2,
			SelectionStrategy: PositiveYieldingSelection,
		},
	}

	changeSource := &ChangeSource{
		NewScript: func() ([]byte, error) {
			// Only length matters for these tests.
			pkScript := make([]byte, txsizes.P2WPKHPkScriptSize)
			// We need to make sure that the pkScript looks like
			// a common P2WKH script otherwise the dustlimit is
			// calculated wrongly.
			pkScript[1] = txscript.OP_DATA_20
			return pkScript, nil
		},
		ScriptSize: txsizes.P2WPKHPkScriptSize,
	}

	for i, test := range tests {
		inputSource := createCredit(test.Credit...)
		outputs := createOutput(test.Outputs...)
		tx, err := NewUnsignedTransaction(
			outputs, test.RelayFee, inputSource,
			test.SelectionStrategy, changeSource,
		)

		switch e := err.(type) {
		case nil:
		case InputSourceError:
			if !test.InputSourceError {
				t.Errorf("Test %d: Returned InputSourceError "+
					"but expected change output with "+
					"amount %v", i, test.ChangeAmount)
			}
			continue
		default:
			t.Errorf("Test %d: Unexpected error: %v", i, e)
			continue
		}
		if tx.ChangeIndex < 0 {
			if test.ChangeAmount != 0 {
				t.Errorf("Test %d: No change output added but "+
					"expected output with amount %v",
					i, test.ChangeAmount)
				continue
			}
		} else {
			changeAmount := btcutil.Amount(
				tx.Tx.TxOut[tx.ChangeIndex].Value,
			)

			if test.ChangeAmount == 0 {
				t.Errorf("Test %d: Included change output "+
					"with value %v but expected no change",
					i, changeAmount)
				continue
			}
			if changeAmount != test.ChangeAmount {
				t.Errorf("Test %d: Got change amount %v, "+
					"Expected %v", i, changeAmount,
					test.ChangeAmount)
				continue
			}
		}
		if len(tx.Tx.TxIn) != test.InputCount {
			t.Errorf("Test %d: Used %d outputs from input source, "+
				"Expected %d", i, len(tx.Tx.TxIn),
				test.InputCount)
		}
	}
}
