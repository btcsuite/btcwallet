package txsizes

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// newTxIn returns a transaction input with signature script and witness items
// of the requested sizes.
func newTxIn(signatureScriptSize int, witnessItemSizes ...int) *wire.TxIn {
	witness := make([][]byte, len(witnessItemSizes))
	for i, size := range witnessItemSizes {
		witness[i] = bytes.Repeat([]byte{0xff}, size)
	}

	return wire.NewTxIn(
		&wire.OutPoint{}, bytes.Repeat([]byte{0xff}, signatureScriptSize),
		witness,
	)
}

// TestEstimateVirtualSizeOutputCount asserts that the estimate accounts for
// the compact int that prefixes the outputs, whose width depends on how many
// outputs the transaction has, change included.
func TestEstimateVirtualSizeOutputCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		outputCount      int
		changeScriptSize int
	}{
		{
			name:        "single output",
			outputCount: 1,
		},
		{
			name:             "single output with change",
			outputCount:      1,
			changeScriptSize: P2WPKHPkScriptSize,
		},
		{
			name:             "change stays inside one byte",
			outputCount:      251,
			changeScriptSize: P2WPKHPkScriptSize,
		},
		{
			name:             "change widens the compact int",
			outputCount:      252,
			changeScriptSize: P2WPKHPkScriptSize,
		},
		{
			name:        "253 outputs without change",
			outputCount: 253,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tx := wire.NewMsgTx(1)
			tx.AddTxIn(newTxIn(RedeemP2PKHSigScriptSize))

			txOuts := make([]*wire.TxOut, test.outputCount)
			for i := range txOuts {
				txOuts[i] = &wire.TxOut{
					PkScript: bytes.Repeat(
						[]byte{0xff}, P2PKHPkScriptSize,
					),
				}
				tx.AddTxOut(txOuts[i])
			}

			// The change output reaches the estimator as a script
			// size, so it has to be appended by hand.
			if test.changeScriptSize > 0 {
				tx.AddTxOut(&wire.TxOut{
					PkScript: bytes.Repeat(
						[]byte{0xff}, test.changeScriptSize,
					),
				})
			}

			actual := EstimateVirtualSize(
				1, 0, 0, 0, txOuts, test.changeScriptSize,
			)
			expected := mempool.GetTxVirtualSize(btcutil.NewTx(tx))
			require.EqualValues(
				t, expected, actual, "unexpected virtual size estimate",
			)
		})
	}
}

// TestEstimateVirtualSizeWitnessAccounting asserts that the estimate accounts
// for the witness of every input type, and for the empty witness that legacy
// inputs are serialized with once any other input carries one.
func TestEstimateVirtualSizeWitnessAccounting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		p2pkhIns        int
		p2trIns         int
		p2wpkhIns       int
		nestedP2WPKHIns int
	}{
		{
			name:     "legacy inputs only",
			p2pkhIns: 2,
		},
		{
			name:      "P2WPKH inputs",
			p2wpkhIns: 2,
		},
		{
			name:            "nested P2WPKH inputs",
			nestedP2WPKHIns: 2,
		},
		{
			name:    "Taproot input",
			p2trIns: 1,
		},
		{
			name:      "legacy inputs need empty witnesses",
			p2pkhIns:  2,
			p2wpkhIns: 1,
		},
		{
			name:            "one input of every type",
			p2pkhIns:        1,
			p2trIns:         1,
			p2wpkhIns:       1,
			nestedP2WPKHIns: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tx := wire.NewMsgTx(1)
			for range test.p2pkhIns {
				tx.AddTxIn(newTxIn(RedeemP2PKHSigScriptSize))
			}
			for range test.p2trIns {
				tx.AddTxIn(newTxIn(RedeemP2TRScriptSize, 65))
			}
			for range test.p2wpkhIns {
				tx.AddTxIn(newTxIn(
					RedeemP2WPKHScriptSize, 73, 33,
				))
			}
			for range test.nestedP2WPKHIns {
				tx.AddTxIn(newTxIn(
					RedeemNestedP2WPKHScriptSize, 73, 33,
				))
			}

			txOuts := []*wire.TxOut{{
				PkScript: bytes.Repeat(
					[]byte{0xff}, P2PKHPkScriptSize,
				),
			}}
			tx.AddTxOut(txOuts[0])

			actual := EstimateVirtualSize(
				test.p2pkhIns, test.p2trIns, test.p2wpkhIns,
				test.nestedP2WPKHIns, txOuts, 0,
			)
			expected := mempool.GetTxVirtualSize(btcutil.NewTx(tx))
			require.EqualValues(
				t, expected, actual, "unexpected virtual size estimate",
			)
		})
	}
}
