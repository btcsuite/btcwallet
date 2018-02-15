package txsizes_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/roasbeef/btcd/wire"
	. "github.com/roasbeef/btcwallet/wallet/internal/txsizes"
)

const (
	p2pkhScriptSize = P2PKHPkScriptSize
	p2shScriptSize  = 23
)

func makeInts(value int, n int) []int {
	v := make([]int, n)
	for i := range v {
		v[i] = value
	}
	return v
}

func TestEstimateSerializeSize(t *testing.T) {
	tests := []struct {
		InputCount           int
		OutputScriptLengths  []int
		AddChangeOutput      bool
		ExpectedSizeEstimate int
	}{
		0: {1, []int{}, false, 159},
		1: {1, []int{p2pkhScriptSize}, false, 193},
		2: {1, []int{}, true, 193},
		3: {1, []int{p2pkhScriptSize}, true, 227},
		4: {1, []int{p2shScriptSize}, false, 191},
		5: {1, []int{p2shScriptSize}, true, 225},

		6:  {2, []int{}, false, 308},
		7:  {2, []int{p2pkhScriptSize}, false, 342},
		8:  {2, []int{}, true, 342},
		9:  {2, []int{p2pkhScriptSize}, true, 376},
		10: {2, []int{p2shScriptSize}, false, 340},
		11: {2, []int{p2shScriptSize}, true, 374},

		// 0xfd is discriminant for 16-bit compact ints, compact int
		// total size increases from 1 byte to 3.
		12: {1, makeInts(p2pkhScriptSize, 0xfc), false, 8727},
		13: {1, makeInts(p2pkhScriptSize, 0xfd), false, 8727 + P2PKHOutputSize + 2},
		14: {1, makeInts(p2pkhScriptSize, 0xfc), true, 8727 + P2PKHOutputSize + 2},
		15: {0xfc, []int{}, false, 37558},
		16: {0xfd, []int{}, false, 37558 + RedeemP2PKHInputSize + 2},
	}
	for i, test := range tests {
		outputs := make([]*wire.TxOut, 0, len(test.OutputScriptLengths))
		for _, l := range test.OutputScriptLengths {
			outputs = append(outputs, &wire.TxOut{PkScript: make([]byte, l)})
		}
		actualEstimate := EstimateSerializeSize(test.InputCount, outputs, test.AddChangeOutput)
		if actualEstimate != test.ExpectedSizeEstimate {
			t.Errorf("Test %d: Got %v: Expected %v", i, actualEstimate, test.ExpectedSizeEstimate)
		}
	}
}

func TestEstimateVirtualSize(t *testing.T) {

	type estimateVSizeTest struct {
		tx             func() (*wire.MsgTx, error)
		p2wkhIns       int
		nestedP2wkhIns int
		change         bool
		result         int
	}

	// TODO(halseth): add tests for more combination out inputs/outputs.
	tests := []estimateVSizeTest{
		// Spending P2WPKH to two outputs. Example adapted from example in BIP-143.
		{
			tx: func() (*wire.MsgTx, error) {
				txHex := "01000000000101ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac0247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
				b, err := hex.DecodeString(txHex)
				if err != nil {
					return nil, err
				}
				tx := &wire.MsgTx{}
				err = tx.Deserialize(bytes.NewReader(b))
				if err != nil {
					return nil, err
				}

				return tx, nil
			},
			p2wkhIns: 1,
			result:   147,
		},
		{
			// Spending P2SH-P2WPKH to two outputs. Example adapted from example in BIP-143.
			tx: func() (*wire.MsgTx, error) {
				txHex := "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"
				b, err := hex.DecodeString(txHex)
				if err != nil {
					return nil, err
				}
				tx := &wire.MsgTx{}
				err = tx.Deserialize(bytes.NewReader(b))
				if err != nil {
					return nil, err
				}

				return tx, nil
			},
			nestedP2wkhIns: 1,
			result:         170,
		},
		{
			// Spendin P2WPKH to on output, adding one change output. We reuse
			// the transaction spending to two outputs, removing one of them.
			tx: func() (*wire.MsgTx, error) {
				txHex := "01000000000101ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac0247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
				b, err := hex.DecodeString(txHex)
				if err != nil {
					return nil, err
				}
				tx := &wire.MsgTx{}
				err = tx.Deserialize(bytes.NewReader(b))
				if err != nil {
					return nil, err
				}

				// Only keep the first output.
				tx.TxOut = []*wire.TxOut{tx.TxOut[0]}
				return tx, nil
			},
			p2wkhIns: 1,
			change:   true,
			result:   144,
		},
	}

	for _, test := range tests {
		tx, err := test.tx()
		if err != nil {
			t.Fatalf("unable to get test tx: %v", err)
		}

		est := EstimateVirtualSize(0, test.p2wkhIns,
			test.nestedP2wkhIns, tx.TxOut, test.change)

		if est != test.result {
			t.Fatalf("expected estimated vsize to be %d, "+
				"instead got %d", test.result, est)
		}
	}
}
