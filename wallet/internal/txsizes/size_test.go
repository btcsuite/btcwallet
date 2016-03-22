package txsizes_test

import (
	"testing"

	"github.com/decred/dcrd/wire"
	. "github.com/decred/dcrwallet/wallet/internal/txsizes"
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
		0: {1, []int{}, false, 181},
		1: {1, []int{p2pkhScriptSize}, false, 217},
		2: {1, []int{}, true, 217},
		3: {1, []int{p2pkhScriptSize}, true, 253},
		4: {1, []int{p2shScriptSize}, false, 215},
		5: {1, []int{p2shScriptSize}, true, 251},

		6:  {2, []int{}, false, 347},
		7:  {2, []int{p2pkhScriptSize}, false, 383},
		8:  {2, []int{}, true, 383},
		9:  {2, []int{p2pkhScriptSize}, true, 419},
		10: {2, []int{p2shScriptSize}, false, 381},
		11: {2, []int{p2shScriptSize}, true, 417},

		// 0xfd is discriminant for 16-bit compact ints, compact int
		// total size increases from 1 byte to 3.
		12: {1, makeInts(p2pkhScriptSize, 0xfc), false, 9253},
		13: {1, makeInts(p2pkhScriptSize, 0xfd), false, 9253 + P2PKHOutputSize + 2},
		14: {1, makeInts(p2pkhScriptSize, 0xfc), true, 9253 + P2PKHOutputSize + 2},
		15: {0xfc, []int{}, false, 41847},
		16: {0xfd, []int{}, false, 41847 + RedeemP2PKHInputSize + 4}, // 4 not 2, varint encoded twice.
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
