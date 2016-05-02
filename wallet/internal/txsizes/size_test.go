package txsizes_test

import (
	"testing"

	"github.com/jadeblaquiere/ctcd/wire"
	. "github.com/jadeblaquiere/ctcwallet/wallet/internal/txsizes"
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
