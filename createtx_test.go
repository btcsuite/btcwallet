package main

import (
	"reflect"
	"sort"
	"testing"

	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
)

func Test_addOutputs(t *testing.T) {
	msgtx := btcwire.NewMsgTx()
	pairs := map[string]btcutil.Amount{
		"1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX": 10,
		"12MzCDwodF9G1e7jfwLXfR164RNtx4BRVG": 1,
	}
	if err := addOutputs(msgtx, pairs); err != nil {
		t.Fatal(err)
	}
	if len(msgtx.TxOut) != 2 {
		t.Fatalf("Expected 2 outputs, found only %d", len(msgtx.TxOut))
	}
	values := []int{int(msgtx.TxOut[0].Value), int(msgtx.TxOut[1].Value)}
	sort.Ints(values)
	if !reflect.DeepEqual(values, []int{1, 10}) {
		t.Fatalf("Expected values to be [1, 10], got: %v", values)
	}
}
