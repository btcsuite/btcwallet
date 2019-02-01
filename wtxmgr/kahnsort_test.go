package wtxmgr_test

import (
	"math/rand"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// createTx is a helper method to create random transactions that spend
// particular inputs.
func createTx(t *testing.T, numOutputs int, inputs ...wire.OutPoint) *wire.MsgTx {
	t.Helper()

	tx := wire.NewMsgTx(1)
	if len(inputs) == 0 {
		tx.AddTxIn(&wire.TxIn{})
	} else {
		for _, input := range inputs {
			tx.AddTxIn(&wire.TxIn{PreviousOutPoint: input})
		}
	}
	for i := 0; i < numOutputs; i++ {
		var pkScript [32]byte
		if _, err := rand.Read(pkScript[:]); err != nil {
			t.Fatal(err)
		}

		tx.AddTxOut(&wire.TxOut{
			Value:    rand.Int63(),
			PkScript: pkScript[:],
		})
	}

	return tx
}

// getOutPoint returns the outpoint for the output with the given index in the
// transaction.
func getOutPoint(tx *wire.MsgTx, index uint32) wire.OutPoint {
	return wire.OutPoint{Hash: tx.TxHash(), Index: index}
}

// TestDependencySort ensures that transactions are topologically sorted by
// their dependency order under multiple scenarios. A transaction (a) can depend
// on another (b) as long as (a) spends an output created in (b).
func TestDependencySort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		// setup is in charge of setting the dependency graph and
		// returning the transactions in their expected sorted order.
		setup func(t *testing.T) []*wire.MsgTx
	}{
		{
			name: "single dependency chain",
			setup: func(t *testing.T) []*wire.MsgTx {
				// a -> b -> c
				a := createTx(t, 1)
				b := createTx(t, 1, getOutPoint(a, 0))
				c := createTx(t, 1, getOutPoint(b, 0))
				return []*wire.MsgTx{a, b, c}
			},
		},
		{
			name: "double dependency chain",
			setup: func(t *testing.T) []*wire.MsgTx {
				// a -> b
				// a -> c
				// c -> d
				// d -> b
				a := createTx(t, 2)
				c := createTx(t, 1, getOutPoint(a, 1))
				d := createTx(t, 1, getOutPoint(c, 0))
				b := createTx(t, 1, getOutPoint(a, 0), getOutPoint(d, 0))
				return []*wire.MsgTx{a, c, d, b}
			},
		},
		{
			name: "multi dependency chain",
			setup: func(t *testing.T) []*wire.MsgTx {
				// a -> e
				// a -> c
				// e -> c
				// c -> g
				// a -> b
				// g -> b
				// e -> f
				// c -> f
				// g -> f
				// b -> f
				// b -> d
				// f -> d
				a := createTx(t, 3)

				a0 := getOutPoint(a, 0)
				e := createTx(t, 2, a0)

				a1 := getOutPoint(a, 1)
				e0 := getOutPoint(e, 0)
				c := createTx(t, 2, a1, e0)

				c0 := getOutPoint(c, 0)
				g := createTx(t, 2, c0)

				a2 := getOutPoint(a, 2)
				g0 := getOutPoint(g, 0)
				b := createTx(t, 1, a2, g0)

				e1 := getOutPoint(e, 1)
				c1 := getOutPoint(c, 1)
				g1 := getOutPoint(g, 1)
				b0 := getOutPoint(b, 0)
				f := createTx(t, 1, e1, c1, g1, b0)

				f0 := getOutPoint(f, 0)
				d := createTx(t, 1, b0, f0)

				return []*wire.MsgTx{a, e, c, g, b, f, d}
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			exp := test.setup(t)

			txSet := make(map[chainhash.Hash]*wire.MsgTx, len(exp))
			for _, tx := range exp {
				txSet[tx.TxHash()] = tx
			}

			sortedTxs := wtxmgr.DependencySort(txSet)

			if !reflect.DeepEqual(sortedTxs, exp) {
				t.Fatalf("expected %v, got %v", exp, sortedTxs)
			}
		})
	}
}
