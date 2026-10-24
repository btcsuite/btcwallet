package bwtest

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// TestListUnspentWorkloadModelsReference checks replicated graphs against the
// observed one-deposit endpoint, including cross-unit outpoint separation.
func TestListUnspentWorkloadModelsReference(t *testing.T) {
	t.Parallel()

	// Arrange: expected endpoints are multiples of the saved lnd census;
	// the shared cases provide only inputs, never the expected graph totals.
	tests := []struct {
		funding      uint32
		transactions int
		utxos        int
		value        int64
	}{
		{
			funding:      1,
			transactions: 204,
			utxos:        101,
			value:        89_636_054,
		},
		{
			funding:      10,
			transactions: 2_040,
			utxos:        1_010,
			value:        896_360_540,
		},
		{
			funding:      100,
			transactions: 20_400,
			utxos:        10_100,
			value:        8_963_605_400,
		},
	}
	for index, test := range tests {
		// Arrange: supply distinct scripts in receiving/change/closing
		// order. Native seeders derive real addresses; this isolates
		// transaction ownership and graph links.
		workload := ListUnspentCases()[index]

		scripts := make([][]byte, workload.Addresses)
		for i := range scripts {
			material := []byte(fmt.Sprintf("reference-script/%d", i))

			hash := chainhash.DoubleHashH(material)
			if i < int(test.funding) {
				scripts[i] = append(
					[]byte{txscript.OP_0, txscript.OP_DATA_20},
					hash[:20]...,
				)
			} else {
				scripts[i] = append(
					[]byte{txscript.OP_1, txscript.OP_DATA_32},
					hash[:]...,
				)
			}
		}

		// Act: consume inputs before recording outputs to reconstruct
		// the graph. Tracking foreign outputs too detects missing
		// parents and repeated contract spends behind the totals.
		batch := workload.Batch(1, scripts)
		outputs := make(map[wire.OutPoint]*wire.TxOut)
		spent := make(map[wire.OutPoint]struct{})
		owned := make(map[wire.OutPoint]*wire.TxOut)

		externalRoots := 0
		for _, record := range batch.Transactions {
			for _, input := range record.Tx.TxIn {
				point := input.PreviousOutPoint
				if _, known := outputs[point]; !known {
					externalRoots++
				}

				_, duplicate := spent[point]
				require.False(t, duplicate)

				spent[point] = struct{}{}
				delete(owned, point)
			}

			hash := record.Tx.TxHash()
			for index, output := range record.Tx.TxOut {
				point := wire.OutPoint{
					Hash:  hash,
					Index: uint32(index),
				}
				_, duplicate := outputs[point]
				require.False(t, duplicate)

				outputs[point] = output
				if _, credit := record.Credits[uint32(index)]; credit {
					require.NotNil(t, record.Block)

					owned[point] = output
				}
			}
		}

		// Assert: scale the observed endpoint by deposits. Unique
		// outpoints ensure totals cannot pass by replaying one unit
		// or unintentionally consuming another unit's inputs.
		require.EqualValues(t, test.funding, externalRoots)
		require.Len(t, batch.Transactions, test.transactions)
		require.Len(t, owned, test.utxos)

		var value int64
		for _, output := range owned {
			require.True(t, txscript.IsPayToTaproot(output.PkScript))
			value += output.Value
		}

		require.Equal(t, test.value, value)
	}
}
