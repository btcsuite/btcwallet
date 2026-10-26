package bwtest

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// TestSyncHistoryBuildsValidSpends proves that the shared unsigned graph can
// become a valid spend chain, including both force-close ancestors and sweeps.
func TestSyncHistoryBuildsValidSpends(t *testing.T) {
	t.Parallel()

	// Arrange: use the existing smoke graph with known witness/Taproot keys.
	// Real preparation supplies the same ordinary script classes and actual
	// mined coinbases; this test isolates signatures and ancestry from mining.
	workload := NodeBenchmarkCases()[3]

	key, pub := btcec.PrivKeyFromBytes([]byte{2})
	defer key.Zero()

	params := &chaincfg.RegressionNetParams
	receive, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pub.SerializeCompressed()), params,
	)
	require.NoError(t, err)
	miner, minerKey, err := syncBenchmarkMinerAddress()
	require.NoError(t, err)

	defer minerKey.Zero()

	change, err := address.NewAddressTaproot(
		schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(pub)),
		params,
	)
	require.NoError(t, err)

	scripts := make([][]byte, workload.NumAddresses)
	for index := range scripts {
		scripts[index], err = txscript.PayToAddrScript(change)
		require.NoError(t, err)
	}

	scripts[0], err = txscript.PayToAddrScript(receive)
	require.NoError(t, err)
	minerScript, err := txscript.PayToAddrScript(miner)
	require.NoError(t, err)

	funding := wire.NewMsgTx(2)
	funding.AddTxIn(wire.NewTxIn(&wire.OutPoint{
		Index: ^uint32(0),
	}, []byte{1, 1}, nil))
	funding.AddTxOut(wire.NewTxOut(5_000_000_000, minerScript))

	// Act: replace synthetic funding and sign owned inputs through the same
	// narrow callback used by real Wallet preparation. Low-level signatures
	// here keep the test focused on graph assembly rather than Wallet setup.
	history, err := BuildSyncBenchmarkHistory(
		t.Context(), workload, scripts,
		[]*wire.MsgTx{funding}, func(_ context.Context, tx *wire.MsgTx,
			index int, output *wire.TxOut,
			hashes *txscript.TxSigHashes) (wire.TxWitness, error) {

			if txscript.IsPayToTaproot(output.PkScript) {
				return txscript.TaprootWitnessSignature(
					tx, hashes, index, output.Value, output.PkScript,
					txscript.SigHashDefault, key,
				)
			}

			return txscript.WitnessSignature(
				tx, hashes, index, output.Value, output.PkScript,
				txscript.SigHashAll, key, true,
			)
		},
	)
	require.NoError(t, err)

	// Assert: every input must already exist, conserve value and execute under
	// standard script flags. This includes the multi-parent mixed-input sweep.
	prevouts := txscript.NewMultiPrevOutFetcher(nil)
	prevouts.AddPrevOut(wire.OutPoint{Hash: funding.TxHash()}, funding.TxOut[0])

	contracts := make(map[string]bool)

	for _, tx := range history {
		hashes := txscript.NewTxSigHashes(tx, prevouts)

		var inputValue, outputValue int64
		for index, input := range tx.TxIn {
			output := prevouts.FetchPrevOutput(input.PreviousOutPoint)
			require.NotNil(t, output)
			engine, err := txscript.NewEngine(
				output.PkScript, tx, index,
				txscript.StandardVerifyFlags, nil, hashes, output.Value,
				prevouts,
			)
			require.NoError(t, err)
			require.NoError(t, engine.Execute())

			inputValue += output.Value
		}

		for index, output := range tx.TxOut {
			// Foreign outputs must retain distinct scripts; collapsing
			// them changes filter contents even if spends still validate.
			if txscript.IsPayToWitnessScriptHash(output.PkScript) {
				require.False(t, contracts[string(output.PkScript)])
				contracts[string(output.PkScript)] = true
			}

			outputValue += output.Value
			prevouts.AddPrevOut(wire.OutPoint{
				Hash: tx.TxHash(), Index: uint32(index),
			}, output)
		}

		require.GreaterOrEqual(t, inputValue, outputValue)
	}

	// Assert: restoring the old unsigned-input condition fails validation,
	// so a graph with correct counts alone cannot masquerade as chain-valid.
	unsigned := history[1].Copy()
	unsigned.TxIn[0].Witness = nil
	output := prevouts.FetchPrevOutput(unsigned.TxIn[0].PreviousOutPoint)
	engine, err := txscript.NewEngine(
		output.PkScript, unsigned, 0,
		txscript.StandardVerifyFlags, nil,
		txscript.NewTxSigHashes(unsigned, prevouts), output.Value, prevouts,
	)
	require.NoError(t, err)
	require.Error(t, engine.Execute())
}

// TestSyncBenchmarkCasesPlaceWalletMatches checks actual owned-match heights,
// distinguishing zero-history and empty-block controls from foreign parents.
func TestSyncBenchmarkCasesPlaceWalletMatches(t *testing.T) {
	t.Parallel()

	// Arrange: reference ownership comes from the unchanged lnd graph. Fixed
	// script bytes suffice because this test checks placement, not signing.
	workload := NodeBenchmarkCases()[0]

	scripts := make([][]byte, workload.NumAddresses)
	for i := range scripts {
		scripts[i] = append(
			[]byte{txscript.OP_0, txscript.OP_DATA_20},
			make([]byte, 20)...,
		)
	}

	records := workload.Batch(1, scripts).Transactions
	tests := []struct {
		id      string
		blocks  int32
		noise   int
		matches int
		first   int32
		last    int32
		step    int32
	}{
		{
			id:      "smoke",
			blocks:  10,
			noise:   6000,
			matches: 1,
			first:   5,
			last:    5,
			step:    1,
		},
		{
			id:     "empty",
			blocks: 1000,
		},
		{
			id:     "hits-0",
			blocks: 1000,
			noise:  6000,
		},
		{
			id:      "hits-1",
			blocks:  1000,
			noise:   6000,
			matches: 1,
			first:   500,
			last:    500,
			step:    1,
		},
		{
			id:      "small-node",
			blocks:  1000,
			noise:   6000,
			matches: 10,
			first:   100,
			last:    1000,
			step:    100,
		},
		{
			id:      "hits-100",
			blocks:  1000,
			noise:   6000,
			matches: 100,
			first:   10,
			last:    1000,
			step:    10,
		},
	}

	// Act: obtain only the public case factory's schedules. Expectations above
	// state the requested experiment independently of its grouping algorithm.
	cases := SyncBenchmarkCases()

	// Assert: count blocks with owned credits, rather than treating foreign
	// force-close parents as Wallet hits. Ordered heights preserve ancestry.
	require.Len(t, cases, len(tests))

	for i, test := range tests {
		scenario := cases[i]
		require.Equal(t, test.id, scenario.ID)
		require.Equal(t, test.blocks, scenario.Blocks)
		require.Equal(t, test.noise, scenario.BackgroundTransactions)

		if test.matches == 0 {
			require.Empty(t, scenario.HistoryBlocks)
			continue
		}

		require.Len(t, scenario.HistoryBlocks, 204)

		matched := make(map[int32]bool)

		var previous int32
		for index, height := range scenario.HistoryBlocks {
			require.GreaterOrEqual(t, height, previous)
			require.Positive(t, height)
			require.LessOrEqual(t, height, scenario.Blocks)

			if len(records[index].Credits) != 0 {
				matched[height] = true
			}

			previous = height
		}

		require.Len(t, matched, test.matches)

		for height := test.first; height <= test.last; height += test.step {
			require.True(t, matched[height])
		}
	}
}
