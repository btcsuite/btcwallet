//go:build itest

package itest

import (
	"bytes"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/pkg/btcunit"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// txReaderFundingType is the address type the TxReader cases fund and spend.
// The script class the readers report for a wallet-owned output follows from
// it, so the funded type is never stated twice.
const txReaderFundingType = waddrmgr.WitnessPubKey

// txReaderScriptClass is the class every output paying a txReaderFundingType
// address belongs to.
const txReaderScriptClass = txscript.WitnessV0PubKeyHashTy

// unminedHeight is the height that stands for "no confirming block" in the
// range ListTxns takes. A negative start includes the unmined transactions
// before the confirmed ones, a negative end includes them after, and both
// negative asks for the unmined transactions alone.
const unminedHeight = -1

// Every transaction a case here can produce is one the wallet published, since
// no public wallet API records a transaction in any other state: Broadcast and
// the syncer both record published transactions, and nothing else writes a
// transaction's status. The pending state the public reader can report
// therefore has no fixture that stays within this task's public-API boundary,
// and the terminal states are SQL-only history that kvdb cannot represent.
const txReaderStatus = wallet.TxStatusPublished

// testListTxnsEmptyHistory verifies that a wallet holding no transactions
// reports none, whichever part of the range a caller asks about.
func testListTxnsEmptyHistory(h *bwtest.HarnessTest) {
	// An unfunded wallet has received nothing and published nothing, so
	// every range below covers a history that is genuinely empty rather
	// than merely filtered out.
	w, _ := h.NewWallet(bwtest.WalletFixture{AddrType: txReaderFundingType})

	_, tip := h.GetBestBlock()

	testCases := []struct {
		name        string
		startHeight int32
		endHeight   int32
	}{{
		name:        "unmined only",
		startHeight: unminedHeight,
		endHeight:   unminedHeight,
	}, {
		name:        "confirmed then unmined",
		startHeight: 0,
		endHeight:   unminedHeight,
	}, {
		name:        "unmined then confirmed",
		startHeight: unminedHeight,
		endHeight:   0,
	}, {
		name:        "whole chain",
		startHeight: 0,
		endHeight:   tip,
	}}

	for _, tc := range testCases {
		details, err := w.ListTxns(
			h.Context(), tc.startHeight, tc.endHeight,
		)
		require.NoError(h, err, "failed to list %s", tc.name)
		require.Empty(h, details, "%s reported a transaction", tc.name)
	}
}

// testGetTxMissing verifies that a transaction the wallet does not hold is
// reported as missing with a stable identity.
func testGetTxMissing(h *bwtest.HarnessTest) {
	// The wallet is funded so that it holds a transaction of its own. That
	// is what separates a miss here from the empty-history case: the reader
	// has something to find and still reports this hash as absent.
	w, _ := h.NewWallet(bwtest.WalletFixture{
		AddrType: txReaderFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
	})

	// The outpoint no wallet knows names a transaction that was never
	// mined and never authored here, so its hash is unknown too.
	_, err := w.GetTx(h.Context(), unknownOutpoint().Hash)
	require.ErrorIs(
		h, err, wallet.ErrTxNotFound,
		"unknown transaction not reported as missing",
	)
}

// testGetTxReceived verifies every field the reader reports for a confirmed
// transaction the wallet received rather than authored: it is credited what it
// was paid, it cannot state a fee it does not know, and it distinguishes its
// own output from the payer's change.
func testGetTxReceived(h *bwtest.HarnessTest) {
	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txReaderFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
	})

	tx := funding.Tx
	txid := tx.TxHash()

	var rawTx bytes.Buffer
	require.NoError(
		h, tx.Serialize(&rawTx), "failed to serialize funding transaction",
	)

	detail, err := w.GetTx(h.Context(), txid)
	require.NoError(h, err, "failed to get the funding transaction")

	require.Equal(h, txid, detail.Hash, "unexpected hash")
	require.Equal(h, rawTx.Bytes(), detail.RawTx, "unexpected raw transaction")
	require.Equal(h, txReaderStatus, detail.Status, "unexpected status")
	require.Empty(h, detail.Label, "unexpected label")
	require.False(h, detail.ReceivedTime.IsZero(), "no received time")

	// The wallet gained exactly what it was paid.
	require.Equal(h, btcutil.Amount(oneBTC), detail.Value, "unexpected value")

	// It cannot state the fee, because the inputs are the payer's and their
	// values are not in the wallet's records.
	require.Zero(h, detail.Fee, "unexpected fee")
	require.True(
		h, btcunit.ZeroSatPerVByte.Equal(detail.FeeRate),
		"unexpected fee rate %v", detail.FeeRate,
	)

	// Weight is a property of the transaction itself, so it is checked
	// against the consensus rule rather than a number that would drift from
	// it as the fixture changes.
	weight := blockchain.GetTransactionWeight(btcutil.NewTx(tx))
	require.Equal(
		h, btcunit.NewWeightUnit(uint64(weight)), detail.Weight,
		"unexpected weight",
	)

	// The funding block is the chain tip, so the transaction has exactly
	// one confirmation.
	require.Equal(
		h, funding.Block.BlockHash(), detail.Block.Hash,
		"unexpected block hash",
	)
	require.Equal(
		h, funding.BlockHeight, detail.Block.Height,
		"unexpected block height",
	)
	require.Equal(
		h, funding.Block.Header.Timestamp.Unix(), detail.Block.Timestamp,
		"unexpected block timestamp",
	)
	require.Equal(
		h, int32(1), detail.Confirmations, "unexpected confirmations",
	)

	// The wallet owns the outputs it was funded through and none of the
	// rest, which is what tells its coins apart from the payer's change.
	ours := make(map[uint32]struct{}, len(funding.WalletOutpoints))
	for _, outpoint := range funding.WalletOutpoints {
		ours[outpoint.Index] = struct{}{}
	}

	require.Len(h, detail.Outputs, len(tx.TxOut), "unexpected output count")

	for i, output := range detail.Outputs {
		require.Equal(h, i, output.Index, "unexpected output index")
		require.Equal(
			h, tx.TxOut[i].PkScript, output.PkScript,
			"unexpected output %d script", i,
		)
		require.Equal(
			h, btcutil.Amount(tx.TxOut[i].Value), output.Amount,
			"unexpected output %d amount", i,
		)

		// The class and the addresses are read back from the output's own
		// script rather than written down here, so both exported fields
		// are covered for the payer's change as well as for the wallet's
		// own coin, without this case pinning the format the miner
		// happens to pay itself in.
		wantType, wantAddrs, _, err := txscript.ExtractPkScriptAddrs(
			tx.TxOut[i].PkScript, h.NetParams(),
		)
		require.NoError(h, err, "failed to read output %d script", i)

		require.Equal(
			h, wantType, output.Type, "unexpected output %d type", i,
		)

		// Addresses are compared in their encoded form because that is
		// the identity a caller acts on, and it does not depend on which
		// concrete address type the extraction returned.
		wantEncoded := make([]string, 0, len(wantAddrs))
		for _, addr := range wantAddrs {
			wantEncoded = append(wantEncoded, addr.EncodeAddress())
		}

		gotEncoded := make([]string, 0, len(output.Addresses))
		for _, addr := range output.Addresses {
			gotEncoded = append(gotEncoded, addr.EncodeAddress())
		}

		require.Equal(
			h, wantEncoded, gotEncoded,
			"unexpected output %d addresses", i,
		)

		_, isOurs := ours[uint32(i)]
		require.Equal(
			h, isOurs, output.IsOurs, "unexpected output %d ownership", i,
		)

		// The wallet's own outputs additionally have to carry the class
		// its funded address type produces. The check above only says the
		// reader agrees with the script; this one says the fixture funded
		// the wallet the way it asked to.
		if !isOurs {
			continue
		}

		require.Equal(
			h, txReaderScriptClass, output.Type,
			"unexpected output %d type", i,
		)
	}

	// The payer funded the transaction, so none of its inputs are the
	// wallet's.
	require.Len(h, detail.PrevOuts, len(tx.TxIn), "unexpected input count")

	for i, prevOut := range detail.PrevOuts {
		require.Equal(
			h, tx.TxIn[i].PreviousOutPoint, prevOut.OutPoint,
			"unexpected input %d outpoint", i,
		)
		require.False(h, prevOut.IsOurs, "input %d claimed by the wallet", i)
	}
}

// testGetTxUnmined verifies every field the reader reports for a transaction
// the wallet published and the network has not yet confirmed: it has no block,
// no confirmations, and a fee the wallet can state because it owns every input.
func testGetTxUnmined(h *bwtest.HarnessTest) {
	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txReaderFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
		Unlocked: true,
	})

	spent := funding.WalletOutpoints[0]

	// Paying the wallet itself keeps both sides of the transaction in its
	// records, which is what lets it state the fee below.
	addr := h.NewWalletAddressOfType(w, txReaderFundingType)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err, "failed to create payment pkscript")

	tx := h.SignSpend(w, bwtest.SpendFixture{
		Inputs: []wire.OutPoint{spent},
		Outputs: []wire.TxOut{{
			Value:    oneBTC - spendFee,
			PkScript: pkScript,
		}},
	})

	txid := tx.TxHash()

	var rawTx bytes.Buffer
	require.NoError(h, tx.Serialize(&rawTx), "failed to serialize spend")

	err = w.Broadcast(h.Context(), tx, "")
	require.NoError(h, err, "failed to broadcast transaction")

	detail, err := w.GetTx(h.Context(), txid)
	require.NoError(h, err, "failed to get the published transaction")

	require.Equal(h, txid, detail.Hash, "unexpected hash")
	require.Equal(h, rawTx.Bytes(), detail.RawTx, "unexpected raw transaction")
	require.Equal(h, txReaderStatus, detail.Status, "unexpected status")
	require.Empty(h, detail.Label, "unexpected label")
	require.False(h, detail.ReceivedTime.IsZero(), "no received time")

	// Nothing confirms it yet.
	require.Nil(h, detail.Block, "unmined transaction reports a block")
	require.Zero(
		h, detail.Confirmations, "unmined transaction reports confirmations",
	)

	// The wallet paid itself, so the only value it gave up is the fee, and
	// every input being its own is what lets it name that fee at all.
	require.Equal(
		h, btcutil.Amount(-spendFee), detail.Value, "unexpected value",
	)
	require.Equal(h, btcutil.Amount(spendFee), detail.Fee, "unexpected fee")

	weight := btcunit.NewWeightUnit(uint64(
		blockchain.GetTransactionWeight(btcutil.NewTx(tx)),
	))
	require.Equal(h, weight, detail.Weight, "unexpected weight")

	feeRate := btcunit.CalcSatPerVByte(btcutil.Amount(spendFee), weight.ToVB())
	require.True(
		h, feeRate.Equal(detail.FeeRate),
		"unexpected fee rate %v", detail.FeeRate,
	)

	// Its single output pays the wallet.
	require.Len(h, detail.Outputs, 1, "unexpected output count")

	output := detail.Outputs[0]
	require.Equal(h, 0, output.Index, "unexpected output index")
	require.Equal(h, pkScript, output.PkScript, "unexpected output script")
	require.Equal(
		h, btcutil.Amount(oneBTC-spendFee), output.Amount,
		"unexpected output amount",
	)
	require.Equal(h, txReaderScriptClass, output.Type, "unexpected output type")
	require.Len(h, output.Addresses, 1, "unexpected output address count")
	require.Equal(
		h, addr.EncodeAddress(), output.Addresses[0].EncodeAddress(),
		"unexpected output address",
	)
	require.True(h, output.IsOurs, "wallet disowns its own output")

	// And its single input spends the coin the wallet was funded with.
	require.Len(h, detail.PrevOuts, 1, "unexpected input count")
	require.Equal(h, spent, detail.PrevOuts[0].OutPoint, "unexpected input")
	require.True(h, detail.PrevOuts[0].IsOurs, "wallet disowns its own input")

	// The harness requires an empty mempool once a case succeeds, so
	// confirm the transaction now that the unmined view has been read.
	h.MineBlockWithTx(tx)
}
