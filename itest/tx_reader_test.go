//go:build itest

package itest

import (
	"bytes"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
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

// testGetTxMined verifies that confirming a transaction adds the block that
// contains it and the confirmations it earned, and changes nothing else about
// how the wallet reports it.
func testGetTxMined(h *bwtest.HarnessTest) {
	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txReaderFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
		Unlocked: true,
	})

	addr := h.NewWalletAddressOfType(w, txReaderFundingType)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err, "failed to create payment pkscript")

	tx := h.SignSpend(w, bwtest.SpendFixture{
		Inputs: []wire.OutPoint{funding.WalletOutpoints[0]},
		Outputs: []wire.TxOut{{
			Value:    oneBTC - spendFee,
			PkScript: pkScript,
		}},
	})

	txid := tx.TxHash()

	err = w.Broadcast(h.Context(), tx, "")
	require.NoError(h, err, "failed to broadcast transaction")

	// Read the unconfirmed view first, so the comparison below is against
	// what confirmation actually changed rather than against a second
	// description of the same transaction.
	unmined, err := w.GetTx(h.Context(), txid)
	require.NoError(h, err, "failed to get the published transaction")

	block := h.MineBlockWithTx(tx)
	_, height := h.GetBestBlock()

	mined, err := w.GetTx(h.Context(), txid)
	require.NoError(h, err, "failed to get the confirmed transaction")

	// The block that confirmed it is now reported, and the mined block is
	// the chain tip, so the transaction has exactly one confirmation.
	require.Equal(
		h, block.BlockHash(), mined.Block.Hash, "unexpected block hash",
	)
	require.Equal(h, height, mined.Block.Height, "unexpected block height")
	require.Equal(
		h, block.Header.Timestamp.Unix(), mined.Block.Timestamp,
		"unexpected block timestamp",
	)
	require.Equal(h, int32(1), mined.Confirmations, "unexpected confirmations")

	// The wallet still reports a time at which it saw the transaction, but
	// which time that is does not survive confirmation on every backend, so
	// it is held out of the comparison below rather than asserted.
	//
	// kvdb rebuilds the stored record from the confirming notification,
	// through InsertConfirmedTx, so the record takes that notification's
	// timestamp. Its own confirmedBatchLabel keeps the stored label across
	// the same transition, but nothing does that for the received time. The
	// SQL backends keep the time the wallet first saw the transaction.
	// Which of the two the public reader should report is a question for
	// the store, not for this case to settle by picking one.
	require.False(h, mined.ReceivedTime.IsZero(), "no received time")

	// Nothing else about the transaction changed. Comparing the whole
	// result with only the confirmation facts removed leaves no field that
	// could have been quietly rewritten.
	unconfirmed := *mined
	unconfirmed.Block = nil
	unconfirmed.Confirmations = 0

	// Carried over rather than compared: this is the exemption explained
	// above, not an assertion that the two times agree.
	unconfirmed.ReceivedTime = unmined.ReceivedTime

	require.Equal(
		h, unmined, &unconfirmed,
		"confirmation altered the transaction beyond its block",
	)
}

// testGetTxConfirmations verifies that the confirmation count a transaction
// reports follows the chain tip as blocks accumulate above it.
func testGetTxConfirmations(h *bwtest.HarnessTest) {
	// blocksMined is how far the chain advances past the funding block. Any
	// count above zero works; two makes an off-by-one visible.
	const blocksMined = 2

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txReaderFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
	})

	txid := funding.Tx.TxHash()

	// The funding block is the tip, so the transaction in it is confirmed
	// exactly once.
	detail, err := w.GetTx(h.Context(), txid)
	require.NoError(h, err, "failed to get the funding transaction")
	require.Equal(
		h, int32(1), detail.Confirmations, "unexpected initial confirmations",
	)

	h.MineEmptyBlocks(blocksMined)

	// Each block mined above it counts, and the block containing it still
	// counts as the first.
	detail, err = w.GetTx(h.Context(), txid)
	require.NoError(h, err, "failed to get the funding transaction")
	require.Equal(
		h, int32(1+blocksMined), detail.Confirmations,
		"confirmations did not follow the chain tip",
	)

	// The block it sits in has not moved.
	require.Equal(
		h, funding.BlockHeight, detail.Block.Height, "unexpected block height",
	)
}

// txReaderHistory is the transaction history the range, agreement and reload
// cases all read: the transaction that funded the wallet, one spend confirmed
// in a block of its own, and one spend left waiting in the mempool.
//
// It holds only what newTxReaderHistory arranged. Every read under test, and
// every assertion about it, stays in the case.
type txReaderHistory struct {
	// wallet is the funded, unlocked wallet holding the history.
	wallet *wallet.Wallet

	// fundingTx paid the wallet its coins, and fundHeight is the block
	// that confirmed it.
	fundingTx  *wire.MsgTx
	fundHeight int32

	// minedTx spends the first coin and was confirmed on its own at
	// minedHeight, which is the chain tip.
	minedTx     *wire.MsgTx
	minedHeight int32

	// unminedTx spends the second coin and is still in the mempool. A case
	// that finishes with the history has to confirm it, because the
	// harness requires an empty mempool on success.
	unminedTx *wire.MsgTx
}

// txids returns the hashes of every transaction the wallet holds, oldest
// first. Cases derive their expected transaction count from its length rather
// than restating a number the fixture already determines.
func (hist txReaderHistory) txids() []chainhash.Hash {
	return []chainhash.Hash{
		hist.fundingTx.TxHash(),
		hist.minedTx.TxHash(),
		hist.unminedTx.TxHash(),
	}
}

// newTxReaderHistory funds a wallet and leaves it holding one confirmed spend
// and one unconfirmed one.
//
// Each spend is confirmed in a block of its own, so every block holds exactly
// one wallet transaction and the order a reader reports does not depend on how
// a backend arranges transactions within a block.
func newTxReaderHistory(h *bwtest.HarnessTest) txReaderHistory {
	h.Helper()

	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txReaderFundingType,
		Amounts:  []btcutil.Amount{oneBTC, twoBTC},
		Unlocked: true,
	})

	// Both spends pay the wallet, which keeps every transaction in the
	// history wallet-relevant on both sides.
	addr := h.NewWalletAddressOfType(w, txReaderFundingType)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err, "failed to create payment pkscript")

	minedTx := h.SignSpend(w, bwtest.SpendFixture{
		Inputs: []wire.OutPoint{funding.WalletOutpoints[0]},
		Outputs: []wire.TxOut{{
			Value:    oneBTC - spendFee,
			PkScript: pkScript,
		}},
	})

	err = w.Broadcast(h.Context(), minedTx, "")
	require.NoError(h, err, "failed to broadcast the transaction to mine")

	h.MineBlockWithTx(minedTx)

	_, minedHeight := h.GetBestBlock()

	// The second coin stays in the mempool, so the unmined leg of a range
	// has something to report.
	unminedTx := h.SignSpend(w, bwtest.SpendFixture{
		Inputs: []wire.OutPoint{funding.WalletOutpoints[1]},
		Outputs: []wire.TxOut{{
			Value:    twoBTC - spendFee,
			PkScript: pkScript,
		}},
	})

	err = w.Broadcast(h.Context(), unminedTx, "")
	require.NoError(h, err, "failed to broadcast the unmined transaction")

	return txReaderHistory{
		wallet:      w,
		fundingTx:   funding.Tx,
		fundHeight:  funding.BlockHeight,
		minedTx:     minedTx,
		minedHeight: minedHeight,
		unminedTx:   unminedTx,
	}
}

// testListTxnsBoundaries verifies which transactions each supported range
// selects and the order it reports them in, at the edges of a history whose
// every block holds exactly one wallet transaction.
func testListTxnsBoundaries(h *bwtest.HarnessTest) {
	hist := newTxReaderHistory(h)

	w := hist.wallet
	fundHeight, spendHeight := hist.fundHeight, hist.minedHeight

	txids := hist.txids()
	fundingTxid, minedTxid, unminedTxid := txids[0], txids[1], txids[2]

	// The row below the funded block subtracts one from its height, and a
	// negative height is the unmined sentinel rather than a block. The
	// miner mines well past genesis before any case runs, so this holds,
	// but a fixture that ever funded at height zero would silently turn
	// that row into a different query instead of failing.
	require.Positive(
		h, fundHeight,
		"fixture funded too close to genesis for the boundary rows",
	)

	testCases := []struct {
		name        string
		startHeight int32
		endHeight   int32
		want        []chainhash.Hash
	}{{
		name:        "unmined only",
		startHeight: unminedHeight,
		endHeight:   unminedHeight,
		want:        []chainhash.Hash{unminedTxid},
	}, {
		name:        "confirmed then unmined",
		startHeight: 0,
		endHeight:   unminedHeight,
		want: []chainhash.Hash{
			fundingTxid, minedTxid, unminedTxid,
		},
	}, {
		name:        "unmined then confirmed in reverse",
		startHeight: unminedHeight,
		endHeight:   0,
		want: []chainhash.Hash{
			unminedTxid, minedTxid, fundingTxid,
		},
	}, {
		name:        "block below the first transaction",
		startHeight: fundHeight - 1,
		endHeight:   fundHeight - 1,
		want:        []chainhash.Hash{},
	}, {
		name:        "first block holding a transaction",
		startHeight: fundHeight,
		endHeight:   fundHeight,
		want:        []chainhash.Hash{fundingTxid},
	}, {
		name:        "chain tip",
		startHeight: spendHeight,
		endHeight:   spendHeight,
		want:        []chainhash.Hash{minedTxid},
	}, {
		name:        "block above the chain tip",
		startHeight: spendHeight + 1,
		endHeight:   spendHeight + 1,
		want:        []chainhash.Hash{},
	}, {
		name:        "whole confirmed history",
		startHeight: fundHeight,
		endHeight:   spendHeight,
		want:        []chainhash.Hash{fundingTxid, minedTxid},
	}, {
		name:        "whole confirmed history reversed",
		startHeight: spendHeight,
		endHeight:   fundHeight,
		want:        []chainhash.Hash{minedTxid, fundingTxid},
	}}

	for _, tc := range testCases {
		details, err := w.ListTxns(
			h.Context(), tc.startHeight, tc.endHeight,
		)
		require.NoError(h, err, "failed to list %s", tc.name)

		got := make([]chainhash.Hash, 0, len(details))
		for _, detail := range details {
			got = append(got, detail.Hash)
		}

		require.Equal(h, tc.want, got, "unexpected result for %s", tc.name)
	}

	// The harness requires an empty mempool once a case succeeds.
	h.MineBlockWithTx(hist.unminedTx)
}

// testListTxnsAgreesWithGetTx verifies that the two readers describe the same
// transaction identically, so a caller's choice between them cannot change what
// it learns.
func testListTxnsAgreesWithGetTx(h *bwtest.HarnessTest) {
	hist := newTxReaderHistory(h)

	w := hist.wallet

	// This range covers the whole history, the transaction still waiting in
	// the mempool included, so the comparison covers a result with no block
	// as well as confirmed ones.
	listed, err := w.ListTxns(h.Context(), unminedHeight, 0)
	require.NoError(h, err, "failed to list transactions")
	require.Len(
		h, listed, len(hist.txids()), "unexpected transaction count",
	)

	for _, listedDetail := range listed {
		point, err := w.GetTx(h.Context(), listedDetail.Hash)
		require.NoError(h, err, "failed to get %v", listedDetail.Hash)

		require.Equal(
			h, listedDetail, point,
			"the readers disagree about %v", listedDetail.Hash,
		)
	}

	// The harness requires an empty mempool once a case succeeds.
	h.MineBlockWithTx(hist.unminedTx)
}

// testTxReaderDurableReopen verifies that the transaction view a wallet
// reports survives closing it and opening the same durable wallet again, which
// is the lifecycle a stored history has to cross to be worth storing.
func testTxReaderDurableReopen(h *bwtest.HarnessTest) {
	// The history includes a transaction still in the mempool because that
	// is the state a reopen could most easily lose: it is held by the
	// wallet alone, with no block to recover it from.
	hist := newTxReaderHistory(h)

	w := hist.wallet

	// Compare whole results rather than chosen fields, so nothing the
	// reopen lost can hide in a field the comparison skipped.
	before, err := w.ListTxns(h.Context(), unminedHeight, 0)
	require.NoError(h, err, "failed to list transactions")

	// Everything below compares the history against itself, which an empty
	// history satisfies without proving anything survived. Require the
	// fixture's transactions to be there before making that comparison the
	// subject.
	require.Len(
		h, before, len(hist.txids()), "unexpected transaction count",
	)

	points := make([]*wallet.TxDetail, 0, len(before))
	for _, detail := range before {
		point, err := w.GetTx(h.Context(), detail.Hash)
		require.NoError(h, err, "failed to get %v", detail.Hash)

		points = append(points, point)
	}

	w = h.ReloadWallet(w)

	// No readiness check follows the reopen on purpose. Nothing is mined
	// across it and the synced tip is durable, so a wallet that has
	// finished starting already reports the same tip and the same
	// confirmations. Waiting here would hide it if that were ever untrue.
	after, err := w.ListTxns(h.Context(), unminedHeight, 0)
	require.NoError(h, err, "failed to list transactions after reopen")
	require.Equal(
		h, before, after, "the reopened wallet lists a different history",
	)

	for _, point := range points {
		reopened, err := w.GetTx(h.Context(), point.Hash)
		require.NoError(h, err, "failed to get %v after reopen", point.Hash)

		require.Equal(
			h, point, reopened,
			"the reopened wallet describes %v differently", point.Hash,
		)
	}

	// The harness requires an empty mempool once a case succeeds.
	h.MineBlockWithTx(hist.unminedTx)
}
