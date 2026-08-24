//go:build itest

package itest

import (
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// txReaderFundingType is the address type the TxReader cases fund and spend.
// The script class the readers report for a wallet-owned output follows from
// it, so the funded type is never stated twice.
const txReaderFundingType = waddrmgr.WitnessPubKey

// unminedHeight is the height that stands for "no confirming block" in the
// range ListTxns takes. A negative start includes the unmined transactions
// before the confirmed ones, a negative end includes them after, and both
// negative asks for the unmined transactions alone.
const unminedHeight = -1

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
