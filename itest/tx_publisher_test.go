//go:build itest

package itest

import (
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/stretchr/testify/require"
)

// txPublisherFundingType is the address type the TxPublisher cases fund and
// spend. Each case derives its key scope from this value, so the funded scope
// is never stated twice.
const txPublisherFundingType = waddrmgr.WitnessPubKey

// spendFee is the fee in satoshis that the publication fixtures leave behind.
// It clears the relay minimum by a wide margin while staying far below the
// backend's default maximum fee rate of 10,000 sat/vbyte, above which an
// otherwise valid transaction is rejected as paying absurdly much.
const spendFee = 10_000

// testCheckMempoolAcceptanceAccepted verifies that the acceptance check reports
// the chain backend's verdict for a spendable transaction, and that asking the
// question publishes nothing: the transaction reaches neither the network nor
// the wallet, and the wallet's coins are untouched.
func testCheckMempoolAcceptanceAccepted(h *bwtest.HarnessTest) {
	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txPublisherFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
		Unlocked: true,
	})

	// Pay the funded coin back to the wallet less the fee, which makes the
	// transaction unambiguously spendable and wallet-relevant on both its
	// input and its output side.
	addr := h.NewWalletAddressOfType(w, txPublisherFundingType)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err, "failed to create payment pkscript")

	tx := h.SignSpend(w, bwtest.SpendFixture{
		Inputs: []wire.OutPoint{funding.WalletOutpoints[0]},
		Outputs: []wire.TxOut{{
			Value:    oneBTC - spendFee,
			PkScript: pkScript,
		}},
	})

	// Snapshot the coins before asking, so the comparison afterwards proves
	// the check consumed nothing rather than merely that a coin still
	// exists.
	before, err := w.ListUnspent(h.Context(), wallet.UtxoQuery{
		MinConfs: 0,
		MaxConfs: maxConfsLimit,
	})
	require.NoError(h, err, "failed to list unspent")

	err = w.CheckMempoolAcceptance(h.Context(), tx)
	if h.Backend.SupportsMempoolAcceptance() {
		require.NoError(h, err, "spendable transaction not accepted")
	} else {
		require.ErrorIs(
			h, err, chain.ErrUnimplemented,
			"backend without a mempool returned a verdict",
		)
	}

	// Whatever the verdict, the check is an inspection. It must not reach
	// the network.
	h.AssertTxNotInMempool(tx.TxHash())

	// Nor may it record the transaction in the wallet.
	_, err = w.GetTx(h.Context(), tx.TxHash())
	require.ErrorIs(
		h, err, wallet.ErrTxNotFound,
		"acceptance check recorded the transaction",
	)

	after, err := w.ListUnspent(h.Context(), wallet.UtxoQuery{
		MinConfs: 0,
		MaxConfs: maxConfsLimit,
	})
	require.NoError(h, err, "failed to list unspent")
	require.ElementsMatch(
		h, before, after, "acceptance check changed the wallet's coins",
	)
}
