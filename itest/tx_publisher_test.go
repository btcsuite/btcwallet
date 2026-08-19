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

// testCheckMempoolAcceptanceRejected verifies that representative rejections
// come back as stable error identities rather than backend-specific text, and
// that a refused transaction is no more published than an accepted one.
func testCheckMempoolAcceptanceRejected(h *bwtest.HarnessTest) {
	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txPublisherFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
		Unlocked: true,
	})

	spent := funding.WalletOutpoints[0]

	addr := h.NewWalletAddressOfType(w, txPublisherFundingType)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err, "failed to create payment pkscript")

	// One satoshi under the threshold for this script is dust by the
	// relay's own definition, so the assertion tracks the policy instead of
	// a number that would drift from it.
	dust := int64(h.DustThreshold(pkScript)) - 1

	// A second output absorbs the rest of the coin, so the dust payment is
	// the only rule this transaction breaks. Paying the remainder as fee
	// instead would break the maximum fee rate as well and leave which
	// rejection the backend reports up to the order of its checks.
	dustTx := h.SignSpend(w, bwtest.SpendFixture{
		Inputs: []wire.OutPoint{spent},
		Outputs: []wire.TxOut{
			{
				Value:    dust,
				PkScript: pkScript,
			},
			{
				Value:    oneBTC - spendFee - dust,
				PkScript: pkScript,
			},
		},
	})

	// An input the chain has never seen cannot be signed by anyone, so this
	// transaction is built directly rather than through the wallet.
	unknown := unknownOutpoint()

	unknownInputTx := wire.NewMsgTx(wire.TxVersion)
	unknownInputTx.AddTxIn(wire.NewTxIn(&unknown, nil, nil))
	unknownInputTx.AddTxOut(&wire.TxOut{
		Value:    oneBTC - spendFee,
		PkScript: pkScript,
	})

	// Spending one coin twice is malformed before any policy applies, so
	// this transaction is likewise built directly: no signer would produce
	// it.
	duplicateInputTx := wire.NewMsgTx(wire.TxVersion)
	duplicateInputTx.AddTxIn(wire.NewTxIn(&spent, nil, nil))
	duplicateInputTx.AddTxIn(wire.NewTxIn(&spent, nil, nil))
	duplicateInputTx.AddTxOut(&wire.TxOut{
		Value:    oneBTC - spendFee,
		PkScript: pkScript,
	})

	rejections := []struct {
		name string
		tx   *wire.MsgTx
		want error
	}{
		{
			name: "dust payment",
			tx:   dustTx,
			want: chain.ErrDust,
		},
		{
			name: "unknown input",
			tx:   unknownInputTx,
			want: chain.ErrMissingInputs,
		},
		{
			name: "duplicate input",
			tx:   duplicateInputTx,
			want: chain.ErrDuplicateInput,
		},
	}

	for _, rejection := range rejections {
		want := rejection.want

		// A backend with no mempool judges none of these. It reports
		// the check as unimplemented instead of naming the rule that
		// was broken, which is just as definite an answer.
		if !h.Backend.SupportsMempoolAcceptance() {
			want = chain.ErrUnimplemented
		}

		err := w.CheckMempoolAcceptance(h.Context(), rejection.tx)
		require.ErrorIs(
			h, err, want, "unexpected verdict for %s",
			rejection.name,
		)

		h.AssertTxNotInMempool(rejection.tx.TxHash())
	}

	// A refused transaction leaves the coin it named still spendable.
	utxo, err := w.GetUtxo(h.Context(), spent)
	require.NoError(h, err, "rejected transaction consumed the coin")
	require.True(h, utxo.Spendable, "coin is no longer spendable")
}
