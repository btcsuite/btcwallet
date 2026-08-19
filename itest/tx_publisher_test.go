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

// testBroadcastTransaction verifies that a published transaction reaches the
// network and becomes visible through the wallet's own coin view, both while it
// waits in the mempool and once it is mined.
func testBroadcastTransaction(h *bwtest.HarnessTest) {
	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txPublisherFundingType,
		Amounts:  []btcutil.Amount{oneBTC, twoBTC},
		Unlocked: true,
	})

	// The second coin is never named by the transaction. It stays behind as
	// the control that tells "this coin was spent" apart from "the wallet
	// lost sight of its coins".
	spent, untouched := funding.WalletOutpoints[0], funding.WalletOutpoints[1]

	addr := h.NewWalletAddressOfType(w, txPublisherFundingType)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err, "failed to create payment pkscript")

	tx := h.SignSpend(w, bwtest.SpendFixture{
		Inputs: []wire.OutPoint{spent},
		Outputs: []wire.TxOut{{
			Value:    oneBTC - spendFee,
			PkScript: pkScript,
		}},
	})

	err = w.Broadcast(h.Context(), tx, "")
	require.NoError(h, err, "failed to broadcast transaction")

	txid := tx.TxHash()

	// The transaction reached the network.
	h.AssertTxInMempool(txid)

	// Before it is mined the wallet already reflects it: the coin it spends
	// is gone from the spendable set.
	_, err = w.GetUtxo(h.Context(), spent)
	require.ErrorIs(
		h, err, wallet.ErrUnknownOutput,
		"broadcast left the spent coin in the wallet",
	)

	// The output it creates is a wallet coin, and reports no confirmations
	// while it waits.
	created := wire.OutPoint{Hash: txid, Index: 0}

	unconfirmed, err := w.GetUtxo(h.Context(), created)
	require.NoError(
		h, err, "broadcast output did not become a wallet coin",
	)
	require.Equal(
		h, btcutil.Amount(oneBTC-spendFee), unconfirmed.Amount,
		"unexpected output amount",
	)
	require.Zero(
		h, unconfirmed.Confirmations,
		"unmined output reports confirmations",
	)

	// The wallet tracks the transaction it published.
	_, err = w.GetTx(h.Context(), txid)
	require.NoError(h, err, "broadcast transaction is not tracked")

	// The coin the transaction never named is untouched.
	_, err = w.GetUtxo(h.Context(), untouched)
	require.NoError(h, err, "broadcast consumed an unrelated coin")

	h.MineBlockWithTx(tx)

	// Confirmation is visible through the same coin view.
	confirmed, err := w.GetUtxo(h.Context(), created)
	require.NoError(h, err, "mined output is no longer a wallet coin")
	require.Equal(
		h, int32(1), confirmed.Confirmations,
		"mined output reports unexpected confirmations",
	)
	require.True(h, confirmed.Spendable, "mined output is not spendable")
}

// testBroadcastAlreadyKnown verifies that publishing a transaction the network
// already holds succeeds rather than failing, and publishes it only once. The
// wallet rebroadcasts its unmined transactions on every sync step, so a repeat
// that reported failure would make ordinary operation look broken.
func testBroadcastAlreadyKnown(h *bwtest.HarnessTest) {
	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txPublisherFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
		Unlocked: true,
	})

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

	txid := tx.TxHash()

	err = w.Broadcast(h.Context(), tx, "")
	require.NoError(h, err, "failed to broadcast transaction")

	h.AssertTxInMempool(txid)

	// Publishing the same transaction again succeeds.
	err = w.Broadcast(h.Context(), tx, "")
	require.NoError(
		h, err, "re-broadcast of a mempool transaction was refused",
	)

	// The repeat published nothing new: the network still holds one copy.
	mempool := h.AssertNumTxnsInMempool(1)
	require.Equal(
		h, txid, mempool[0], "unexpected transaction in the mempool",
	)

	// The wallet's coin view is unchanged by the repeat, so the second
	// attempt did not re-record or invalidate what the first claimed.
	created := wire.OutPoint{Hash: txid, Index: 0}

	utxo, err := w.GetUtxo(h.Context(), created)
	require.NoError(h, err, "re-broadcast dropped the wallet's output")
	require.Equal(
		h, btcutil.Amount(oneBTC-spendFee), utxo.Amount,
		"unexpected output amount",
	)

	h.MineBlockWithTx(tx)
}

// testBroadcastRejected verifies that a transaction the network refuses is
// reported with a stable identity and claims no coin: neither of its outputs
// becomes spendable, and the coin it named is still there afterwards.
func testBroadcastRejected(h *bwtest.HarnessTest) {
	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txPublisherFundingType,
		Amounts:  []btcutil.Amount{oneBTC},
		Unlocked: true,
	})

	spent := funding.WalletOutpoints[0]

	addr := h.NewWalletAddressOfType(w, txPublisherFundingType)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err, "failed to create payment pkscript")

	// A dust payment is a well formed transaction the network will not
	// relay, which is what this case needs: the wallet has every reason to
	// record it and only the backend's answer to stop it. The second output
	// absorbs the rest of the coin so dust is the only rule it breaks, and
	// both outputs pay the wallet, so a refusal that still left the wallet
	// holding coins would be visible below.
	//
	// A double spend of an unconfirmed transaction was tried as the subject
	// here and dropped: bitcoind enables full replace-by-fee by default, so
	// it judges the second transaction as a replacement bid, accepting it
	// when it pays more and reporting an insufficient fee when it pays
	// less, while btcd reports a mempool conflict. One condition with three
	// outcomes is not a contract a caller can branch on.
	dust := int64(h.DustThreshold(pkScript)) - 1

	tx := h.SignSpend(w, bwtest.SpendFixture{
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

	err = w.Broadcast(h.Context(), tx, "")

	require.ErrorIs(
		h, err, chain.ErrDust, "dust transaction was not refused",
	)

	// The refusal published nothing.
	h.AssertTxNotInMempool(tx.TxHash())

	// It claimed no coin either. Neither output became one, which both of
	// them would have, since both pay the wallet.
	//
	// Whether the transaction was recorded at all is deliberately not
	// asserted, because it differs by backend and the difference is not
	// this task's to define. A backend that answers the acceptance check
	// refuses before Broadcast records anything, while neutrino has no
	// answer to refuse with, so it records, publishes, and invalidates the
	// row once its peer rejects. Both leave the coin view below identical;
	// what the store keeps for an invalidated transaction belongs to the
	// invalidation task.
	for i := range tx.TxOut {
		_, err = w.GetUtxo(h.Context(), wire.OutPoint{
			Hash:  tx.TxHash(),
			Index: uint32(i),
		})
		require.ErrorIs(
			h, err, wallet.ErrUnknownOutput,
			"refused transaction left output %d in the wallet", i,
		)
	}

	// And the coin it named is untouched.
	utxo, err := w.GetUtxo(h.Context(), spent)
	require.NoError(h, err, "refused transaction consumed the coin")
	require.True(h, utxo.Spendable, "coin is no longer spendable")
}

// testCheckMempoolAcceptanceWalletState verifies the lifecycle gate on the
// acceptance check: it is unavailable before the wallet starts and after it
// stops, so a caller asking during startup or shutdown is told the wallet is
// not running rather than something about its transaction.
func testCheckMempoolAcceptanceWalletState(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{
		AddrType:  txPublisherFundingType,
		Unstarted: true,
	})

	// The gate refuses the transaction before anything looks at its
	// content, so this only has to be non-nil. It is never published.
	tx := wire.NewMsgTx(wire.TxVersion)

	err := w.CheckMempoolAcceptance(h.Context(), tx)
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"acceptance check before start not rejected",
	)

	require.NoError(h, w.Start(h.Context()), "failed to start wallet")

	// Stop the wallet, then deregister it so the harness does not drive a
	// stopped wallet during teardown.
	require.NoError(h, w.Stop(h.Context()), "failed to stop wallet")
	require.True(h, h.DeregisterWallet(w), "failed to deregister wallet")

	err = w.CheckMempoolAcceptance(h.Context(), tx)
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"acceptance check after stop not rejected",
	)
}

// testBroadcastWalletState verifies the same lifecycle gate on Broadcast, which
// enforces it separately from the acceptance check.
func testBroadcastWalletState(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{
		AddrType:  txPublisherFundingType,
		Unstarted: true,
	})

	// The gate refuses the transaction before anything looks at its
	// content, so this only has to be non-nil. It is never published.
	tx := wire.NewMsgTx(wire.TxVersion)

	err := w.Broadcast(h.Context(), tx, "")
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"broadcast before start not rejected",
	)

	require.NoError(h, w.Start(h.Context()), "failed to start wallet")

	// Stop the wallet, then deregister it so the harness does not drive a
	// stopped wallet during teardown.
	require.NoError(h, w.Stop(h.Context()), "failed to stop wallet")
	require.True(h, h.DeregisterWallet(w), "failed to deregister wallet")

	err = w.Broadcast(h.Context(), tx, "")
	require.ErrorIs(
		h, err, wallet.ErrStateForbidden,
		"broadcast after stop not rejected",
	)
}
