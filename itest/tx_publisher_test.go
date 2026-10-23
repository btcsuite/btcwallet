//go:build itest

package itest

import (
	"bytes"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/blockchain"
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

// testBroadcastTransaction verifies that an automatically authored spend and
// its change reach the network, confirm, and survive a fresh Manager loading
// the same database through the public transaction and UTXO views.
func testBroadcastTransaction(h *bwtest.HarnessTest) {
	// Arrange: Two distinct coins make largest-first selection deterministic
	// while retaining an untouched control. Funding already crosses the
	// harness's exact block synchronization boundary.
	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txPublisherFundingType,
		Amounts:  []btcutil.Amount{oneBTC, twoBTC},
		Unlocked: true,
	})

	untouched, spent := funding.WalletOutpoints[0], funding.WalletOutpoints[1]
	prevOut := funding.Tx.TxOut[spent.Index]

	// Preserve the untouched coin before publication so whole-list checks
	// detect unrelated changes as well as replacement of the selected input.
	control, err := w.GetUtxo(h.Context(), untouched)
	require.NoError(h, err, "failed to read control coin")

	// Derive one funded scope for both coin selection and change, keeping
	// the signing and change handoffs tied to this Wallet fixture.
	scope, err := txPublisherFundingType.KeyScope()
	require.NoError(h, err, "failed to resolve funding scope")

	account := &wallet.ScopedAccount{
		AccountName: waddrmgr.DefaultAccountName,
		KeyScope:    scope,
	}

	// A fixed foreign witness program keeps the recipient separate from
	// wallet change without introducing another Wallet or signing fixture.
	const witnessProgramSize = 20

	addr, err := address.NewAddressWitnessPubKeyHash(
		make([]byte, witnessProgramSize), h.NetParams(),
	)
	require.NoError(h, err, "failed to create recipient address")

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err, "failed to create payment pkscript")

	// Act: Ask the public author to select the funded input and allocate
	// change for this payment through the normal account policy.
	authored, err := w.CreateTransaction(h.Context(), &wallet.TxIntent{
		Outputs: []wire.TxOut{{
			Value:    halfBTC,
			PkScript: pkScript,
		}},
		Inputs: &wallet.InputsPolicy{
			Strategy: wallet.CoinSelectionLargest,
			MinConfs: 1,
			Source:   account,
		},
		ChangeSource: account,
		FeeRate:      relayFeeRate,
	})
	require.NoError(h, err, "failed to author spend")

	tx := authored.Tx

	// Assert: The funding transaction is an independent oracle for the
	// selected coin and signing metadata; the recipient and change must
	// conserve that input with a positive fee.
	require.Len(h, tx.TxIn, 1, "unexpected input count")
	require.Equal(h, spent, tx.TxIn[0].PreviousOutPoint)
	require.Equal(h, btcutil.Amount(prevOut.Value), authored.TotalInput)
	require.Equal(h, [][]byte{prevOut.PkScript}, authored.PrevScripts)
	require.Equal(
		h, []btcutil.Amount{btcutil.Amount(prevOut.Value)},
		authored.PrevInputValues,
	)
	require.Len(h, tx.TxOut, 2, "expected recipient and change")
	require.GreaterOrEqual(h, authored.ChangeIndex, 0, "no change output")
	require.Less(h, authored.ChangeIndex, len(tx.TxOut))
	paid := tx.TxOut[1-authored.ChangeIndex]
	require.Equal(h, int64(halfBTC), paid.Value)
	require.Equal(h, pkScript, paid.PkScript)

	change := tx.TxOut[authored.ChangeIndex]
	fee := btcutil.Amount(prevOut.Value - paid.Value - change.Value)
	require.Positive(h, fee, "authored spend pays no fee")

	// Act: Sign the authored input using its returned metadata and attach
	// the public signer's stacks to that same transaction.
	fetcher := txscript.NewCannedPrevOutputFetcher(
		prevOut.PkScript, prevOut.Value,
	)
	hashes := txscript.NewTxSigHashes(tx, fetcher)
	unlocking, err := w.ComputeUnlockingScript(
		h.Context(), &wallet.UnlockingScriptParams{
			Tx: tx,
			Output: wire.NewTxOut(
				int64(authored.PrevInputValues[0]),
				authored.PrevScripts[0],
			),
			SigHashes: hashes,
			HashType:  txscript.SigHashAll,
		},
	)
	require.NoError(h, err, "failed to sign authored spend")

	tx.TxIn[0].Witness = unlocking.Witness
	tx.TxIn[0].SignatureScript = unlocking.SigScript

	// Assert: Verify sanity and execute the input against the mined funding
	// output so incorrect authoring or unlocking data cannot validate itself.
	require.NoError(h, blockchain.CheckTransactionSanity(btcutil.NewTx(tx)))
	engine, err := txscript.NewEngine(
		prevOut.PkScript, tx, 0, txscript.StandardVerifyFlags,
		nil, hashes, prevOut.Value, fetcher,
	)
	require.NoError(h, err, "failed to construct input verifier")
	require.NoError(h, engine.Execute(), "authored input script is invalid")

	// Capture the signed bytes independently of the reader so subsequent
	// public views must return the exact transaction sent to the network.
	var rawTx bytes.Buffer
	require.NoError(h, tx.Serialize(&rawTx), "failed to serialize spend")

	// Act: Publish the signed authored spend. Only relay to the external
	// miner is asynchronous; Broadcast already commits the Wallet views.
	err = w.Broadcast(h.Context(), tx, "")
	require.NoError(h, err, "failed to broadcast transaction")

	txid := tx.TxHash()
	h.AssertTxInMempool(txid)

	// Assert: The unmined reader describes this exact signed spend, and owns
	// its change rather than the foreign payment.
	unmined, err := w.GetTx(h.Context(), txid)
	require.NoError(h, err, "failed to read published spend")
	require.Equal(h, txid, unmined.Hash)
	require.Equal(h, rawTx.Bytes(), unmined.RawTx)
	require.Nil(h, unmined.Block)
	require.Zero(h, unmined.Confirmations)
	require.Equal(h, fee, unmined.Fee)
	require.Equal(h, -btcutil.Amount(halfBTC)-fee, unmined.Value)
	require.Len(h, unmined.PrevOuts, 1)
	require.Equal(h, spent, unmined.PrevOuts[0].OutPoint)
	require.True(h, unmined.PrevOuts[0].IsOurs)
	require.Len(h, unmined.Outputs, len(tx.TxOut))
	changeDetail := unmined.Outputs[authored.ChangeIndex]
	require.True(h, changeDetail.IsOurs, "reader disowns authored change")
	require.False(h, unmined.Outputs[1-authored.ChangeIndex].IsOurs)
	require.Equal(h, change.PkScript, changeDetail.PkScript)
	require.Equal(h, btcutil.Amount(change.Value), changeDetail.Amount)

	// The complete coin view replaces only the selected input with change;
	// the control proves publication did not simply lose the funding coins.
	_, err = w.GetUtxo(h.Context(), spent)
	require.ErrorIs(
		h, err, wallet.ErrUnknownOutput,
		"broadcast left the spent coin in the wallet",
	)

	created := wire.OutPoint{Hash: txid, Index: uint32(authored.ChangeIndex)}

	unconfirmed, err := w.GetUtxo(h.Context(), created)
	require.NoError(h, err, "authored change did not become a wallet coin")
	require.Equal(h, changeDetail.Amount, unconfirmed.Amount)
	require.Equal(h, changeDetail.PkScript, unconfirmed.PkScript)
	require.Zero(h, unconfirmed.Confirmations)

	query := wallet.UtxoQuery{MinConfs: 0, MaxConfs: maxConfsLimit}
	coins, err := w.ListUnspent(h.Context(), query)
	require.NoError(h, err, "failed to list published spend's coins")
	require.ElementsMatch(h, []*wallet.Utxo{control, unconfirmed}, coins)

	// Act: Mine the spend through the harness's exact hash/height boundary.
	// Reads below must succeed directly once that boundary returns.
	block := h.MineBlockWithTx(tx)
	_, height := h.GetBestBlock()

	// Assert: The reader and coin view agree on confirmed, spendable change.
	mined, err := w.GetTx(h.Context(), txid)
	require.NoError(h, err, "failed to read confirmed spend")
	require.Equal(h, rawTx.Bytes(), mined.RawTx)
	require.Equal(h, &wallet.BlockDetails{
		Hash:      block.BlockHash(),
		Height:    height,
		Timestamp: block.Header.Timestamp.Unix(),
	}, mined.Block)
	require.Equal(h, int32(1), mined.Confirmations)
	require.Equal(h, changeDetail, mined.Outputs[authored.ChangeIndex])

	confirmed, err := w.GetUtxo(h.Context(), created)
	require.NoError(h, err, "confirmed change is missing")
	require.Equal(h, changeDetail.Amount, confirmed.Amount)
	require.Equal(h, changeDetail.PkScript, confirmed.PkScript)
	require.Equal(h, int32(1), confirmed.Confirmations)
	require.True(h, confirmed.Spendable, "confirmed change is not spendable")

	// Only one block passed, so the untouched funding coin gains exactly one
	// confirmation. Compare the full list to exclude resurrected spent coins.
	control.Confirmations++
	coins, err = w.ListUnspent(h.Context(), query)
	require.NoError(h, err, "failed to list confirmed spend's coins")
	require.ElementsMatch(h, []*wallet.Utxo{control, confirmed}, coins)

	// Act: ReloadWallet stops and joins the old Manager and starts a fresh
	// one over this database, transferring harness cleanup to its Wallet.
	w = h.ReloadWallet(w)

	// Reload returns a locked Wallet. Restore the fixture's unlock state
	// because kvdb's public Spendable result also reflects that runtime state.
	h.UnlockWallet(w)

	// Assert: Compare whole public results immediately. No block was mined
	// across reload, so polling would conceal lost durable transaction data.
	reloaded, err := w.GetTx(h.Context(), txid)
	require.NoError(h, err, "failed to read spend after reload")
	require.Equal(h, mined, reloaded, "reload changed the transaction view")
	changeAfter, err := w.GetUtxo(h.Context(), created)
	require.NoError(h, err, "failed to read change after reload")
	require.Equal(h, confirmed, changeAfter, "reload changed the change coin")
	coinsAfter, err := w.ListUnspent(h.Context(), query)
	require.NoError(h, err, "failed to list coins after reload")
	require.Equal(
		h, coins, coinsAfter, "reload changed the complete coin view",
	)
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

	// It left no record either. A backend that answers the acceptance check
	// refuses before Broadcast records anything, while neutrino has no
	// answer to refuse with, so it records, publishes, and removes the
	// branch once its peer rejects. Both end with the wallet holding no row.
	_, err = w.GetTx(h.Context(), tx.TxHash())
	require.ErrorIs(
		h, err, wallet.ErrTxNotFound,
		"refused transaction is still recorded",
	)

	// It claimed no coin either. Neither output became one, which both of
	// them would have, since both pay the wallet.
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

// testCheckMempoolAcceptanceWalletState verifies rejection of a retained
// Wallet pointer after its owning runtime has stopped.
func testCheckMempoolAcceptanceWalletState(h *bwtest.HarnessTest) {
	// Retain the Manager so this case can stop its Wallet directly.
	manager := h.NewWalletManager()
	_, err := manager.Start(h.Context())
	require.NoError(h, err, "failed to start wallet manager")

	w, err := manager.Create(h.TestWalletParams())
	require.NoError(h, err, "failed to create wallet")

	require.NoError(h, manager.Stop(), "failed to stop wallet manager")

	// The gate refuses the transaction before anything looks at its
	// content, so this only has to be non-nil. It is never published.
	tx := wire.NewMsgTx(wire.TxVersion)

	err = w.CheckMempoolAcceptance(h.Context(), tx)

	require.ErrorIs(
		h, err, wallet.ErrWalletStopped,
		"acceptance check after stop not rejected",
	)
}

// testBroadcastWalletState verifies the public operation rejects a retained
// Wallet pointer after its owning runtime has stopped.
func testBroadcastWalletState(h *bwtest.HarnessTest) {
	// Retain the Manager so this case can stop its Wallet directly.
	manager := h.NewWalletManager()
	_, err := manager.Start(h.Context())
	require.NoError(h, err, "failed to start wallet manager")

	w, err := manager.Create(h.TestWalletParams())
	require.NoError(h, err, "failed to create wallet")

	require.NoError(h, manager.Stop(), "failed to stop wallet manager")

	// The gate refuses the transaction before anything looks at its
	// content, so this only has to be non-nil. It is never published.
	tx := wire.NewMsgTx(wire.TxVersion)

	err = w.Broadcast(h.Context(), tx, "")

	require.ErrorIs(
		h, err, wallet.ErrWalletStopped,
		"broadcast after stop not rejected",
	)
}
