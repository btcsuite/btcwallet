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

// testBroadcastTransaction checks a spend that the Wallet creates and signs.
// It checks transaction and change data after broadcast, confirmation, and
// a restart with a new Manager.
func testBroadcastTransaction(h *bwtest.HarnessTest) {
	// Arrange: Use different amounts so selection always spends the larger
	// coin. Use the other coin to detect unexpected changes. The harness waits
	// for the Wallet to reach the exact block that contains the coins.
	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txPublisherFundingType,
		Amounts:  []btcutil.Amount{oneBTC, twoBTC},
		Unlocked: true,
	})

	untouched, spent := funding.WalletOutpoints[0], funding.WalletOutpoints[1]
	prevOut := funding.Tx.TxOut[spent.Index]

	// Save the other coin before broadcast. The list of coins must show
	// that this coin does not change.
	control, err := w.GetUtxo(h.Context(), untouched)
	require.NoError(h, err, "failed to read control coin")

	// Get the scope from txPublisherFundingType. Use the same account for
	// the input and the change so both operations use the account with coins.
	scope, err := txPublisherFundingType.KeyScope()
	require.NoError(h, err, "failed to resolve funding scope")

	account := &wallet.ScopedAccount{
		AccountName: waddrmgr.DefaultAccountName,
		KeyScope:    scope,
	}

	// Use a fixed witness program for an address outside this Wallet.
	// This separates the payment from change without another Wallet.
	const witnessProgramSize = 20

	addr, err := address.NewAddressWitnessPubKeyHash(
		make([]byte, witnessProgramSize), h.NetParams(),
	)
	require.NoError(h, err, "failed to create recipient address")

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err, "failed to create payment pkscript")

	// Act: Call CreateTransaction to select an input and create change.
	// Use the account that received the coins for both operations.
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

	// Assert: Check the input data against the original transaction.
	// The selected coin must have the expected script and value.
	// The payment and change must leave a positive fee.
	require.Len(h, tx.TxIn, 1, "unexpected input count")
	require.Equal(h, spent, tx.TxIn[0].PreviousOutPoint)
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

	// Act: Use the data from CreateTransaction to sign the input.
	// Add the result from ComputeUnlockingScript to that same transaction.
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

	// Assert: Check the signed transaction and execute its input script.
	// Use the original output so incorrect input data cannot pass this check.
	require.NoError(h, blockchain.CheckTransactionSanity(btcutil.NewTx(tx)))
	engine, err := txscript.NewEngine(
		prevOut.PkScript, tx, 0, txscript.StandardVerifyFlags,
		nil, hashes, prevOut.Value, fetcher,
	)
	require.NoError(h, err, "failed to construct input verifier")
	require.NoError(h, engine.Execute(), "authored input script is invalid")

	// Save the signed bytes before broadcast. Compare them with the bytes
	// from the public reader to detect a different transaction.
	var rawTx bytes.Buffer
	require.NoError(h, tx.Serialize(&rawTx), "failed to serialize spend")

	// Act: Broadcast the signed transaction. Broadcast writes the Wallet data
	// before it returns. Wait for the miner to receive the transaction.
	err = w.Broadcast(h.Context(), tx, "")
	require.NoError(h, err, "failed to broadcast transaction")

	txid := tx.TxHash()
	h.AssertTxInMempool(txid)

	// Assert: Check that the reader returns the exact signed transaction.
	// The change must belong to the Wallet. The payment must not belong to it.
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

	// The list of coins must replace the spent input with change.
	// The other coin must have the same values as before broadcast.
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

	// Act: Mine the transaction. The harness waits for the Wallet to reach
	// that block's exact hash and height. Read the results without a retry.
	block := h.MineBlockWithTx(tx)
	_, height := h.GetBestBlock()

	// Assert: Check that the reader and the coin report one confirmation.
	// Check that the change is spendable.
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

	// One new block adds one confirmation to the other coin. Compare the
	// complete list to detect any spent coin that appears again.
	control.Confirmations++
	coins, err = w.ListUnspent(h.Context(), query)
	require.NoError(h, err, "failed to list confirmed spend's coins")
	require.ElementsMatch(h, []*wallet.Utxo{control, confirmed}, coins)

	// Act: ReloadWallet stops the old Manager. It starts a new Manager with
	// the same database. It registers the returned Wallet for cleanup.
	w = h.ReloadWallet(w)

	// The new Wallet starts locked. Unlock it to match the state before
	// the restart. The kvdb Spendable result also depends on the lock state.
	h.UnlockWallet(w)

	// Assert: Compare all fields in the public results without a retry.
	// The miner creates no new block during the restart. A retry could hide
	// data loss.
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

// testBroadcastRejected verifies a stable refusal error and wallet state at
// the rejection boundary: preflight creates no row, while a send-time refusal
// preserves the recorded transaction and its input spend links.
func testBroadcastRejected(h *bwtest.HarnessTest) {
	// Arrange: Fund one owned input and create a dust payment back to the
	// wallet so both its input claim and credited outputs are observable.
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
	// both outputs pay the wallet, making recording visible below.
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

	// Act: Attempt publication; a capable backend can refuse at preflight,
	// while a light client records before its peer refuses the send.
	err = w.Broadcast(h.Context(), tx, "")

	// Assert: Preserve the public refusal identity and check the wallet
	// state promised at the backend's documented rejection boundary.
	require.ErrorIs(
		h, err, chain.ErrDust, "dust transaction was not refused",
	)

	// The refusal published nothing.
	h.AssertTxNotInMempool(tx.TxHash())

	// Without preflight, recording commits before peer refusal. Retain the
	// row and its spend links because that refusal cannot prove invalidity.
	if !h.Backend.SupportsMempoolAcceptance() {
		_, err = w.GetTx(h.Context(), tx.TxHash())
		require.NoError(h, err, "send refusal removed the recorded tx")

		for i, output := range tx.TxOut {
			utxo, err := w.GetUtxo(h.Context(), wire.OutPoint{
				Hash:  tx.TxHash(),
				Index: uint32(i),
			})
			require.NoError(h, err, "recorded output %d was removed", i)
			require.Equal(h, btcutil.Amount(output.Value), utxo.Amount)
		}

		_, err = w.GetUtxo(h.Context(), spent)
		require.ErrorIs(
			h, err, wallet.ErrUnknownOutput,
			"send refusal released the claimed input",
		)

		return
	}

	// Preflight refuses before recording, leaving the wallet untouched.
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
