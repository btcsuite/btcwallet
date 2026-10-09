//go:build itest

package itest

import (
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/bwtest"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

// txNotifierAddrType is the address type the TxNotifier cases receive to.
const txNotifierAddrType = waddrmgr.WitnessPubKey

// testTxNotifierReceiveUnconfirmed verifies that a payment the chain backend
// relays from its mempool is reported unconfirmed. Neutrino does not relay
// unconfirmed transactions, which SubscribeTxns documents.
func testTxNotifierReceiveUnconfirmed(h *bwtest.HarnessTest) {
	if _, ok := h.ChainClient.(*chain.NeutrinoClient); ok {
		h.Skip("neutrino does not relay unconfirmed transactions")
	}

	w, _ := h.NewWallet(bwtest.WalletFixture{})
	addr := h.NewWalletAddressOfType(w, txNotifierAddrType)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(h, err, "failed to create payment pkscript")

	sub, err := w.SubscribeTxns(h.Context())
	require.NoError(h, err, "failed to subscribe")

	txid := h.SendOutput(&wire.TxOut{
		Value:    oneBTC,
		PkScript: pkScript,
	}, bwtest.MinerFeeRate)

	event := h.ReceiveTxEvent(sub)
	require.Equal(h, *txid, event.Hash, "unexpected transaction")
	require.Nil(h, event.Block, "unconfirmed payment reports a block")
	require.Zero(
		h, event.Confirmations, "unconfirmed payment reports confirmations",
	)
	require.Equal(h, btcutil.Amount(oneBTC), event.Value, "unexpected value")

	// The harness requires an empty mempool once a case succeeds.
	h.MineBlockWithTx(h.AssertTxInMempool(*txid))
}

// testTxNotifierReceiveConfirmed verifies that a block paying the wallet is
// reported with that block. A coinbase payment is never in a mempool, so every
// chain backend reports it only once confirmed.
func testTxNotifierReceiveConfirmed(h *bwtest.HarnessTest) {
	w, _ := h.NewWallet(bwtest.WalletFixture{})
	addr := h.NewWalletAddressOfType(w, txNotifierAddrType)

	sub, err := w.SubscribeTxns(h.Context())
	require.NoError(h, err, "failed to subscribe")

	block := h.MineBlockToAddress(addr)
	coinbase := block.Transactions[0]

	event := h.ReceiveTxEvent(sub)
	require.Equal(h, coinbase.TxHash(), event.Hash, "unexpected transaction")
	require.Equal(
		h, block.BlockHash(), event.Block.Hash, "unexpected block",
	)
	require.Equal(h, int32(1), event.Confirmations, "unexpected confirmations")
	require.Equal(
		h, btcutil.Amount(coinbase.TxOut[0].Value), event.Value,
		"unexpected value",
	)
}

// testTxNotifierBroadcastTransaction verifies that a transaction the wallet
// publishes is reported unconfirmed once, on every chain backend. The chain
// backend relaying it back to the wallet must not report it again, which the
// next event being its confirmation shows.
func testTxNotifierBroadcastTransaction(h *bwtest.HarnessTest) {
	w, funding := h.NewWallet(bwtest.WalletFixture{
		AddrType: txNotifierAddrType,
		Amounts:  []btcutil.Amount{oneBTC},
		Unlocked: true,
	})

	addr := h.NewWalletAddressOfType(w, txNotifierAddrType)

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

	sub, err := w.SubscribeTxns(h.Context())
	require.NoError(h, err, "failed to subscribe")

	err = w.Broadcast(h.Context(), tx, "")
	require.NoError(h, err, "failed to broadcast transaction")

	unconfirmed := h.ReceiveTxEvent(sub)
	require.Equal(h, txid, unconfirmed.Hash, "unexpected transaction")
	require.Nil(h, unconfirmed.Block, "published transaction reports a block")

	h.MineBlockWithTx(tx)

	// The next event is the confirmation, so no second unconfirmed event
	// was reported in between.
	confirmed := h.ReceiveTxEvent(sub)
	require.Equal(h, txid, confirmed.Hash, "unexpected transaction")
	require.NotNil(h, confirmed.Block, "next event is not the confirmation")
}
