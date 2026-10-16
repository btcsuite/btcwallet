// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// subscriptionWallet reuses the existing SQLite Manager fixture and prepares
// an owned output script. The fixture remains the only lifecycle/mock owner.
func subscriptionWallet(t *testing.T) (*Wallet, *bwmock.Chain, []byte) {
	t.Helper()

	_, client, w := newLiveWatchManager(t)
	client.On("WatchAddrsFromTip", mock.Anything, mock.Anything).
		Return(nil).Once()

	recv, err := w.NewAddress(t.Context(), NewAccountSelectorByName(
		waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountName,
	), false)
	require.NoError(t, err)

	script, err := txscript.PayToAddrScript(recv.Addr)
	require.NoError(t, err)

	return w, client, script
}

// subscriptionTx supplies distinct owned transactions without a second mining
// or signing fixture; the chain mock controls their publication outcome.
func subscriptionTx(script []byte, nonce uint32) *wire.MsgTx {
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{
		Hash:  chainhash.Hash{1},
		Index: nonce,
	}, nil, nil))
	tx.AddTxOut(&wire.TxOut{
		Value:    1000,
		PkScript: script,
	})

	return tx
}

// TestTxSubscriptionPublicationOwnership verifies fan-out gives each caller
// independent mutable data while retaining the same observation timestamp.
func TestTxSubscriptionPublicationOwnership(t *testing.T) {
	t.Parallel()

	// Arrange: Register two streams before publishing one owned transaction.
	// The fixture verifies these exact chain calls during its existing cleanup.
	w, client, script := subscriptionWallet(t)
	first, _, err := w.SubscribeTxns(t.Context())
	require.NoError(t, err)

	second, _, err := w.SubscribeTxns(t.Context())
	require.NoError(t, err)
	client.On("TestMempoolAccept", mock.Anything, float64(0)).
		Return(nil, chain.ErrUnimplemented).Once()
	client.On("NotifyReceived", mock.Anything).Return(nil).Once()
	client.On("SendRawTransaction", mock.Anything, false).
		Return(nil, nil).Once()

	tx := subscriptionTx(script, 1)
	before := time.Now()

	// Act: Publish through the public API and mutate one caller's result.
	// These mutations must not affect the sibling's buffered observation.
	require.NoError(t, w.Broadcast(t.Context(), tx, "subscription"))

	after := time.Now()
	changed := receiveTxSubscription(t, first)
	changed.Detail.Hash = chainhash.Hash{}
	changed.Detail.RawTx[0] ^= 1
	changed.Detail.Outputs[0].PkScript[0] ^= 1
	changed.Detail.Outputs[0].Addresses[0] = nil
	changed.Detail.PrevOuts[0].OutPoint.Hash = chainhash.Hash{}

	// Assert: The sibling retains the complete unconfirmed Wallet result and
	// a shared observation time bounded by publication, not its stored receipt.
	notification := receiveTxSubscription(t, second)
	detail := notification.Detail
	require.Equal(t, tx.TxHash(), detail.Hash)
	require.Equal(t, byte(2), detail.RawTx[0])
	require.Equal(t, script, detail.Outputs[0].PkScript)
	require.NotNil(t, detail.Outputs[0].Addresses[0])
	require.Equal(t, chainhash.Hash{1}, detail.PrevOuts[0].OutPoint.Hash)
	require.Nil(t, detail.Block)
	require.Equal(t, changed.Timestamp, notification.Timestamp)
	require.False(t, notification.Timestamp.Before(before))
	require.False(t, notification.Timestamp.After(after))
}

// TestTxSubscriptionSlowConsumer verifies drop-oldest FIFO buffering without
// blocking publication, its consuming sibling, or Wallet shutdown.
func TestTxSubscriptionSlowConsumer(t *testing.T) {
	t.Parallel()

	// Arrange: Leave one stream unread while its sibling consumes every
	// notification. Use the public limit as the single source of queue size.
	w, client, script := subscriptionWallet(t)
	slow, _, err := w.SubscribeTxns(t.Context())
	require.NoError(t, err)

	fast, _, err := w.SubscribeTxns(t.Context())
	require.NoError(t, err)

	count := TxSubscriptionQueueLimit + 1
	client.On("TestMempoolAccept", mock.Anything, float64(0)).
		Return(nil, chain.ErrUnimplemented).Times(count + 1)
	client.On("NotifyReceived", mock.Anything).Return(nil).Times(count + 1)
	client.On("SendRawTransaction", mock.Anything, false).
		Return(nil, nil).Times(count + 1)

	// Act: Fill the queue and exceed it by one. Publication returns without
	// any help from the stalled consumer, and the healthy sibling keeps up.
	for i := range uint32(count) {
		tx := subscriptionTx(script, i)
		require.NoError(t, w.Broadcast(t.Context(), tx, ""))
		require.Equal(t, tx.TxHash(),
			receiveTxSubscription(t, fast).Detail.Hash)
	}

	// Assert: The oldest item alone was discarded; every retained item arrives
	// FIFO, including the newest. Overflow is not a terminal condition.
	for i := uint32(1); i < uint32(count); i++ {
		require.Equal(t, subscriptionTx(script, i).TxHash(),
			receiveTxSubscription(t, slow).Detail.Hash)
	}

	// A subsequent publication still succeeds, and Stop discards its unread
	// notifications instead of requiring either consumer to drain them.
	require.NoError(t, w.Broadcast(
		t.Context(), subscriptionTx(script, uint32(count)), "",
	))
	require.NoError(t, w.stop())

	_, open := <-slow
	require.False(t, open)
}
