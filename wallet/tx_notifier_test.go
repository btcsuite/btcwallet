package wallet

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/stretchr/testify/require"
)

// txEventTimeout bounds how long a test waits for a subscription to deliver or
// close.
const txEventTimeout = 5 * time.Second

// receiveTxEvent returns the next event from sub.
func receiveTxEvent(t *testing.T, sub *TxSubscription) *TxDetail {
	t.Helper()

	select {
	case detail, ok := <-sub.Events():
		require.True(t, ok, "subscription ended: %v", sub.Err())

		return detail

	case <-time.After(txEventTimeout):
		require.FailNow(t, "no transaction event")

		return nil
	}
}

// requireTxSubscriptionEnded waits for sub's channel to close and returns the
// reason it ended.
func requireTxSubscriptionEnded(t *testing.T, sub *TxSubscription) error {
	t.Helper()

	timeout := time.After(txEventTimeout)
	for {
		select {
		case _, ok := <-sub.Events():
			if !ok {
				return sub.Err()
			}

		case <-timeout:
			require.FailNow(t, "subscription did not end")
		}
	}
}

// testTxEvent returns an event identified by the given hash byte.
func testTxEvent(id byte) *TxDetail {
	return &TxDetail{Hash: chainhash.Hash{id}}
}

// TestTxNotifierDeliversInOrder verifies that every subscription receives
// every event in delivery order.
func TestTxNotifierDeliversInOrder(t *testing.T) {
	t.Parallel()

	var n txNotifier
	t.Cleanup(n.close)

	first, err := n.subscribe(t.Context())
	require.NoError(t, err)

	second, err := n.subscribe(t.Context())
	require.NoError(t, err)

	for id := byte(1); id <= 3; id++ {
		n.deliver(testTxEvent(id))
	}

	for _, sub := range []*TxSubscription{first, second} {
		for id := byte(1); id <= 3; id++ {
			require.Equal(
				t, chainhash.Hash{id}, receiveTxEvent(t, sub).Hash,
			)
		}
	}
}

// TestTxNotifierUnreadSubscriptionKeepsEvents verifies that delivery never
// waits for a reader and that an unread subscription keeps every event.
func TestTxNotifierUnreadSubscriptionKeepsEvents(t *testing.T) {
	t.Parallel()

	const numEvents = 1000

	var n txNotifier
	t.Cleanup(n.close)

	sub, err := n.subscribe(t.Context())
	require.NoError(t, err)

	for i := range numEvents {
		n.deliver(&TxDetail{Confirmations: int32(i)})
	}

	for i := range numEvents {
		require.Equal(t, int32(i), receiveTxEvent(t, sub).Confirmations)
	}
}

// TestTxNotifierDeliversCopies verifies that one subscriber modifying its
// event cannot change the event another subscriber receives.
func TestTxNotifierDeliversCopies(t *testing.T) {
	t.Parallel()

	var n txNotifier
	t.Cleanup(n.close)

	first, err := n.subscribe(t.Context())
	require.NoError(t, err)

	second, err := n.subscribe(t.Context())
	require.NoError(t, err)

	n.deliver(&TxDetail{
		RawTx:    []byte{1},
		Block:    &BlockDetails{Height: 1},
		Outputs:  []Output{{PkScript: []byte{1}}},
		PrevOuts: []PrevOut{{IsOurs: true}},
	})

	mutated := receiveTxEvent(t, first)
	mutated.RawTx[0] = 2
	mutated.Block.Height = 2
	mutated.Outputs[0].PkScript[0] = 2
	mutated.PrevOuts[0].IsOurs = false

	require.Equal(t, &TxDetail{
		RawTx:    []byte{1},
		Block:    &BlockDetails{Height: 1},
		Outputs:  []Output{{PkScript: []byte{1}}},
		PrevOuts: []PrevOut{{IsOurs: true}},
	}, receiveTxEvent(t, second))
}

// TestTxSubscriptionCancel verifies that Cancel ends only its own
// subscription, with context.Canceled.
func TestTxSubscriptionCancel(t *testing.T) {
	t.Parallel()

	var n txNotifier
	t.Cleanup(n.close)

	canceled, err := n.subscribe(t.Context())
	require.NoError(t, err)

	active, err := n.subscribe(t.Context())
	require.NoError(t, err)

	n.deliver(testTxEvent(1))

	canceled.Cancel()
	n.deliver(testTxEvent(2))

	require.ErrorIs(
		t, requireTxSubscriptionEnded(t, canceled), context.Canceled,
	)
	require.Equal(t, chainhash.Hash{1}, receiveTxEvent(t, active).Hash)
	require.Equal(t, chainhash.Hash{2}, receiveTxEvent(t, active).Hash)
}

// TestTxSubscriptionCancelEnded verifies that Cancel is safe on a subscription
// that has already ended and does not change why it ended.
func TestTxSubscriptionCancelEnded(t *testing.T) {
	t.Parallel()

	var n txNotifier

	sub, err := n.subscribe(t.Context())
	require.NoError(t, err)

	n.close()
	require.ErrorIs(t, requireTxSubscriptionEnded(t, sub), ErrWalletStopped)

	sub.Cancel()

	require.ErrorIs(t, sub.Err(), ErrWalletStopped)
}

// TestTxSubscriptionContextEnd verifies that a subscription ends with the
// cause of its context.
func TestTxSubscriptionContextEnd(t *testing.T) {
	t.Parallel()

	var n txNotifier
	t.Cleanup(n.close)

	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	t.Cleanup(cancel)

	sub, err := n.subscribe(ctx)
	require.NoError(t, err)

	err = requireTxSubscriptionEnded(t, sub)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.False(t, n.hasSubscribers())
}

// TestTxNotifierCloseEndsSubscriptions verifies that closing ends a
// subscription with ErrWalletStopped even while it still holds events.
func TestTxNotifierCloseEndsSubscriptions(t *testing.T) {
	t.Parallel()

	var n txNotifier

	sub, err := n.subscribe(t.Context())
	require.NoError(t, err)

	n.deliver(testTxEvent(1))

	n.close()

	require.ErrorIs(t, requireTxSubscriptionEnded(t, sub), ErrWalletStopped)
}

// TestTxNotifierCloseRejectsSubscribe verifies that a closed notifier rejects
// new subscriptions with ErrWalletStopped.
func TestTxNotifierCloseRejectsSubscribe(t *testing.T) {
	t.Parallel()

	var n txNotifier
	n.close()

	_, err := n.subscribe(t.Context())

	require.ErrorIs(t, err, ErrWalletStopped)
}
