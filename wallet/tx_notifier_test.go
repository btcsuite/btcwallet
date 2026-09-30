package wallet

import (
	"context"
	"testing"
	"testing/synctest"
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

// requireNoTxEvent waits until every goroutine in the synctest bubble is
// blocked, then requires sub to have no event ready.
func requireNoTxEvent(t *testing.T, sub *TxSubscription) {
	t.Helper()

	synctest.Wait()

	select {
	case detail, ok := <-sub.Events():
		require.False(t, ok, "unexpected event %v", detail)

	default:
	}
}

// TestTxNotifierDeliversInOrder verifies that every subscription receives
// every event in delivery order, and nothing more.
func TestTxNotifierDeliversInOrder(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		t.Helper()

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
					t, chainhash.Hash{id},
					receiveTxEvent(t, sub).Hash,
				)
			}

			requireNoTxEvent(t, sub)
		}
	})
}

// TestTxNotifierUnreadSubscriptionKeepsEvents verifies that delivery never
// waits for a reader and that an unread subscription keeps every event up to
// its limit.
func TestTxNotifierUnreadSubscriptionKeepsEvents(t *testing.T) {
	t.Parallel()

	const numEvents = TxSubscriptionQueueLimit

	synctest.Test(t, func(t *testing.T) {
		t.Helper()

		var n txNotifier
		t.Cleanup(n.close)

		sub, err := n.subscribe(t.Context())
		require.NoError(t, err)

		for i := range numEvents {
			n.deliver(&TxDetail{Confirmations: int32(i)})
		}

		for i := range numEvents {
			require.Equal(
				t, int32(i), receiveTxEvent(t, sub).Confirmations,
			)
		}

		requireNoTxEvent(t, sub)
	})
}

// TestTxSubscriptionOverflow verifies that a subscription whose reader falls
// more than TxSubscriptionQueueLimit events behind ends with
// ErrTxSubscriptionOverflow instead of skipping events.
func TestTxSubscriptionOverflow(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		t.Helper()

		var n txNotifier
		t.Cleanup(n.close)

		sub, err := n.subscribe(t.Context())
		require.NoError(t, err)

		for i := range TxSubscriptionQueueLimit + 1 {
			n.deliver(&TxDetail{Confirmations: int32(i)})
		}

		require.ErrorIs(
			t, requireTxSubscriptionEnded(t, sub),
			ErrTxSubscriptionOverflow,
		)
	})
}

// TestTxNotifierDeliversCopies verifies that one subscriber modifying its
// event cannot change the event another subscriber receives.
func TestTxNotifierDeliversCopies(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		t.Helper()

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
	})
}

// TestTxSubscriptionCancel verifies that Cancel ends only its own
// subscription, with context.Canceled.
func TestTxSubscriptionCancel(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		t.Helper()

		var n txNotifier
		t.Cleanup(n.close)

		canceled, err := n.subscribe(t.Context())
		require.NoError(t, err)

		active, err := n.subscribe(t.Context())
		require.NoError(t, err)

		canceled.Cancel()
		synctest.Wait()

		n.deliver(testTxEvent(1))

		_, ok := <-canceled.Events()
		require.False(t, ok, "canceled subscription received an event")
		require.ErrorIs(t, canceled.Err(), context.Canceled)
		require.Equal(t, chainhash.Hash{1}, receiveTxEvent(t, active).Hash)
		requireNoTxEvent(t, active)
	})
}

// TestTxSubscriptionCancelEnded verifies that Cancel is safe on a subscription
// that has already ended and does not change why it ended.
func TestTxSubscriptionCancelEnded(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		t.Helper()

		var n txNotifier

		sub, err := n.subscribe(t.Context())
		require.NoError(t, err)

		n.close()
		require.ErrorIs(
			t, requireTxSubscriptionEnded(t, sub), ErrWalletStopped,
		)

		sub.Cancel()

		require.ErrorIs(t, sub.Err(), ErrWalletStopped)
	})
}

// TestTxSubscriptionContextEnd verifies that a subscription ends with the
// cause of its context.
func TestTxSubscriptionContextEnd(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		t.Helper()

		var n txNotifier
		t.Cleanup(n.close)

		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		t.Cleanup(cancel)

		sub, err := n.subscribe(ctx)
		require.NoError(t, err)

		err = requireTxSubscriptionEnded(t, sub)

		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.False(t, n.hasSubscribers())
	})
}

// TestTxNotifierCloseEndsSubscriptions verifies that closing ends a
// subscription with ErrWalletStopped even while it still holds events.
func TestTxNotifierCloseEndsSubscriptions(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		t.Helper()

		var n txNotifier

		sub, err := n.subscribe(t.Context())
		require.NoError(t, err)

		n.deliver(testTxEvent(1))
		synctest.Wait()

		n.close()

		_, ok := <-sub.Events()
		require.False(t, ok, "closed subscription delivered an event")
		require.ErrorIs(t, sub.Err(), ErrWalletStopped)
	})
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

// TestSubscribeTxnsRequiresStarted verifies that a wallet accepts
// subscriptions only while it is started.
func TestSubscribeTxnsRequiresStarted(t *testing.T) {
	t.Parallel()

	w, _ := createTestWalletWithMocks(t)

	_, err := w.SubscribeTxns(t.Context())

	require.ErrorIs(t, err, ErrStateForbidden)
}

// TestWalletStopEndsTxSubscriptions verifies that stopping the wallet ends
// its subscriptions with ErrWalletStopped.
func TestWalletStopEndsTxSubscriptions(t *testing.T) {
	t.Parallel()

	w, _ := createStartedWalletWithMocks(t)

	sub, err := w.SubscribeTxns(t.Context())
	require.NoError(t, err)

	err = w.stop()

	require.NoError(t, err)
	require.ErrorIs(t, requireTxSubscriptionEnded(t, sub), ErrWalletStopped)
}

// TestSubscribeTxnsRejectsStopped verifies that a stopped wallet rejects new
// subscriptions with ErrWalletStopped.
func TestSubscribeTxnsRejectsStopped(t *testing.T) {
	t.Parallel()

	w, _ := createStartedWalletWithMocks(t)
	require.NoError(t, w.stop())

	_, err := w.SubscribeTxns(t.Context())

	require.ErrorIs(t, err, ErrWalletStopped)
}

// TestTxChanged verifies which committed states a write reports: only the
// state the write recorded, and only when it differs from the state before.
func TestTxChanged(t *testing.T) {
	t.Parallel()

	blockA := chainhash.Hash{0xaa}
	blockB := chainhash.Hash{0xbb}

	tests := []struct {
		name   string
		before txState
		wrote  *chainhash.Hash
		after  *TxDetail
		want   bool
	}{
		{
			name:   "new unconfirmed",
			before: txState{},
			after:  &TxDetail{Status: TxStatusPublished},
			want:   true,
		},
		{
			name:   "known unconfirmed",
			before: txState{known: true},
			after:  &TxDetail{Status: TxStatusPublished},
		},
		{
			name:   "unconfirmed write of confirmed tx",
			before: txState{},
			after: &TxDetail{
				Status: TxStatusPublished,
				Block:  &BlockDetails{Hash: blockA},
			},
		},
		{
			name:   "new confirmation",
			before: txState{known: true},
			wrote:  &blockA,
			after: &TxDetail{
				Status: TxStatusPublished,
				Block:  &BlockDetails{Hash: blockA},
			},
			want: true,
		},
		{
			name:   "same confirmation",
			before: txState{known: true, block: &blockA},
			wrote:  &blockA,
			after: &TxDetail{
				Status: TxStatusPublished,
				Block:  &BlockDetails{Hash: blockA},
			},
		},
		{
			name:   "moved confirmation",
			before: txState{known: true, block: &blockA},
			wrote:  &blockB,
			after: &TxDetail{
				Status: TxStatusPublished,
				Block:  &BlockDetails{Hash: blockB},
			},
			want: true,
		},
		{
			name:   "confirmation not recorded by this write",
			before: txState{known: true},
			wrote:  &blockB,
			after: &TxDetail{
				Status: TxStatusPublished,
				Block:  &BlockDetails{Hash: blockA},
			},
		},
		{
			name:   "invalidated",
			before: txState{},
			after:  &TxDetail{Status: TxStatusFailed},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(
				t, tc.want, txChanged(tc.before, tc.wrote, tc.after),
			)
		})
	}
}
