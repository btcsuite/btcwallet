package wallet

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/mock"
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

// txEventBackends lists the Store backends a managed wallet runs on in unit
// tests.
var txEventBackends = []struct {
	name       string
	newManager func(testing.TB) *Manager
}{
	{name: "kvdb", newManager: testKVDBManager},
	{name: "sqlite", newManager: testSQLiteManager},
}

// txEventFixture is a started, unlocked wallet with a receiving address. Its
// mock chain never reports synced, so tests drive the syncer's notification
// handling themselves.
type txEventFixture struct {
	w     *Wallet
	sync  *syncer
	chain *bwmock.Chain
	addr  address.Address
}

// newTxEventFixture creates a txEventFixture on newManager's backend.
func newTxEventFixture(t *testing.T,
	newManager func(testing.TB) *Manager) *txEventFixture {

	t.Helper()

	m := newManager(t)
	chainMock, ok := m.config.ChainSource.(*bwmock.Chain)
	require.True(t, ok)
	chainMock.On("NotifyReceived", mock.Anything).Return(nil).Maybe()

	params := sqliteCreateParams(t)
	w, err := m.Create(params)
	require.NoError(t, err)

	require.NoError(t, w.Unlock(t.Context(), UnlockRequest{
		Passphrase: params.PrivatePassphrase,
		Timeout:    -1,
	}))

	const accountName = "events"

	_, err = w.NewAccount(t.Context(), NewAccountParams{
		Scope: waddrmgr.KeyScopeBIP0084,
		Name:  accountName,
	})
	require.NoError(t, err)

	addr, err := w.NewAddress(
		t.Context(), accountName, waddrmgr.WitnessPubKey, false,
	)
	require.NoError(t, err)

	s, ok := w.sync.(*syncer)
	require.True(t, ok)

	return &txEventFixture{w: w, sync: s, chain: chainMock, addr: addr}
}

// txEventAmount is the value every newTxEventRecord transaction pays.
const txEventAmount = btcutil.Amount(10_000)

// newTxEventRecord returns a transaction paying addr that spends an outpoint
// derived from id.
func newTxEventRecord(t *testing.T, addr address.Address,
	id byte) *wtxmgr.TxRecord {

	t.Helper()

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(
		wire.NewOutPoint(&chainhash.Hash{id}, 0), nil, nil,
	))
	tx.AddTxOut(wire.NewTxOut(int64(txEventAmount), pkScript))

	rec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
	require.NoError(t, err)

	return rec
}

// nextTxEventBlock returns metadata for a block extending the wallet's synced
// tip, identified by id.
func nextTxEventBlock(w *Wallet, id byte) *wtxmgr.BlockMeta {
	return &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   chainhash.Hash{0xbb, id},
			Height: w.SyncedTo().Height + 1,
		},
		Time: time.Now(),
	}
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

// TestSubscribeTxnsChainUnconfirmed verifies that an unconfirmed transaction
// relayed by the chain backend is reported once, when the wallet first records
// it.
func TestSubscribeTxnsChainUnconfirmed(t *testing.T) {
	t.Parallel()

	for _, backend := range txEventBackends {
		t.Run(backend.name, func(t *testing.T) {
			t.Parallel()

			f := newTxEventFixture(t, backend.newManager)
			first := newTxEventRecord(t, f.addr, 1)
			second := newTxEventRecord(t, f.addr, 2)

			sub, err := f.w.SubscribeTxns(t.Context())
			require.NoError(t, err)

			for _, rec := range []*wtxmgr.TxRecord{first, first, second} {
				err = f.sync.processChainUpdate(
					t.Context(), chain.RelevantTx{TxRecord: rec},
				)
				require.NoError(t, err)
			}

			event := receiveTxEvent(t, sub)
			require.Equal(t, first.Hash, event.Hash)
			require.Nil(t, event.Block)
			require.Equal(t, txEventAmount, event.Value)

			// The repeated relay produced no event, so the next one
			// reports the second transaction.
			require.Equal(t, second.Hash, receiveTxEvent(t, sub).Hash)
		})
	}
}

// TestSubscribeTxnsChainConfirmed verifies that a block confirming wallet
// transactions reports each of them, whether or not the wallet saw the
// transaction unconfirmed first.
func TestSubscribeTxnsChainConfirmed(t *testing.T) {
	t.Parallel()

	for _, backend := range txEventBackends {
		t.Run(backend.name, func(t *testing.T) {
			t.Parallel()

			f := newTxEventFixture(t, backend.newManager)
			seen := newTxEventRecord(t, f.addr, 1)
			unseen := newTxEventRecord(t, f.addr, 2)
			later := newTxEventRecord(t, f.addr, 3)

			err := f.sync.processChainUpdate(
				t.Context(), chain.RelevantTx{TxRecord: seen},
			)
			require.NoError(t, err)

			sub, err := f.w.SubscribeTxns(t.Context())
			require.NoError(t, err)

			block := nextTxEventBlock(f.w, 1)
			err = f.sync.processChainUpdate(
				t.Context(), chain.FilteredBlockConnected{
					Block: block,
					RelevantTxs: []*wtxmgr.TxRecord{
						seen, unseen,
					},
				},
			)
			require.NoError(t, err)

			err = f.sync.processChainUpdate(
				t.Context(), chain.RelevantTx{TxRecord: later},
			)
			require.NoError(t, err)

			for _, rec := range []*wtxmgr.TxRecord{seen, unseen} {
				event := receiveTxEvent(t, sub)
				require.Equal(t, rec.Hash, event.Hash)
				require.NotNil(t, event.Block)
				require.Equal(t, block.Hash, event.Block.Hash)
				require.Equal(t, block.Height, event.Block.Height)
				require.Equal(t, int32(1), event.Confirmations)
			}

			// The block produced no other event, so the next one
			// reports the later transaction.
			require.Equal(t, later.Hash, receiveTxEvent(t, sub).Hash)
		})
	}
}

// TestSubscribeTxnsReorgReconfirms verifies that a reorg reports only the
// block that confirms a transaction again, after the stale confirmation and
// with no event for the disconnect.
func TestSubscribeTxnsReorgReconfirms(t *testing.T) {
	t.Parallel()

	for _, backend := range txEventBackends {
		t.Run(backend.name, func(t *testing.T) {
			t.Parallel()

			f := newTxEventFixture(t, backend.newManager)
			rec := newTxEventRecord(t, f.addr, 1)
			forkPoint := f.w.SyncedTo()

			sub, err := f.w.SubscribeTxns(t.Context())
			require.NoError(t, err)

			stale := nextTxEventBlock(f.w, 1)
			err = f.sync.processChainUpdate(
				t.Context(), chain.FilteredBlockConnected{
					Block:       stale,
					RelevantTxs: []*wtxmgr.TxRecord{rec},
				},
			)
			require.NoError(t, err)

			require.NoError(t, f.sync.rewindToBlock(t.Context(), forkPoint))

			replacement := nextTxEventBlock(f.w, 2)
			err = f.sync.processChainUpdate(
				t.Context(), chain.FilteredBlockConnected{
					Block:       replacement,
					RelevantTxs: []*wtxmgr.TxRecord{rec},
				},
			)
			require.NoError(t, err)

			// The next event after the stale confirmation is the
			// replacement, so the disconnect reported nothing.
			for _, block := range []*wtxmgr.BlockMeta{stale, replacement} {
				event := receiveTxEvent(t, sub)
				require.Equal(t, rec.Hash, event.Hash)
				require.NotNil(t, event.Block)
				require.Equal(t, block.Hash, event.Block.Hash)
			}
		})
	}
}
