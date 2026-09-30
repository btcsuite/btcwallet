package wallet

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
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

// txEventBackends lists the Store backends a managed wallet runs on in unit
// tests.
var txEventBackends = []DBBackend{DBBackendKVDB, DBBackendSQLite}

// txEventFixture is a started, unlocked wallet with a receiving address. Its
// mock chain never reports synced, so tests drive the syncer's notification
// handling themselves.
type txEventFixture struct {
	w     *Wallet
	sync  *syncer
	chain *bwmock.Chain
	addr  address.Address
}

// newTxEventFixture creates a txEventFixture on the given backend.
func newTxEventFixture(t *testing.T, backend DBBackend) *txEventFixture {
	t.Helper()

	var m *Manager

	switch backend {
	case DBBackendKVDB:
		m = testKVDBManager(t)

	case DBBackendSQLite:
		m = testSQLiteManager(t)

	case DBBackendPostgres:
		require.FailNow(t, "postgres needs a database server", backend)
	}

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

	info, err := w.NewAddress(
		t.Context(), NewAccountSelectorByName(
			waddrmgr.KeyScopeBIP0084, accountName,
		), false,
	)
	require.NoError(t, err)

	s, ok := w.sync.(*syncer)
	require.True(t, ok)

	return &txEventFixture{
		w: w, sync: s, chain: chainMock, addr: info.Addr,
	}
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

// txEventScanResult returns a scan result that finds recs in block.
func txEventScanResult(s *syncer, block *wtxmgr.BlockMeta,
	recs ...*wtxmgr.TxRecord) scanResult {

	return scanResult{
		BlockProcessResult: &BlockProcessResult{
			RelevantOutputs: s.prepareTxMatches(recs),
		},
		meta: block,
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
		t.Run(string(backend), func(t *testing.T) {
			t.Parallel()

			f := newTxEventFixture(t, backend)
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
		t.Run(string(backend), func(t *testing.T) {
			t.Parallel()

			f := newTxEventFixture(t, backend)
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
		t.Run(string(backend), func(t *testing.T) {
			t.Parallel()

			f := newTxEventFixture(t, backend)
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

// TestSubscribeTxnsSyncBatch verifies that a catch-up scan batch reports each
// transaction it confirms, both one the wallet saw unconfirmed and one it
// discovers in the scanned block.
func TestSubscribeTxnsSyncBatch(t *testing.T) {
	t.Parallel()

	for _, backend := range txEventBackends {
		t.Run(string(backend), func(t *testing.T) {
			t.Parallel()

			f := newTxEventFixture(t, backend)
			seen := newTxEventRecord(t, f.addr, 1)
			discovered := newTxEventRecord(t, f.addr, 2)
			later := newTxEventRecord(t, f.addr, 3)

			err := f.sync.processChainUpdate(
				t.Context(), chain.RelevantTx{TxRecord: seen},
			)
			require.NoError(t, err)

			sub, err := f.w.SubscribeTxns(t.Context())
			require.NoError(t, err)

			block := nextTxEventBlock(f.w, 1)
			err = f.sync.putSyncBatch(
				t.Context(), &RecoveryState{}, []scanResult{
					txEventScanResult(
						f.sync, block, seen, discovered,
					),
				},
			)
			require.NoError(t, err)

			err = f.sync.processChainUpdate(
				t.Context(), chain.RelevantTx{TxRecord: later},
			)
			require.NoError(t, err)

			for _, rec := range []*wtxmgr.TxRecord{seen, discovered} {
				event := receiveTxEvent(t, sub)
				require.Equal(t, rec.Hash, event.Hash)
				require.NotNil(t, event.Block)
				require.Equal(t, block.Hash, event.Block.Hash)
			}

			// The batch produced no other event, so the next one
			// reports the later transaction.
			require.Equal(t, later.Hash, receiveTxEvent(t, sub).Hash)
		})
	}
}

// TestSubscribeTxnsTargetedBatch verifies that a targeted rescan reports a
// historical transaction it newly records, with the block it finds it in.
func TestSubscribeTxnsTargetedBatch(t *testing.T) {
	t.Parallel()

	for _, backend := range txEventBackends {
		t.Run(string(backend), func(t *testing.T) {
			t.Parallel()

			f := newTxEventFixture(t, backend)
			historical := newTxEventRecord(t, f.addr, 1)
			later := newTxEventRecord(t, f.addr, 2)

			// The wallet syncs past the block before the rescan finds
			// the transaction in it.
			block := nextTxEventBlock(f.w, 1)
			err := f.sync.processChainUpdate(
				t.Context(), chain.FilteredBlockConnected{Block: block},
			)
			require.NoError(t, err)

			sub, err := f.w.SubscribeTxns(t.Context())
			require.NoError(t, err)

			err = f.sync.putTargetedBatch(
				t.Context(), &RecoveryState{}, []scanResult{
					txEventScanResult(f.sync, block, historical),
				},
			)
			require.NoError(t, err)

			err = f.sync.processChainUpdate(
				t.Context(), chain.RelevantTx{TxRecord: later},
			)
			require.NoError(t, err)

			event := receiveTxEvent(t, sub)
			require.Equal(t, historical.Hash, event.Hash)
			require.NotNil(t, event.Block)
			require.Equal(t, block.Hash, event.Block.Hash)

			require.Equal(t, later.Hash, receiveTxEvent(t, sub).Hash)
		})
	}
}

// TestSubscribeTxnsTargetedBatchRecorded verifies that a targeted rescan does
// not report a transaction already confirmed in the rescanned block. It runs
// on SQLite only: kvdb rejects recording a confirmed transaction again in the
// same block, so the rescan fails before any event could be reported.
func TestSubscribeTxnsTargetedBatchRecorded(t *testing.T) {
	t.Parallel()

	f := newTxEventFixture(t, DBBackendSQLite)
	confirmed := newTxEventRecord(t, f.addr, 1)
	later := newTxEventRecord(t, f.addr, 2)

	block := nextTxEventBlock(f.w, 1)
	err := f.sync.processChainUpdate(
		t.Context(), chain.FilteredBlockConnected{
			Block:       block,
			RelevantTxs: []*wtxmgr.TxRecord{confirmed},
		},
	)
	require.NoError(t, err)

	sub, err := f.w.SubscribeTxns(t.Context())
	require.NoError(t, err)

	err = f.sync.putTargetedBatch(
		t.Context(), &RecoveryState{}, []scanResult{
			txEventScanResult(f.sync, block, confirmed),
		},
	)
	require.NoError(t, err)

	err = f.sync.processChainUpdate(
		t.Context(), chain.RelevantTx{TxRecord: later},
	)
	require.NoError(t, err)

	// The rescan produced no event, so the next one reports the later
	// transaction.
	require.Equal(t, later.Hash, receiveTxEvent(t, sub).Hash)
}

// TestSubscribeTxnsRepeatedWrite verifies that a write naming the same
// transaction twice reports it once.
func TestSubscribeTxnsRepeatedWrite(t *testing.T) {
	t.Parallel()

	for _, backend := range txEventBackends {
		t.Run(string(backend), func(t *testing.T) {
			t.Parallel()

			f := newTxEventFixture(t, backend)
			repeated := newTxEventRecord(t, f.addr, 1)
			later := newTxEventRecord(t, f.addr, 2)

			sub, err := f.w.SubscribeTxns(t.Context())
			require.NoError(t, err)

			err = f.sync.putTxNotifications(
				t.Context(), f.sync.prepareTxMatches(
					[]*wtxmgr.TxRecord{repeated, repeated},
				), nil,
			)
			require.NoError(t, err)

			err = f.sync.processChainUpdate(
				t.Context(), chain.RelevantTx{TxRecord: later},
			)
			require.NoError(t, err)

			require.Equal(t, repeated.Hash, receiveTxEvent(t, sub).Hash)
			require.Equal(t, later.Hash, receiveTxEvent(t, sub).Hash)
		})
	}
}

// TestSubscribeTxnsConfirmedAboveTip verifies that a confirmation the chain
// backend relays before the wallet's tip reaches its block is held, then
// reported once with one confirmation when the block connects.
func TestSubscribeTxnsConfirmedAboveTip(t *testing.T) {
	t.Parallel()

	for _, backend := range txEventBackends {
		t.Run(string(backend), func(t *testing.T) {
			t.Parallel()

			f := newTxEventFixture(t, backend)
			confirmed := newTxEventRecord(t, f.addr, 1)
			unconfirmed := newTxEventRecord(t, f.addr, 2)
			later := newTxEventRecord(t, f.addr, 3)

			sub, err := f.w.SubscribeTxns(t.Context())
			require.NoError(t, err)

			block := nextTxEventBlock(f.w, 1)
			err = f.sync.processChainUpdate(
				t.Context(), chain.RelevantTx{
					TxRecord: confirmed,
					Block:    block,
				},
			)
			require.NoError(t, err)

			// The held confirmation is not reported ahead of a later
			// change.
			err = f.sync.processChainUpdate(
				t.Context(), chain.RelevantTx{TxRecord: unconfirmed},
			)
			require.NoError(t, err)

			// The block connects without repeating the transaction the
			// wallet already recorded in it.
			err = f.sync.processChainUpdate(
				t.Context(), chain.FilteredBlockConnected{Block: block},
			)
			require.NoError(t, err)

			err = f.sync.processChainUpdate(
				t.Context(), chain.RelevantTx{TxRecord: later},
			)
			require.NoError(t, err)

			require.Equal(
				t, unconfirmed.Hash, receiveTxEvent(t, sub).Hash,
			)

			event := receiveTxEvent(t, sub)
			require.Equal(t, confirmed.Hash, event.Hash)
			require.NotNil(t, event.Block)
			require.Equal(t, block.Hash, event.Block.Hash)
			require.Equal(t, int32(1), event.Confirmations)

			require.Equal(t, later.Hash, receiveTxEvent(t, sub).Hash)
		})
	}
}

// txDetailFailStore fails the next GetTxDetail call with errTxDetailRead.
type txDetailFailStore struct {
	db.Store

	fail atomic.Bool
}

// errTxDetailRead is the failure txDetailFailStore injects.
var errTxDetailRead = errors.New("injected tx detail read failure")

// GetTxDetail fails once after fail is set, then reads through.
func (s *txDetailFailStore) GetTxDetail(ctx context.Context,
	query db.GetTxDetailQuery) (*db.TxDetailInfo, error) {

	if s.fail.CompareAndSwap(true, false) {
		return nil, errTxDetailRead
	}

	return s.Store.GetTxDetail(ctx, query)
}

// TestSubscribeTxnsReadFailureEndsSubscriptions verifies that a committed
// change the wallet cannot read ends the subscriptions with ErrTxEventLost
// instead of being skipped, and that a new subscription receives later
// changes.
func TestSubscribeTxnsReadFailureEndsSubscriptions(t *testing.T) {
	t.Parallel()

	for _, backend := range txEventBackends {
		t.Run(string(backend), func(t *testing.T) {
			t.Parallel()

			f := newTxEventFixture(t, backend)
			lost := newTxEventRecord(t, f.addr, 1)
			later := newTxEventRecord(t, f.addr, 2)

			failing := &txDetailFailStore{Store: f.w.store}
			f.w.store = failing

			sub, err := f.w.SubscribeTxns(t.Context())
			require.NoError(t, err)

			failing.fail.Store(true)

			err = f.sync.processChainUpdate(
				t.Context(), chain.RelevantTx{TxRecord: lost},
			)
			require.NoError(t, err)

			err = requireTxSubscriptionEnded(t, sub)
			require.ErrorIs(t, err, ErrTxEventLost)
			require.ErrorIs(t, err, errTxDetailRead)

			resubscribed, err := f.w.SubscribeTxns(t.Context())
			require.NoError(t, err)

			err = f.sync.processChainUpdate(
				t.Context(), chain.RelevantTx{TxRecord: later},
			)
			require.NoError(t, err)

			require.Equal(
				t, later.Hash, receiveTxEvent(t, resubscribed).Hash,
			)
		})
	}
}
