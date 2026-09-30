// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// TxNotifier provides live notifications of wallet transaction changes.
type TxNotifier interface {
	// SubscribeTxns returns a subscription to the wallet's transaction
	// changes.
	SubscribeTxns(ctx context.Context) (*TxSubscription, error)
}

// A compile-time assertion to ensure that Wallet implements the TxNotifier
// interface.
var _ TxNotifier = (*Wallet)(nil)

// SubscribeTxns returns a subscription to the transaction changes made by
// writes that begin after this call returns. A write already in progress may
// go unreported, and earlier history is not replayed; use ListTxns for it.
//
// The wallet reports a transaction the chain backend relays unconfirmed when
// it first records it, and reports each block that newly confirms a wallet
// transaction, including after a reorg. A transaction disconnected by a reorg
// is not reported until a block confirms it again. Chain backends that do not
// relay unconfirmed transactions, such as neutrino, only produce
// confirmations.
//
// The subscription lives until ctx ends, Cancel is called, or the wallet
// stops. The wallet must be started.
//
// NOTE: This method is part of the TxNotifier interface.
func (w *Wallet) SubscribeTxns(ctx context.Context) (*TxSubscription, error) {
	err := w.state.validateStarted()
	if err != nil {
		return nil, err
	}

	return w.txEvents.subscribe(ctx)
}

// TxSubscription delivers wallet transaction changes. Events for one
// transaction arrive in the order the wallet committed them. Each subscription
// buffers its own undelivered events, so a slow reader never stalls the wallet
// and never loses an event while the subscription is active.
type TxSubscription struct {
	// ctx ends the subscription. Its cause reports why it ended.
	//
	//nolint:containedctx
	ctx context.Context

	// cancel ends the subscription with the given cause.
	cancel context.CancelCauseFunc

	// events is closed after the subscription ends.
	events chan *TxDetail

	// wake signals the delivery goroutine that the queue grew.
	wake chan struct{}

	// mu guards queue.
	mu sync.Mutex

	// queue holds the events not yet sent on events.
	queue []*TxDetail
}

// Events returns the channel that delivers each wallet transaction change. An
// event with a nil Block reports an unconfirmed transaction; otherwise it
// reports the block that confirmed it. Each subscription receives its own
// copy, so changing an event's fields or slices does not affect another.
//
// The channel is closed once the subscription ends. Events still queued at
// that point are discarded; Err reports the reason.
func (s *TxSubscription) Events() <-chan *TxDetail {
	return s.events
}

// Cancel ends the subscription and releases its resources. It is safe to call
// more than once and after the subscription has already ended.
func (s *TxSubscription) Cancel() {
	s.cancel(context.Canceled)
}

// Err returns nil while the subscription is active. Afterwards it returns
// context.Canceled after Cancel, the cause of the subscription context ending,
// or ErrWalletStopped when the wallet stopped.
func (s *TxSubscription) Err() error {
	return context.Cause(s.ctx)
}

// push queues one event and wakes the delivery goroutine.
func (s *TxSubscription) push(detail *TxDetail) {
	s.mu.Lock()
	s.queue = append(s.queue, detail)
	s.mu.Unlock()

	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// pop removes the oldest queued event. It returns false when the queue is
// empty.
func (s *TxSubscription) pop() (*TxDetail, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.queue) == 0 {
		return nil, false
	}

	detail := s.queue[0]
	s.queue[0] = nil
	s.queue = s.queue[1:]

	return detail, true
}

// run sends queued events until the subscription ends.
func (s *TxSubscription) run() {
	for {
		detail, ok := s.pop()
		if !ok {
			select {
			case <-s.wake:
				continue

			case <-s.ctx.Done():
				return
			}
		}

		select {
		case s.events <- detail:

		case <-s.ctx.Done():
			return
		}
	}
}

// txNotifier fans committed transaction changes out to subscriptions. Events
// reach every subscription in the order deliver is called. The zero value is
// ready to use.
type txNotifier struct {
	// mu guards subs and closed, and orders deliveries.
	mu sync.Mutex

	// subs holds the active subscriptions.
	subs map[*TxSubscription]struct{}

	// closed is set by close, after which subscribe fails.
	closed bool

	// wg tracks the delivery goroutine of each subscription.
	wg sync.WaitGroup

	// recordMu serializes transaction writes that report events, so two
	// writers cannot both see a transaction as new.
	recordMu sync.Mutex
}

// subscribe registers a subscription that lives until ctx ends, the caller
// cancels it, or the notifier closes. It returns ErrWalletStopped after close.
func (n *txNotifier) subscribe(ctx context.Context) (*TxSubscription, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.closed {
		return nil, ErrWalletStopped
	}

	subCtx, cancel := context.WithCancelCause(ctx)
	sub := &TxSubscription{
		ctx:    subCtx,
		cancel: cancel,
		events: make(chan *TxDetail),
		wake:   make(chan struct{}, 1),
	}

	if n.subs == nil {
		n.subs = make(map[*TxSubscription]struct{})
	}

	n.subs[sub] = struct{}{}

	n.wg.Add(1)

	go func() {
		defer n.wg.Done()
		defer close(sub.events)
		defer n.remove(sub)

		sub.run()
	}()

	return sub, nil
}

// remove unregisters a subscription whose delivery goroutine has returned.
func (n *txNotifier) remove(sub *TxSubscription) {
	n.mu.Lock()
	defer n.mu.Unlock()

	delete(n.subs, sub)
}

// hasSubscribers reports whether any subscription is registered.
func (n *txNotifier) hasSubscribers() bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	return len(n.subs) > 0
}

// deliver queues a copy of detail on every registered subscription.
func (n *txNotifier) deliver(detail *TxDetail) {
	n.mu.Lock()
	defer n.mu.Unlock()

	for sub := range n.subs {
		sub.push(cloneTxDetail(detail))
	}
}

// close ends every subscription with ErrWalletStopped, rejects new ones, and
// waits for all delivery goroutines to return.
func (n *txNotifier) close() {
	n.mu.Lock()
	n.closed = true

	for sub := range n.subs {
		sub.cancel(ErrWalletStopped)
	}

	n.mu.Unlock()

	// Delivery goroutines take mu to unregister, so wait without it.
	n.wg.Wait()
}

// cloneTxDetail returns a copy of detail that shares no slice or block with
// it.
func cloneTxDetail(detail *TxDetail) *TxDetail {
	clone := *detail
	clone.RawTx = append([]byte(nil), detail.RawTx...)

	if detail.Block != nil {
		block := *detail.Block
		clone.Block = &block
	}

	if detail.Outputs != nil {
		clone.Outputs = make([]Output, len(detail.Outputs))
		for i, output := range detail.Outputs {
			output.Addresses = append(
				output.Addresses[:0:0], output.Addresses...,
			)
			output.PkScript = append([]byte(nil), output.PkScript...)
			clone.Outputs[i] = output
		}
	}

	if detail.PrevOuts != nil {
		clone.PrevOuts = append([]PrevOut(nil), detail.PrevOuts...)
	}

	return &clone
}

// txState is the committed state of one transaction before a write.
type txState struct {
	// known is set when the wallet has a record of the transaction.
	known bool

	// block is the confirming block hash, or nil when unconfirmed.
	block *chainhash.Hash
}

// txWrite names one transaction a write records and the block it records the
// transaction in, nil when the write records it unconfirmed.
type txWrite struct {
	hash  chainhash.Hash
	block *chainhash.Hash
}

// txWritesFromParams returns the transactions a Store batch records.
func txWritesFromParams(params []db.CreateTxParams) []txWrite {
	writes := make([]txWrite, 0, len(params))
	for _, param := range params {
		write := txWrite{hash: param.Tx.TxHash()}
		if param.Block != nil {
			write.block = &param.Block.Hash
		}

		writes = append(writes, write)
	}

	return writes
}

// txChanged reports whether after, read once a write committed, is a change
// that write made and subscribers should see. A write reports only the state
// it recorded, so the writer that records a confirmation is the one that
// reports it. An unconfirmed transaction is new only when the wallet had no
// record of it, and a confirmation is new unless the same block already
// confirmed it. Invalidated transactions are not reported.
func txChanged(before txState, wrote *chainhash.Hash, after *TxDetail) bool {
	switch {
	case after.Status != TxStatusPending &&
		after.Status != TxStatusPublished:

		return false

	case wrote == nil:
		return after.Block == nil && !before.known

	case after.Block == nil || after.Block.Hash != *wrote:
		return false

	default:
		return before.block == nil || *before.block != *wrote
	}
}

// txRecordEntry is one transaction tracked by a txRecord.
type txRecordEntry struct {
	txWrite

	// before is the committed state before the write.
	before txState
}

// txRecord captures the state of the transactions a write may change so the
// changes it commits can be delivered afterwards. A record with no subscribers
// at its start is inactive and delivers nothing.
type txRecord struct {
	// w reads committed state and owns the notifier.
	w *Wallet

	// entries lists the recorded transactions in delivery order. It is
	// nil for an inactive record.
	entries []txRecordEntry
}

// beginTxRecord reads the current state of the written transactions and holds
// the record lock until release. Call release once the write finishes, then
// deliver if it committed.
func (w *Wallet) beginTxRecord(ctx context.Context,
	writes []txWrite) (*txRecord, error) {

	rec := &txRecord{w: w}
	if len(writes) == 0 || !w.txEvents.hasSubscribers() {
		return rec, nil
	}

	w.txEvents.recordMu.Lock()

	entries := make([]txRecordEntry, 0, len(writes))
	index := make(map[chainhash.Hash]int, len(writes))

	for _, write := range writes {
		// A later write of the same transaction decides its final state.
		if i, ok := index[write.hash]; ok {
			entries[i].block = write.block

			continue
		}

		before, err := w.lookupTxState(ctx, write.hash)
		if err != nil {
			w.txEvents.recordMu.Unlock()

			return nil, err
		}

		index[write.hash] = len(entries)
		entries = append(entries, txRecordEntry{
			txWrite: write,
			before:  before,
		})
	}

	rec.entries = entries

	return rec, nil
}

// release lets other writers record transactions.
func (r *txRecord) release() {
	if r.entries != nil {
		r.w.txEvents.recordMu.Unlock()
	}
}

// deliver reads the committed state of each recorded transaction and delivers
// the ones the write changed. Reading and delivering under the record lock
// keeps events for one transaction in commit order across writers.
func (r *txRecord) deliver(ctx context.Context) {
	if r.entries == nil {
		return
	}

	r.w.txEvents.recordMu.Lock()
	defer r.w.txEvents.recordMu.Unlock()

	for _, entry := range r.entries {
		detail, err := r.w.lookupTxDetail(ctx, entry.hash)
		if errors.Is(err, ErrTxNotFound) {
			continue
		}

		if err != nil {
			log.Errorf("Unable to read transaction %v for "+
				"subscribers: %v", entry.hash, err)

			continue
		}

		if txChanged(entry.before, entry.block, detail) {
			r.w.txEvents.deliver(detail)
		}
	}
}

// lookupTxState returns the committed state of txHash.
func (w *Wallet) lookupTxState(ctx context.Context,
	txHash chainhash.Hash) (txState, error) {

	info, err := w.store.GetTx(ctx, db.GetTxQuery{
		WalletID: w.id,
		Txid:     txHash,
	})
	if errors.Is(err, db.ErrTxNotFound) {
		return txState{}, nil
	}

	if err != nil {
		return txState{}, fmt.Errorf("get tx %v: %w", txHash, err)
	}

	state := txState{known: true}
	if info.Block != nil {
		state.block = &info.Block.Hash
	}

	return state, nil
}

// lookupTxDetail returns the committed detail of txHash at the wallet's synced
// tip.
func (w *Wallet) lookupTxDetail(ctx context.Context,
	txHash chainhash.Hash) (*TxDetail, error) {

	//nolint:contextcheck // SyncedTo takes no context.
	return w.getTxDetail(ctx, txHash, w.SyncedTo().Height)
}
