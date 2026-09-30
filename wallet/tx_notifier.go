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

// TxSubscriptionQueueLimit is the most undelivered events a transaction
// subscription buffers before it ends with ErrTxSubscriptionOverflow.
const TxSubscriptionQueueLimit = 1000

// ErrTxEventLost ends transaction subscriptions when the wallet committed a
// change but could not read it to report. Callers can match it with errors.Is,
// then resubscribe and use ListTxns to catch up.
var ErrTxEventLost = errors.New("transaction event lost")

// ErrTxSubscriptionOverflow ends a transaction subscription whose reader fell
// TxSubscriptionQueueLimit events behind. Callers can match it with
// errors.Is, then resubscribe and use ListTxns to catch up.
var ErrTxSubscriptionOverflow = errors.New(
	"transaction subscription queue full",
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
// go unreported. Subscribing does not replay what the wallet already records;
// use ListTxns for it. A later recovery or rescan can still report historical
// transactions it newly records or newly confirms.
//
// The wallet reports a transaction the chain backend relays unconfirmed when
// it first records it, and reports each block that newly confirms a wallet
// transaction, including after a reorg. A confirmation is reported once the
// wallet's synced tip reaches its block, so it carries at least one
// confirmation. A transaction disconnected by a reorg is not reported until a
// block confirms it again. Chain backends that do not relay unconfirmed
// transactions, such as neutrino, only produce confirmations.
//
// The subscription lives until ctx ends, Cancel is called, its reader falls
// TxSubscriptionQueueLimit events behind, a committed change cannot be read
// for it (ErrTxEventLost), or the wallet stops; Err then reports which. The
// wallet must be started.
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
// buffers up to TxSubscriptionQueueLimit undelivered events, so a slow reader
// never stalls the wallet. A reader that falls further behind loses its
// subscription, which ends with ErrTxSubscriptionOverflow rather than skipping
// events.
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

	// mu guards queue and undelivered.
	mu sync.Mutex

	// queue holds the events the delivery goroutine has not taken yet.
	queue []*TxDetail

	// undelivered counts the queued events plus the one being sent.
	undelivered int
}

// Events returns the channel that delivers each wallet transaction change. An
// event with a nil Block reports an unconfirmed transaction; otherwise it
// reports the block that confirmed it. Each subscription receives its own
// TxDetail, slices and Block, so changing them does not affect another. The
// address values in Output.Addresses are shared and must be treated as
// read-only.
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
// ErrTxSubscriptionOverflow when the reader fell too far behind, or
// ErrWalletStopped when the wallet stopped.
func (s *TxSubscription) Err() error {
	return context.Cause(s.ctx)
}

// push queues one event and wakes the delivery goroutine. A full queue ends
// the subscription with ErrTxSubscriptionOverflow instead.
func (s *TxSubscription) push(detail *TxDetail) {
	s.mu.Lock()

	if s.undelivered >= TxSubscriptionQueueLimit {
		s.mu.Unlock()
		s.cancel(ErrTxSubscriptionOverflow)

		return
	}

	s.queue = append(s.queue, detail)
	s.undelivered++
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
			s.mu.Lock()
			s.undelivered--
			s.mu.Unlock()

			log.Tracef("Delivered transaction event: txid=%v, "+
				"confirmed=%v", detail.Hash, detail.Block != nil)

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
	// writers cannot both see a transaction as new. It also guards pending.
	recordMu sync.Mutex

	// pending holds confirmations whose block is above the wallet's synced
	// tip, until the tip reaches it.
	pending []pendingTxEvent
}

// pendingTxEvent is a confirmation held until the wallet's synced tip reaches
// its block.
type pendingTxEvent struct {
	hash   chainhash.Hash
	block  chainhash.Hash
	height int32
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

	log.Debugf("Transaction subscription started")

	go func() {
		defer n.wg.Done()
		defer close(sub.events)
		defer n.remove(sub)

		sub.run()

		log.Debugf("Transaction subscription ended: %v",
			context.Cause(sub.ctx))
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

// endAll ends every registered subscription with cause.
func (n *txNotifier) endAll(cause error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	for sub := range n.subs {
		sub.cancel(cause)
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
// it. The address values in Output.Addresses are shared, not copied.
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
// at its start is inactive and reports none of its own changes.
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
	seen := make(map[chainhash.Hash]struct{}, len(writes))

	for _, write := range writes {
		// A batch the Store commits records one state per transaction, so
		// a repeated hash adds nothing to track.
		if _, ok := seen[write.hash]; ok {
			continue
		}

		before, err := w.lookupTxState(ctx, write.hash)
		if err != nil {
			w.txEvents.recordMu.Unlock()

			return nil, err
		}

		seen[write.hash] = struct{}{}
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

// deliver reports the changes the committed write made, then the held
// confirmations the wallet's synced tip has reached. Reading and delivering
// under the record lock keeps events for one transaction in commit order
// across writers. A confirmation above the tip is held rather than reported
// with no confirmations. If a committed change cannot be read, every
// subscription ends with ErrTxEventLost rather than missing it.
func (r *txRecord) deliver(ctx context.Context) {
	n := &r.w.txEvents

	n.recordMu.Lock()
	defer n.recordMu.Unlock()

	if r.entries == nil && len(n.pending) == 0 {
		return
	}

	// Read the tip once: on SQL wallets each SyncedTo call reads the Store.
	//
	//nolint:contextcheck // SyncedTo takes no context.
	height := r.w.SyncedTo().Height

	for i, entry := range r.entries {
		err := r.report(ctx, i, height)
		if err != nil {
			r.w.failTxEvents(ctx, entry.hash, err)

			return
		}
	}

	r.w.flushPendingTxEvents(ctx, height)
}

// report delivers the change the write made to entry i, holds it if its block
// is above the synced tip at height, or does nothing if the write changed
// nothing to report. The caller holds the record lock.
func (r *txRecord) report(ctx context.Context, i int, height int32) error {
	n := &r.w.txEvents
	entry := r.entries[i]

	detail, err := r.w.getTxDetail(ctx, entry.hash, height)
	if errors.Is(err, ErrTxNotFound) {
		return nil
	}

	if err != nil {
		return err
	}

	if !txChanged(entry.before, entry.block, detail) {
		return nil
	}

	if detail.Block != nil && detail.Block.Height > height {
		n.pending = append(n.pending, pendingTxEvent{
			hash:   entry.hash,
			block:  detail.Block.Hash,
			height: detail.Block.Height,
		})

		return nil
	}

	n.deliver(detail)

	return nil
}

// flushPendingTxEvents reports the held confirmations whose block the synced
// tip at height has reached. A confirmation no longer in that block is dropped:
// a disconnect is not reported, and a write that confirms the transaction in
// another block reports that itself. The caller holds the record lock.
func (w *Wallet) flushPendingTxEvents(ctx context.Context, height int32) {
	n := &w.txEvents

	kept := n.pending[:0]
	for _, event := range n.pending {
		if event.height > height {
			kept = append(kept, event)

			continue
		}

		detail, err := w.getTxDetail(ctx, event.hash, height)
		if errors.Is(err, ErrTxNotFound) {
			continue
		}

		if err != nil {
			w.failTxEvents(ctx, event.hash, err)

			return
		}

		if detail.Block != nil && detail.Block.Hash == event.block {
			n.deliver(detail)
		}
	}

	clear(n.pending[len(kept):])
	n.pending = kept
}

// failTxEvents ends every subscription because the committed change to txHash
// could not be read. A read canceled by the wallet shutting down ends them with
// ErrWalletStopped instead. The caller holds the record lock.
func (w *Wallet) failTxEvents(ctx context.Context, txHash chainhash.Hash,
	err error) {

	cause := fmt.Errorf("%w: tx %v: %w", ErrTxEventLost, txHash, err)
	if ctx.Err() != nil {
		cause = ErrWalletStopped
	}

	log.Errorf("Ending transaction subscriptions: %v", cause)

	w.txEvents.pending = nil
	w.txEvents.endAll(cause)
}

// txEventStore is the Store the syncer writes through. Its batch writes record
// the transaction changes they commit and report them to subscribers, so the
// Wallet rather than the syncer owns notification.
type txEventStore struct {
	db.Store

	w *Wallet
}

// ApplyTxBatch applies the batch and reports the transaction changes it
// committed.
func (s *txEventStore) ApplyTxBatch(ctx context.Context,
	params db.TxBatchParams) error {

	rec, err := s.beginRecord(ctx, params.Transactions)
	if err != nil {
		return err
	}

	err = s.Store.ApplyTxBatch(ctx, params)

	rec.release()

	if err != nil {
		return err //nolint:wrapcheck // The decorator is transparent.
	}

	rec.deliver(ctx)

	return nil
}

// ApplyScanBatch applies the batch and reports the transaction changes it
// committed.
func (s *txEventStore) ApplyScanBatch(ctx context.Context,
	params db.ScanBatchParams) error {

	rec, err := s.beginRecord(ctx, params.Transactions)
	if err != nil {
		return err
	}

	err = s.Store.ApplyScanBatch(ctx, params)

	rec.release()

	if err != nil {
		return err //nolint:wrapcheck // The decorator is transparent.
	}

	rec.deliver(ctx)

	return nil
}

// beginRecord starts a record of the transactions a batch writes. Without a
// subscriber it returns an inactive record before hashing any transaction.
func (s *txEventStore) beginRecord(ctx context.Context,
	transactions []db.CreateTxParams) (*txRecord, error) {

	if !s.w.txEvents.hasSubscribers() {
		return &txRecord{w: s.w}, nil
	}

	return s.w.beginTxRecord(ctx, txWritesFromParams(transactions))
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
