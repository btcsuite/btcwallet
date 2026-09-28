// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"sync"
)

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
