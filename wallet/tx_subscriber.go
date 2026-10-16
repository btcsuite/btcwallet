// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"time"
)

// TxSubscriptionQueueLimit bounds each stream's retained notifications. A full
// stream discards its oldest notification to make room for the incoming one.
const TxSubscriptionQueueLimit = 1000

// TxSubscriber provides wallet-scoped transaction observations without exposing
// transaction-writing or Wallet lifecycle operations.
type TxSubscriber interface {
	// SubscribeTxns returns future best-effort transaction events and a cleanup
	// function. Subscribe before initiating work: late registration may miss
	// events, and observations may repeat or arrive out of transaction order,
	// without replay. Subscriber count is uncapped; queues retain the newest
	// TxSubscriptionQueueLimit events.
	//
	// Incoming unconfirmed events depend on the chain backend's mempool feed,
	// which Neutrino does not provide. Local Broadcast events and confirmed
	// chain observations are available across all supported backends.
	//
	// Context completion or Wallet shutdown closes the stream. The returned
	// cancel function is safe to call repeatedly or concurrently; it discards
	// queued events and closes the channel before returning, but cannot recall
	// a received event. It may wait for Wallet control requests. Failure
	// returns nil results.
	SubscribeTxns(ctx context.Context) (<-chan *TxEvent, func(), error)
}

// A compile-time assertion to ensure that Wallet implements the TxSubscriber
// interface.
var _ TxSubscriber = (*Wallet)(nil)

// TxEvent describes one Wallet observation, separate from stored
// transaction history. Repeated observations need not arrive in time order.
type TxEvent struct {
	// Detail belongs to this subscriber, including its mutable slices and
	// Block. Address objects remain read-only. Block identifies confirmation.
	Detail *TxDetail

	// Timestamp records when notification preparation began, not when the
	// transaction or its block was received. It does not establish ordering.
	Timestamp time.Time
}

// txSubscription retains only the event queue and cleanup acknowledgement.
// Closing done also releases the Wallet handler that owns this lifetime.
type txSubscription struct {
	events chan *TxEvent
	done   chan struct{}
}

// subscribeTxns registers before exposing the stream, so cancellation
// always finds its record. Allocate the map only for subscribed Wallets.
func (w *Wallet) subscribeTxns() *txSubscription {
	w.txSubscribersMu.Lock()
	defer w.txSubscribersMu.Unlock()

	sub := &txSubscription{
		events: make(chan *TxEvent, TxSubscriptionQueueLimit),
		done:   make(chan struct{}),
	}
	if w.txSubscribers == nil {
		w.txSubscribers = make(map[*txSubscription]struct{})
	}

	w.txSubscribers[sub] = struct{}{}

	return sub
}

// cancelTxSubscription removes membership before closure, making every
// termination path idempotent. The mutex excludes refill during the drain.
func (w *Wallet) cancelTxSubscription(sub *txSubscription) {
	w.txSubscribersMu.Lock()
	defer w.txSubscribersMu.Unlock()

	if _, active := w.txSubscribers[sub]; !active {
		return
	}

	delete(w.txSubscribers, sub)

	// Consumers can race the drain; never wait for them to release payloads.
	for {
		select {
		case <-sub.events:
		default:
			close(sub.events)
			close(sub.done)

			return
		}
	}
}

// subscribeTxnsReq retains caller cancellation in the existing joined handler,
// keeping registration and stream teardown within Wallet's shutdown boundary.
type subscribeTxnsReq struct {
	reqCtx

	respChan chan subscribeTxnsResp
}

// subscribeTxnsResp transfers an admitted record or its registration error.
type subscribeTxnsResp struct {
	sub *txSubscription
	err error
}

// cancelTxSubscriptionReq asks mainLoop to remove a stream; sub.done
// acknowledges cleanup without another response channel or Wallet reference.
type cancelTxSubscriptionReq struct {
	sub *txSubscription
}

// SubscribeTxns implements TxSubscriber using Wallet's request admission and
// joined lifetime handlers so registration and cleanup participate in shutdown.
func (w *Wallet) SubscribeTxns(ctx context.Context) (<-chan *TxEvent, func(),
	error) {

	err := w.state.validateStarted()
	if err != nil {
		return nil, nil, err
	}

	// Admission joins registration and its lifetime handler through Stop.
	r := subscribeTxnsReq{
		reqCtx:   reqCtx{ctx: ctx},
		respChan: make(chan subscribeTxnsResp, 1),
	}

	err = w.sendReq(ctx, r)
	if err != nil {
		return nil, nil, err
	}

	result := <-r.respChan
	if result.err != nil {
		return nil, nil, result.err
	}

	// Capture channels, not the owning Wallet. A request transfers cleanup to
	// mainLoop; if shutdown wins, the admitted lifetime handler finishes it.
	sub := result.sub
	requests, quit := w.requestChan, w.lifetimeCtx.Done()
	cancel := func() {
		select {
		case requests <- cancelTxSubscriptionReq{sub: sub}:
		case <-sub.done:
			return
		case <-quit:
		}

		<-sub.done
	}

	return sub.events, cancel, nil
}

// handleSubscribeTxns registers and watches a stream using the existing joined
// request handler. It exits when any cancellation path acknowledges cleanup.
func (w *Wallet) handleSubscribeTxns(r subscribeTxnsReq) {
	err := r.ctx.Err()
	if err != nil {
		r.respChan <- subscribeTxnsResp{err: err}

		return
	}

	if w.lifetimeCtx.Err() != nil {
		r.respChan <- subscribeTxnsResp{err: ErrWalletStopped}

		return
	}

	sub := w.subscribeTxns()
	r.respChan <- subscribeTxnsResp{sub: sub}

	// Context and shutdown cleanup bypass request admission, which may already
	// be stopped. All paths share the same send/close synchronization.
	select {
	case <-r.ctx.Done():
		w.cancelTxSubscription(sub)
	case <-w.lifetimeCtx.Done():
		w.cancelTxSubscription(sub)
	case <-sub.done:
	}
}
