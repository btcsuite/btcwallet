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
