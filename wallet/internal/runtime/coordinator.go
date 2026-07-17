// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package runtime implements the Stage 3 per-wallet mutation gate and the
// Cache And Commit Protocol over the semantic db.RuntimeStore. It is the
// consumer side of the runtime contract the wallet will adopt: it prepares
// work without the gate, commits one short durable operation under the gate,
// and publishes the in-memory cache only after the durable commit agrees.
//
// The Phase 1A spike models one operation, allocating an account's next
// address-branch index, with a simple per-account next-index cache. Later
// phases reuse this gate, lock order, and protocol for every semantic
// operation, replacing the spike cache with the real manager caches.
package runtime

import (
	"context"
	"errors"
	"sync"

	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
)

// BranchKey identifies one account branch whose next index the coordinator
// caches and allocates.
type BranchKey struct {
	// Scope is the account's key scope.
	Scope waddrmgr.KeyScope

	// Account is the account number within the scope.
	Account uint32

	// Branch is the derivation branch, external or internal.
	Branch uint32
}

// Reservation is the result of allocating a branch index through the
// coordinator.
type Reservation struct {
	// AllocatedIndex is the index the caller reserved.
	AllocatedIndex uint32

	// NextIndex is the account's new next index after the allocation.
	NextIndex uint32

	// Replayed is true when the durable state was not changed by this call
	// because the operation had already committed.
	Replayed bool
}

// Coordinator implements the Cache And Commit Protocol for one wallet. It owns
// the per-wallet mutation gate and a next-index cache and drives durable
// mutations through a semantic db.RuntimeStore.
//
// Lock order: the mutation gate is the sole and outermost lock. Preparation
// takes no lock beyond a brief shared hold to read the cache; the durable
// commit and the cache publication run under one exclusive hold. When the real
// manager and scoped-manager mutexes are integrated in later phases they are
// always acquired after the gate, never before it, so the one lock order is
// gate -> manager -> scoped-manager.
type Coordinator struct {
	// gate is the per-wallet mutation gate, held by pointer so it is never
	// copied. Cache reads take it in shared mode; the durable commit and
	// cache publication take it exclusively.
	gate *sync.RWMutex

	// store is the semantic runtime store that owns the durable transactions.
	store walletstore.RuntimeStore

	// cache maps a branch to its next index. It is authoritative for local
	// allocation once warm and is accessed only while holding gate.
	cache map[BranchKey]uint32

	// beforePublish is a test seam invoked while the gate is held
	// exclusively, after a durable commit and before the cache publication.
	// It is nil in production.
	beforePublish func()
}

// Option configures a Coordinator.
type Option func(*Coordinator)

// WithBeforePublish installs a test seam invoked under the exclusive gate,
// after a durable commit and before the cache publication. It lets a test
// observe the window in which the database has committed but the cache has not
// yet been published.
func WithBeforePublish(hook func()) Option {
	return func(c *Coordinator) {
		c.beforePublish = hook
	}
}

// New constructs a Coordinator over a semantic runtime store.
func New(store walletstore.RuntimeStore, opts ...Option) *Coordinator {
	c := &Coordinator{
		gate:  &sync.RWMutex{},
		store: store,
		cache: make(map[BranchKey]uint32),
	}
	for _, opt := range opts {
		opt(c)
	}

	return c
}

// CachedNextIndex returns the cached next index for a branch, taking the
// mutation gate in shared mode. It is the cache-sensitive read a concurrent
// caller uses. It observes a value consistent with the durable commit order
// because a committing writer holds the gate exclusively across its
// compare-and-swap and cache publication, so a shared reader never sees a
// committed index before its cache update. The boolean is false when the branch
// is not cached yet.
func (c *Coordinator) CachedNextIndex(key BranchKey) (uint32, bool) {
	c.gate.RLock()
	defer c.gate.RUnlock()

	index, ok := c.cache[key]

	return index, ok
}

// ReserveNextIndex allocates the account's next branch index following the
// Cache And Commit Protocol:
//
//  1. Prepare a next-index snapshot without holding the gate.
//  2. Acquire the gate exclusively for the durable commit.
//  3. Revalidate the prepared expected value against the cache.
//  4. Run the short database-only compare-and-swap commit.
//  5. On success publish the new index into the cache under the gate.
//  6. On ordinary failure leave the cache unchanged.
//  7. On an ambiguous commit reread durable state and publish or reload.
func (c *Coordinator) ReserveNextIndex(ctx context.Context, key BranchKey,
	operationID []byte) (Reservation, error) {

	// Prepare without the gate: read the expected-index snapshot, preferring
	// the warm cache (a shared-gate read) and falling back to a durable
	// snapshot. A real caller would derive and encrypt the address for the
	// expected index here, still without the gate.
	expected, cached := c.CachedNextIndex(key)
	if !cached {
		var err error

		expected, err = c.store.CurrentBranchIndex(
			ctx, key.Scope, key.Account, key.Branch,
		)
		if err != nil {
			return Reservation{}, err
		}
	}

	// Acquire the mutation gate exclusively for the semantic commit and the
	// cache publication.
	c.gate.Lock()
	defer c.gate.Unlock()

	// Revalidate: if a local allocation advanced the cache while we prepared,
	// adopt the newer expected value. A real caller would re-prepare the
	// derived address here; the spike carries no prepared address.
	if current, ok := c.cache[key]; ok {
		expected = current
	}

	result, err := c.store.ReserveNextBranchIndex(
		ctx, walletstore.ReserveBranchIndexRequest{
			Scope:         key.Scope,
			Account:       key.Account,
			Branch:        key.Branch,
			ExpectedIndex: expected,
			OperationID:   operationID,
		},
	)
	switch {
	// The durable outcome is unknown: resolve it by durable reread while
	// still holding the gate, never by repeating the compare-and-swap.
	case errors.Is(err, walletstore.ErrAmbiguousCommit):
		return c.resolveAmbiguous(ctx, key, operationID)

	// A cross-process writer advanced the index: reload the cache from
	// durable state and let the caller re-prepare. The cache is otherwise
	// unchanged.
	case errors.Is(err, walletstore.ErrStaleAccountIndex):
		c.reload(ctx, key)

		return Reservation{}, err

	// Any other failure leaves the cache unchanged.
	case err != nil:
		return Reservation{}, err
	}

	// Publish the committed index into the cache while holding the gate.
	return c.publish(key, result), nil
}

// publish records a committed reservation into the cache under the exclusive
// gate and returns its Reservation. It publishes only when the cached value
// changes, so an idempotent replay produces no duplicate cache mutation.
func (c *Coordinator) publish(key BranchKey,
	result walletstore.ReserveBranchIndexResult) Reservation {

	if current, ok := c.cache[key]; !ok || current != result.NextIndex {
		if c.beforePublish != nil {
			c.beforePublish()
		}

		c.cache[key] = result.NextIndex
	}

	return Reservation{
		AllocatedIndex: result.AllocatedIndex,
		NextIndex:      result.NextIndex,
		Replayed:       result.Replayed,
	}
}

// resolveAmbiguous resolves an ambiguous commit while the exclusive gate is
// held. It rereads the durable journal: a committed reservation is published
// into the cache; otherwise the cache is reloaded from durable state and the
// ambiguity is reported so the caller re-prepares. It never repeats the
// compare-and-swap.
func (c *Coordinator) resolveAmbiguous(ctx context.Context, key BranchKey,
	operationID []byte) (Reservation, error) {

	result, found, err := c.store.LookupBranchIndexReservation(
		ctx, operationID,
	)
	if err != nil {
		return Reservation{}, err
	}

	if found {
		return c.publish(key, result), nil
	}

	c.reload(ctx, key)

	return Reservation{}, walletstore.ErrAmbiguousCommit
}

// reload refreshes the cached next index from durable state under the exclusive
// gate, used after a cross-process advance or an unresolved ambiguous commit.
func (c *Coordinator) reload(ctx context.Context, key BranchKey) {
	index, err := c.store.CurrentBranchIndex(
		ctx, key.Scope, key.Account, key.Branch,
	)
	if err == nil {
		c.cache[key] = index
	}
}
