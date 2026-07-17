// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package runtime implements the Stage 3 per-wallet mutation gate and the
// Cache And Commit Protocol over the semantic db.RuntimeStore. It is the
// consumer side of the runtime contract the wallet will adopt: it prepares
// work without the gate, commits one short durable operation under the gate,
// publishes the in-memory cache only after the durable commit agrees, and
// delivers post-commit notifications after releasing the gate.
//
// The Phase 1A spike modeled one operation, allocating an account's next
// address-branch index. Phase 1B adds the representative second operation,
// advancing the wallet's synced tip, and generalizes the gate protocol into one
// audited implementation both operations reuse. The same Coordinator drives the
// SQL and KV runtime stores identically; their stale, ambiguous, and guard
// signals are internal to each backend and never observed differently here.
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

// TipAdvance is the result of advancing the wallet's synced tip through the
// coordinator.
type TipAdvance struct {
	// Tip is the wallet's synced tip after the advance.
	Tip walletstore.BlockRef

	// Replayed is true when the durable state was not changed by this call
	// because the operation had already committed.
	Replayed bool

	// Events are the fully materialized post-commit events the advance
	// produced. They are delivered to the notifier after the gate is released
	// and are also returned so the caller can publish them itself.
	Events []walletstore.Event
}

// Coordinator implements the Cache And Commit Protocol for one wallet. It owns
// the per-wallet mutation gate and the caches address allocation and tip
// advances rely on, and drives durable mutations through a semantic
// db.RuntimeStore.
//
// Lock order: the mutation gate is the sole and outermost lock. Preparation
// takes no lock beyond a brief shared hold to read a cache; the durable commit
// and the cache publication run under one exclusive hold; notification delivery
// happens after the gate is released. When the real manager and scoped-manager
// mutexes are integrated in later phases they are always acquired after the
// gate, never before it, so the one lock order is gate -> manager ->
// scoped-manager.
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

	// lastAccount maps a key scope to its cached last allocated account,
	// authoritative for local account-number allocation once warm and
	// accessed only while holding gate. It stands in for the manager's account
	// map, which the live wallet integrates in Phase 2B.
	lastAccount map[waddrmgr.KeyScope]uint32

	// scopes is the set of key scopes known to exist, published after a scope
	// is created. It is accessed only while holding gate.
	scopes map[waddrmgr.KeyScope]struct{}

	// tip is the wallet's cached synced tip, authoritative once tipSet is
	// true, accessed only while holding gate.
	tip    walletstore.BlockRef
	tipSet bool

	// beforePublish is a test seam invoked while the gate is held
	// exclusively, after a durable commit and before the cache publication.
	// It is nil in production.
	beforePublish func()

	// notifier receives the post-commit events an operation produced, after
	// the gate is released. It is nil when no consumer is registered.
	notifier func([]walletstore.Event)
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

// WithNotifier registers a consumer for the post-commit events an operation
// produces. The coordinator invokes it after releasing the mutation gate, so
// notification delivery never overlaps a durable commit or cache publication.
func WithNotifier(notifier func([]walletstore.Event)) Option {
	return func(c *Coordinator) {
		c.notifier = notifier
	}
}

// New constructs a Coordinator over a semantic runtime store.
func New(store walletstore.RuntimeStore, opts ...Option) *Coordinator {
	c := &Coordinator{
		gate:        &sync.RWMutex{},
		store:       store,
		cache:       make(map[BranchKey]uint32),
		lastAccount: make(map[waddrmgr.KeyScope]uint32),
		scopes:      make(map[waddrmgr.KeyScope]struct{}),
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

// CachedTip returns the cached synced tip, taking the mutation gate in shared
// mode. The boolean is false when the tip is not cached yet.
func (c *Coordinator) CachedTip() (walletstore.BlockRef, bool) {
	c.gate.RLock()
	defer c.gate.RUnlock()

	return c.tip, c.tipSet
}

// ReserveNextIndex allocates the account's next branch index following the
// Cache And Commit Protocol: prepare a next-index snapshot without the gate,
// then commit and publish under the shared gate protocol.
func (c *Coordinator) ReserveNextIndex(ctx context.Context, key BranchKey,
	operationID []byte) (Reservation, error) {

	// Prepare without the gate: read the expected-index snapshot, preferring
	// the warm cache and falling back to a durable snapshot. A real caller
	// would derive and encrypt the address for the expected index here, still
	// without the gate.
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

	return runGated(
		c, ctx, walletstore.ErrStaleAccountIndex,
		// commit: revalidate the expected index against the cache under the
		// gate, then run the durable compare-and-swap.
		func() (Reservation, error) {
			if current, ok := c.cache[key]; ok {
				expected = current
			}

			res, err := c.store.ReserveNextBranchIndex(
				ctx, walletstore.ReserveBranchIndexRequest{
					Scope:         key.Scope,
					Account:       key.Account,
					Branch:        key.Branch,
					ExpectedIndex: expected,
					OperationID:   operationID,
				},
			)
			if err != nil {
				return Reservation{}, err
			}

			return Reservation{
				AllocatedIndex: res.AllocatedIndex,
				NextIndex:      res.NextIndex,
				Replayed:       res.Replayed,
			}, nil
		},
		// resolve: reread the durable journal after an ambiguous commit.
		func() (Reservation, bool, error) {
			res, found, err := c.store.LookupBranchIndexReservation(
				ctx, operationID,
			)
			if err != nil || !found {
				return Reservation{}, found, err
			}

			return Reservation{
				AllocatedIndex: res.AllocatedIndex,
				NextIndex:      res.NextIndex,
				Replayed:       res.Replayed,
			}, true, nil
		},
		// reload: refresh the cache from durable state after a conflict.
		func() { c.reloadIndex(ctx, key) },
		// publish: record the new index under the gate; no event.
		func(r Reservation) []walletstore.Event {
			c.publishIndex(key, r.NextIndex)

			return nil
		},
	)
}

// AdvanceTip advances the wallet's synced tip to newTip following the Cache And
// Commit Protocol: prepare the expected-tip snapshot without the gate, then
// commit, publish, and notify under the shared gate protocol.
func (c *Coordinator) AdvanceTip(ctx context.Context,
	newTip walletstore.BlockRef, operationID []byte) (TipAdvance, error) {

	// Prepare without the gate: read the expected-tip snapshot, preferring the
	// warm cache and falling back to a durable snapshot. A real caller would
	// validate the connecting header here, still without the gate.
	expected, cached := c.CachedTip()
	if !cached {
		var err error

		expected, err = c.store.CurrentSyncedTip(ctx)
		if err != nil {
			return TipAdvance{}, err
		}
	}

	return runGated(
		c, ctx, walletstore.ErrStaleTip,
		// commit: revalidate the expected tip against the cache under the
		// gate, then run the durable compare-and-swap.
		func() (TipAdvance, error) {
			if c.tipSet {
				expected = c.tip
			}

			res, err := c.store.AdvanceWalletTip(
				ctx, walletstore.AdvanceTipRequest{
					ExpectedTip: expected,
					NewTip:      newTip,
					OperationID: operationID,
				},
			)
			if err != nil {
				return TipAdvance{}, err
			}

			return TipAdvance{
				Tip:      res.Tip,
				Replayed: res.Replayed,
				Events:   res.Events,
			}, nil
		},
		// resolve: reread the durable journal after an ambiguous commit.
		func() (TipAdvance, bool, error) {
			res, found, err := c.store.LookupTipAdvance(
				ctx, operationID,
			)
			if err != nil || !found {
				return TipAdvance{}, found, err
			}

			return TipAdvance{
				Tip:      res.Tip,
				Replayed: res.Replayed,
				Events:   res.Events,
			}, true, nil
		},
		// reload: refresh the cache from durable state after a conflict.
		func() { c.reloadTip(ctx) },
		// publish: record the new tip under the gate; return its events.
		func(r TipAdvance) []walletstore.Event {
			c.publishTip(r.Tip)

			return r.Events
		},
	)
}

// runGated runs one semantic operation under the exclusive mutation gate,
// following the Cache And Commit Protocol so every operation shares one audited
// implementation. commit runs the durable operation; on an ambiguous commit
// resolve rereads durable state without repeating the mutation; on a conflict
// matching staleErr reload refreshes the cache; publish records the committed
// result into the cache and returns the events to deliver. The gate is held
// across commit and publication and released before notification.
//
// resolve may be nil for a naturally idempotent operation that keeps no
// operation journal to reread; an ambiguous commit then reloads the affected
// cache domain and surfaces ErrAmbiguousCommit, so the caller re-prepares and
// re-runs the idempotent operation rather than repeating a non-idempotent one.
func runGated[R any](c *Coordinator, ctx context.Context, staleErr error,
	commit func() (R, error), resolve func() (R, bool, error),
	reload func(), publish func(R) []walletstore.Event) (R, error) {

	var zero R

	c.gate.Lock()

	result, err := commit()
	switch {
	// The durable outcome is unknown: resolve it by durable reread while still
	// holding the gate, never by repeating the mutation.
	case errors.Is(err, walletstore.ErrAmbiguousCommit):
		if resolve == nil {
			reload()
			c.gate.Unlock()

			return zero, walletstore.ErrAmbiguousCommit
		}

		resolved, found, rerr := resolve()
		if rerr != nil {
			c.gate.Unlock()

			return zero, rerr
		}

		if !found {
			reload()
			c.gate.Unlock()

			return zero, walletstore.ErrAmbiguousCommit
		}

		result = resolved

	// A cross-process writer moved the durable record: reload the cache from
	// durable state and let the caller re-prepare. The cache is otherwise
	// unchanged. A nil staleErr means the operation has no stale conflict.
	case staleErr != nil && errors.Is(err, staleErr):
		reload()
		c.gate.Unlock()

		return zero, err

	// Any other failure leaves the cache unchanged.
	case err != nil:
		c.gate.Unlock()

		return zero, err
	}

	// Publish the committed result into the cache while holding the gate, then
	// release it before delivering notifications.
	events := publish(result)

	c.gate.Unlock()

	c.notify(ctx, events)

	return result, nil
}

// notify delivers an operation's post-commit events after the gate is released,
// honoring the delayed and dropped notification failpoints carried on ctx.
func (c *Coordinator) notify(ctx context.Context, events []walletstore.Event) {
	if len(events) == 0 {
		return
	}

	fp := walletstore.FailpointsFromContext(ctx)
	fp.RunBeforeNotify()

	if fp.Dropped() {
		return
	}

	if c.notifier != nil {
		c.notifier(events)
	}
}

// publishIndex records a committed reservation's next index into the cache under
// the exclusive gate. It publishes only when the cached value changes, so an
// idempotent replay produces no duplicate cache mutation.
func (c *Coordinator) publishIndex(key BranchKey, nextIndex uint32) {
	if current, ok := c.cache[key]; !ok || current != nextIndex {
		if c.beforePublish != nil {
			c.beforePublish()
		}

		c.cache[key] = nextIndex
	}
}

// publishTip records a committed tip into the cache under the exclusive gate. It
// publishes only when the cached tip changes, so an idempotent replay produces
// no duplicate cache mutation.
func (c *Coordinator) publishTip(tip walletstore.BlockRef) {
	if !c.tipSet || c.tip.Hash != tip.Hash {
		if c.beforePublish != nil {
			c.beforePublish()
		}

		c.tip = tip
		c.tipSet = true
	}
}

// reloadIndex refreshes the cached next index from durable state under the
// exclusive gate, used after a cross-process advance or an unresolved ambiguous
// commit.
func (c *Coordinator) reloadIndex(ctx context.Context, key BranchKey) {
	index, err := c.store.CurrentBranchIndex(
		ctx, key.Scope, key.Account, key.Branch,
	)
	if err == nil {
		c.cache[key] = index
	}
}

// reloadTip refreshes the cached synced tip from durable state under the
// exclusive gate, used after a cross-process advance or an unresolved ambiguous
// commit.
func (c *Coordinator) reloadTip(ctx context.Context) {
	tip, err := c.store.CurrentSyncedTip(ctx)
	if err == nil {
		c.tip = tip
		c.tipSet = true
	}
}
