package chain

import (
	"context"
	"errors"
	"sync"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// chainEventSubscriberBufferSize accommodates a burst of up to 50 ordinary
// two-event Bitcoin Core block pairs.
const chainEventSubscriberBufferSize = 100

// ErrEventSubscriptionBufferFull means a new event found a full buffer and
// ended that subscription.
var ErrEventSubscriptionBufferFull = errors.New("chain event buffer full")

// EventSubscription delivers native events in source order until it ends.
// Event payloads may be shared across subscribers. Copy any data you intend
// to modify.
type EventSubscription struct {
	// Events carries buffered notifications published after enrollment.
	Events <-chan any

	// Done closes after Events on cancellation, source shutdown, or buffer
	// overflow. Buffered events remain readable after closure.
	Done <-chan struct{}

	// listener gives Err access to the result stored before closure.
	listener *eventListener
}

// Err returns the terminal result after Done closes. Cancellation and source
// shutdown return nil. An offer to a full buffer ends the subscription with
// [ErrEventSubscriptionBufferFull].
func (s EventSubscription) Err() error {
	// Handles supplied by test doubles may only contain public channels.
	if s.listener == nil {
		return nil
	}

	// Observe the owner's close before reading the published result.
	select {
	case <-s.listener.done:
		return s.listener.err
	default:
		return nil
	}
}

// eventListener owns the writable ends for one subscription.
type eventListener struct {
	// events holds this listener's bounded buffer.
	events chan any

	// done signals that the listener can receive no further offers.
	done chan struct{}

	// err holds the terminal result published before done closes.
	err error

	// scripts tracks watched pkScripts for cleanup. Guarded by stream.mu.
	scripts map[string]struct{}

	// outpoints tracks watched outpoints for cleanup. Guarded by stream.mu.
	outpoints map[wire.OutPoint]struct{}
}

// close publishes the terminal result before releasing callers waiting on Done.
func (l *eventListener) close(err error) {
	l.err = err
	l.scripts = nil
	l.outpoints = nil
	close(l.events)
	close(l.done)
}

// watchIndex maps a comparable watch key to subscribed listeners.
type watchIndex[K comparable] map[K]map[*eventListener]struct{}

// chainEventStream tracks listeners for one native notification handler.
type chainEventStream struct {
	// params defines the Bitcoin network used when extracting scripts from
	// multi-key outputs such as bare multisig.
	params *chaincfg.Params

	// mu protects admission, publication and channel closure.
	mu sync.Mutex

	// members maps each listener to the function that stops its context
	// cancellation callback. A nil map means the owner retired the stream.
	members map[*eventListener]func() bool

	// scriptListeners maps watched pkScripts to active listeners.
	scriptListeners watchIndex[string]

	// outpointListeners maps watched outpoints to active listeners.
	//
	// TODO(yy): Prune confirmed spent outpoints past a reorg-safe depth.
	outpointListeners watchIndex[wire.OutPoint]
}

// newChainEventStream creates the registry for one running native owner.
func newChainEventStream(params *chaincfg.Params) *chainEventStream {
	return &chainEventStream{
		params:            params,
		members:           make(map[*eventListener]func() bool),
		scriptListeners:   make(watchIndex[string]),
		outpointListeners: make(watchIndex[wire.OutPoint]),
	}
}

// indexWatch records key in index and owned. Caller must hold s.mu.
func indexWatch[K comparable](index watchIndex[K], owned map[K]struct{},
	l *eventListener, key K) {

	if index[key] == nil {
		index[key] = make(map[*eventListener]struct{})
	}

	index[key][l] = struct{}{}
	owned[key] = struct{}{}
}

// unindexWatches removes l from index for every key in owned. Caller holds mu.
func unindexWatches[K comparable](index watchIndex[K], owned map[K]struct{},
	l *eventListener) {

	for key := range owned {
		delete(index[key], l)

		if len(index[key]) == 0 {
			delete(index, key)
		}
	}
}

// canRegisterWatchLocked checks whether l may register watches. Call-site
// ctx.Err is checked first so shared deadlines preserve DeadlineExceeded.
func (s *chainEventStream) canRegisterWatchLocked(ctx context.Context,
	l *eventListener, canceled <-chan struct{}) error {

	err := ctx.Err()
	if err != nil {
		return err
	}

	select {
	case <-canceled:
		return context.Canceled
	default:
	}

	if _, ok := s.members[l]; !ok {
		if l.err != nil {
			return l.err
		}

		return context.Canceled
	}

	return nil
}

// registerWatchKeys validates enrollment and indexes keys under s.mu.
func registerWatchKeys[K comparable](ctx context.Context, s *chainEventStream,
	l *eventListener, canceled <-chan struct{}, index *watchIndex[K],
	owned *map[K]struct{}, keys []K) error {

	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.canRegisterWatchLocked(ctx, l, canceled)
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		return nil
	}

	if *owned == nil {
		*owned = make(map[K]struct{}, len(keys))
	}

	for _, key := range keys {
		indexWatch(*index, *owned, l, key)
	}

	return nil
}

// indexScripts installs pkScripts into the reverse script index for l.
func (s *chainEventStream) indexScripts(ctx context.Context, l *eventListener,
	canceled <-chan struct{}, scripts []string) error {

	return registerWatchKeys(
		ctx, s, l, canceled, &s.scriptListeners, &l.scripts, scripts,
	)
}

// indexOutpoints installs outpoints into the reverse outpoint index for l.
func (s *chainEventStream) indexOutpoints(ctx context.Context,
	l *eventListener, canceled <-chan struct{},
	points []wire.OutPoint) error {

	return registerWatchKeys(
		ctx, s, l, canceled, &s.outpointListeners, &l.outpoints, points,
	)
}

// retireListenerLocked removes l, unindexes its watches, resets drained
// top-level maps, and closes l with err. Caller must hold s.mu.
func (s *chainEventStream) retireListenerLocked(l *eventListener, err error) {
	stop, ok := s.members[l]
	if !ok {
		return
	}

	delete(s.members, l)
	stop()

	hadScripts, hadOutpoints := len(l.scripts) > 0, len(l.outpoints) > 0
	unindexWatches(s.scriptListeners, l.scripts, l)
	unindexWatches(s.outpointListeners, l.outpoints, l)

	if len(s.members) == 0 {
		s.members = make(map[*eventListener]func() bool)
	}

	if hadScripts && len(s.scriptListeners) == 0 {
		s.scriptListeners = make(watchIndex[string])
	}

	if hadOutpoints && len(s.outpointListeners) == 0 {
		s.outpointListeners = make(watchIndex[wire.OutPoint])
	}

	l.close(err)
}

// subscribe registers the listener directly at the publication boundary.
func (s *chainEventStream) subscribe(ctx context.Context) EventSubscription {
	l := &eventListener{
		events: make(chan any, chainEventSubscriberBufferSize),
		done:   make(chan struct{}),
	}
	sub := EventSubscription{
		Events:   l.events,
		Done:     l.done,
		listener: l,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Close rejected handles before returning so callers can observe
	// completion even if the native owner has already exited.
	if ctx.Err() != nil || s.members == nil {
		l.close(nil)

		return sub
	}

	// Canceling an idle subscription does not require a native event.
	s.members[l] = context.AfterFunc(ctx, func() {
		s.removeListener(l)
	})

	return sub
}

// removeListener retires a listener whose context has been canceled.
func (s *chainEventStream) removeListener(l *eventListener) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.retireListenerLocked(l, nil)
}

// publish synchronously offers the event to each subscriber on the native
// owner. Delivery is asynchronous because the nonblocking send can place
// the event in the subscriber's buffer before the subscriber reads it.
// A failed offer retires only that subscriber and leaves its accepted
// events readable.
func (s *chainEventStream) publish(event any) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for l, stop := range s.members {
		select {
		case l.events <- event:
		default:
			// End delivery at the first gap and release the
			// cancellation callback even if the context stays live.
			_ = stop
			s.retireListenerLocked(
				l, ErrEventSubscriptionBufferFull,
			)
		}
	}
}

// close retires the remaining listeners and rejects subsequent registrations.
func (s *chainEventStream) close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for l, stop := range s.members {
		stop()
		l.close(nil)
	}

	// A stopped client can outlive its subscriptions and their buffers.
	s.members = nil
	s.scriptListeners = nil
	s.outpointListeners = nil
}
