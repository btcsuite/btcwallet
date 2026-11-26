package chain

import (
	"context"
	"errors"
	"sync"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wtxmgr"
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

	// scripts counts active WatchAddrs references per pkScript for
	// rollback and cleanup. Guarded by stream.mu.
	scripts map[string]int

	// outpoints counts active WatchOutputs and auto-indexed references per
	// outpoint for rollback and cleanup. Guarded by stream.mu.
	outpoints map[wire.OutPoint]int

	// autoOutpoints tracks received outpoints already auto-indexed on
	// delivery so each received output contributes one independent
	// reference to outpoints. Guarded by stream.mu.
	autoOutpoints map[wire.OutPoint]struct{}
}

// close publishes the terminal result before releasing callers waiting on Done.
func (l *eventListener) close(err error) {
	l.err = err
	l.scripts = nil
	l.outpoints = nil
	l.autoOutpoints = nil
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

	// client is the backing chain backend used to register address and
	// outpoint watches for active subscriptions. Guarded by mu; cleared on
	// close.
	client Interface

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
func newChainEventStream(params *chaincfg.Params,
	client Interface) *chainEventStream {

	return &chainEventStream{
		params:            params,
		client:            client,
		members:           make(map[*eventListener]func() bool),
		scriptListeners:   make(watchIndex[string]),
		outpointListeners: make(watchIndex[wire.OutPoint]),
	}
}

// indexWatch records key in index and increments its refcount in owned. Caller
// must hold s.mu.
func indexWatch[K comparable](index watchIndex[K], owned map[K]int,
	l *eventListener, key K) {

	if index[key] == nil {
		index[key] = make(map[*eventListener]struct{})
	}

	index[key][l] = struct{}{}
	owned[key]++
}

// unindexWatches removes l from index for every key in owned. Caller holds mu.
func unindexWatches[K comparable](index watchIndex[K], owned map[K]int,
	l *eventListener) {

	for key := range owned {
		delete(index[key], l)

		if len(index[key]) == 0 {
			delete(index, key)
		}
	}
}

// canRegisterWatch checks whether l may register watches. Call-site ctx.Err is
// checked first so shared deadlines preserve DeadlineExceeded. Caller must
// hold s.mu.
func (s *chainEventStream) canRegisterWatch(ctx context.Context,
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

// registerWatchKeys validates enrollment, indexes keys under s.mu, and returns
// the stream's backing client for watch delegation.
func registerWatchKeys[K comparable](ctx context.Context, s *chainEventStream,
	l *eventListener, canceled <-chan struct{}, index *watchIndex[K],
	owned *map[K]int, keys []K) (Interface, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	err := s.canRegisterWatch(ctx, l, canceled)
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		return s.client, nil
	}

	if *owned == nil {
		*owned = make(map[K]int, len(keys))
	}

	for _, key := range keys {
		indexWatch(*index, *owned, l, key)
	}

	return s.client, nil
}

// removeSubscriber removes l, unindexes its watches, and closes l with err.
// Caller must hold s.mu.
func (s *chainEventStream) removeSubscriber(l *eventListener, err error) {
	stop, ok := s.members[l]
	if !ok {
		log.Debugf("Subscriber already removed (err=%v)", err)

		return
	}

	delete(s.members, l)
	stop()

	unindexWatches(s.scriptListeners, l.scripts, l)
	unindexWatches(s.outpointListeners, l.outpoints, l)

	l.close(err)
}

// recordOutputMatches adds every listener in listeners to matched and
// auto-indexes op for each matched listener so subsequent spends of that
// received output are routed to the owning subscription. Caller holds s.mu.
func (s *chainEventStream) recordOutputMatches(
	listeners map[*eventListener]struct{}, op wire.OutPoint,
	matched *map[*eventListener]struct{}) {

	if len(listeners) == 0 {
		return
	}

	if *matched == nil {
		*matched = make(map[*eventListener]struct{}, len(listeners))
	}

	for l := range listeners {
		(*matched)[l] = struct{}{}
		if _, ok := l.autoOutpoints[op]; ok {
			continue
		}

		if l.autoOutpoints == nil {
			l.autoOutpoints = make(map[wire.OutPoint]struct{})
		}

		l.autoOutpoints[op] = struct{}{}
		if l.outpoints == nil {
			l.outpoints = make(map[wire.OutPoint]int)
		}

		indexWatch(s.outpointListeners, l.outpoints, l, op)
	}
}

// matchOutput checks whether pkScript matches any watched script directly or
// via extracted bare multisig pubkeys, adding matching listeners to matched
// and auto-indexing op for them. Caller must hold s.mu.
func (s *chainEventStream) matchOutput(pkScript []byte, op wire.OutPoint,
	matched *map[*eventListener]struct{}) {

	s.recordOutputMatches(s.scriptListeners[string(pkScript)], op, matched)

	// Bare multisig scripts do not match a single address pkScript, so
	// extract their constituent pubkeys and match against P2PK watches
	// without conflating P2PKH watches.
	if len(pkScript) == 0 ||
		pkScript[len(pkScript)-1] != txscript.OP_CHECKMULTISIG {

		return
	}

	class, addrs, _, err := txscript.ExtractPkScriptAddrs(
		pkScript, s.params,
	)
	if err != nil || class != txscript.MultiSigTy {
		return
	}

	for _, addr := range addrs {
		subScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			continue
		}

		s.recordOutputMatches(
			s.scriptListeners[string(subScript)], op, matched,
		)
	}
}

// addMatchedListeners inserts every listener from src into dst, lazily
// allocating dst on the first non-empty source set.
func addMatchedListeners(dst *map[*eventListener]struct{},
	src map[*eventListener]struct{}) {

	if len(src) == 0 {
		return
	}

	if *dst == nil {
		*dst = make(map[*eventListener]struct{}, len(src))
	}

	for l := range src {
		(*dst)[l] = struct{}{}
	}
}

// matchTxInputs checks every input of rec against watched outpoints and
// ComputePkScript-derived scripts. Caller must hold s.mu.
func (s *chainEventStream) matchTxInputs(rec *wtxmgr.TxRecord,
	matched *map[*eventListener]struct{}) {

	for _, txIn := range rec.MsgTx.TxIn {
		addMatchedListeners(
			matched, s.outpointListeners[txIn.PreviousOutPoint],
		)

		if len(s.scriptListeners) == 0 {
			continue
		}

		pkScript, err := txscript.ComputePkScript(
			txIn.SignatureScript, txIn.Witness,
		)
		if err != nil {
			continue
		}

		addMatchedListeners(
			matched, s.scriptListeners[string(pkScript.Script())],
		)
	}
}

// matchTx inspects each input and output of rec at most once and returns the
// set of listeners interested in rec, auto-indexing matched output outpoints
// for their owning listeners. Caller must hold s.mu.
func (s *chainEventStream) matchTx(
	rec *wtxmgr.TxRecord) map[*eventListener]struct{} {

	if len(s.scriptListeners) == 0 && len(s.outpointListeners) == 0 {
		return nil
	}

	var matched map[*eventListener]struct{}

	s.matchTxInputs(rec, &matched)

	if len(s.scriptListeners) > 0 {
		var idx uint32
		for _, txOut := range rec.MsgTx.TxOut {
			op := wire.OutPoint{
				Hash:  rec.Hash,
				Index: idx,
			}
			s.matchOutput(txOut.PkScript, op, &matched)

			idx++
		}
	}

	return matched
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
		s.mu.Lock()
		defer s.mu.Unlock()

		s.removeSubscriber(l, nil)
	})

	return sub
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
			s.removeSubscriber(
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
	s.client = nil
	s.members = nil
	s.scriptListeners = nil
	s.outpointListeners = nil
}
