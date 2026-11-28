package chain

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

const (
	// chainEventSubscriberBufferSize holds up to 100 normalized block
	// Events per subscription (connected and disconnected blocks).
	chainEventSubscriberBufferSize = 100

	// chainMempoolSubscriberBufferSize holds up to 1000 matching
	// unconfirmed tx records per subscription before dropping excess
	// mempool notifications. Typical wallet txns are ~1-2 KB in heap
	// (MsgTx plus SerializedTx), so 1000 slots absorb mempool bursts in
	// ~1-2 MB while keeping worst-case unread memory bounded even against
	// max-weight standard txns (400k WU / ~400 KB serialized, ~0.8-1 MB
	// in heap; matching subscribers share *wtxmgr.TxRecord pointers).
	//
	// TODO(yy): make this value configurable.
	chainMempoolSubscriberBufferSize = 1000

	// compressedP2PKScriptLen is the byte length of a standard compressed
	// P2PK script (OP_DATA_33 + 33-byte pubkey + OP_CHECKSIG).
	compressedP2PKScriptLen = 35

	// uncompressedP2PKScriptLen is the byte length of a standard
	// uncompressed P2PK script (OP_DATA_65 + 65-byte pubkey + OP_CHECKSIG).
	uncompressedP2PKScriptLen = 67
)

// ErrEventSubscriptionBufferFull means a new block event found a full
// BlockEvents buffer and ended that subscription.
var ErrEventSubscriptionBufferFull = errors.New("chain event buffer full")

// EventType identifies the kind of normalized block event delivered on
// EventSubscription.BlockEvents.
type EventType uint8

const (
	// EventUnknown identifies an unset or zero-value EventType.
	// Subscriptions never emit this value for a live event.
	EventUnknown EventType = iota

	// EventBlockConnected reports one connected block carrying both Block
	// metadata and matching RelevantTxs in block order. Callers must invoke
	// NotifyBlocks to receive block connection events.
	EventBlockConnected

	// EventBlockDisconnected reports one disconnected block carrying Block
	// metadata. It is the sole signal across backends when a detached block
	// silently reinserts txns into the backend mempool. Callers must invoke
	// NotifyBlocks to receive disconnect events.
	EventBlockDisconnected
)

// Event is a normalized block lifecycle notification delivered on
// EventSubscription.BlockEvents.
type Event struct {
	// Type distinguishes connected blocks from disconnected blocks.
	Type EventType

	// Block carries block metadata for EventBlockConnected and
	// EventBlockDisconnected.
	Block *wtxmgr.BlockMeta

	// RelevantTxs carries matching txns in block order for
	// EventBlockConnected, and is nil for EventBlockDisconnected.
	RelevantTxs []*wtxmgr.TxRecord
}

// EventSubscription delivers scoped chain notifications until it ends. Block
// lifecycle events arrive strictly ordered on BlockEvents, while unconfirmed
// matching txns arrive best-effort on MempoolTxns. Payloads may be shared
// across subscribers; copy before mutating. Watches and auto-indexed outpoints
// grow unboundedly until retirement.
type EventSubscription interface {
	// BlockEvents returns the bounded channel carrying strictly ordered
	// block Events (EventBlockConnected and EventBlockDisconnected)
	// published after enrollment. Sending to a full BlockEvents buffer
	// closes both BlockEvents and MempoolTxns and retires the subscription
	// with [ErrEventSubscriptionBufferFull], leaving already-buffered items
	// readable.
	BlockEvents() <-chan Event

	// MempoolTxns returns the bounded channel carrying matching unconfirmed
	// tx records published after enrollment. Delivery is best-effort: when
	// MempoolTxns is full, incoming mempool tx notifications are dropped
	// without blocking BlockEvents, retiring the subscription, or setting
	// [ErrEventSubscriptionBufferFull]. Already-matched outputs are still
	// auto-indexed for subsequent spend matching. On Bitcoin Core in ZMQ
	// mode, rawtx also publishes directly-mined block txns without block
	// metadata, so a directly-mined tx may appear on both MempoolTxns and
	// BlockEvents. Neutrino never sends on MempoolTxns. The channel closes
	// before Done on cancellation, source shutdown, or BlockEvents
	// overflow.
	MempoolTxns() <-chan *wtxmgr.TxRecord

	// Done returns a channel that closes after both BlockEvents and
	// MempoolTxns close on cancellation, source shutdown, or BlockEvents
	// buffer overflow.
	Done() <-chan struct{}

	// Err returns the terminal result after Done closes. Cancellation and
	// source shutdown return nil. Overflowing BlockEvents ends the
	// subscription with [ErrEventSubscriptionBufferFull].
	Err() error

	// WatchAddrs registers addrs on this subscription and delegates to
	// WatchAddrsFromTip. Received outputs are auto-indexed on delivery;
	// NotifyBlocks is required for block events and block-confirmed spend
	// tracking.
	WatchAddrs(ctx context.Context, addrs []address.Address) error

	// WatchOutputs registers points on this subscription and delegates to
	// NotifySpent, keeping its no-complete-mempool-snapshot contract
	// (Neutrino's NotifySpent is a no-op so it only scopes txns surfaced
	// by its active scan).
	WatchOutputs(ctx context.Context, points []*wire.OutPoint) error
}

// eventSubscription is the concrete EventSubscription backed by a
// chainEventStream.
type eventSubscription struct {
	// stream is the owning event stream that manages watch indices and
	// delegates watch registration to the backing chain client.
	stream *chainEventStream

	// listener gives BlockEvents, MempoolTxns, Done, Err, and watch
	// registration access to this subscription's state and terminal result.
	listener *eventListener

	// canceled mirrors the subscription context's Done channel so watch
	// registration fails promptly once the subscription is canceled.
	canceled <-chan struct{}
}

// A compile-time check to ensure eventSubscription implements
// EventSubscription.
var _ EventSubscription = eventSubscription{}

// BlockEvents returns the channel carrying buffered block Events published
// after enrollment.
func (s eventSubscription) BlockEvents() <-chan Event {
	return s.listener.blockEvents
}

// MempoolTxns returns the channel carrying best-effort matching unconfirmed tx
// records published after enrollment.
func (s eventSubscription) MempoolTxns() <-chan *wtxmgr.TxRecord {
	return s.listener.mempoolTxns
}

// Done returns a channel that closes after BlockEvents and MempoolTxns on
// cancellation, source shutdown, or BlockEvents buffer overflow.
func (s eventSubscription) Done() <-chan struct{} {
	return s.listener.done
}

// Err returns the terminal result after Done closes. Cancellation and source
// shutdown return nil. Overflowing BlockEvents ends the subscription with
// [ErrEventSubscriptionBufferFull].
func (s eventSubscription) Err() error {
	// Observe the owner's close before reading the published result.
	select {
	case <-s.listener.done:
		return s.listener.err
	default:
		return nil
	}
}

// WatchAddrs registers addrs on this subscription and delegates to
// WatchAddrsFromTip. Received outputs are auto-indexed on delivery;
// NotifyBlocks is required for block events and block-confirmed spend tracking.
func (s eventSubscription) WatchAddrs(ctx context.Context,
	addrs []address.Address) error {

	err := ctx.Err()
	if err != nil {
		return err
	}

	scripts := make([]string, len(addrs))
	for i, addr := range addrs {
		if addr == nil {
			return fmt.Errorf("%w: nil addr %d", ErrInvalidParam, i)
		}

		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return fmt.Errorf("pkScript for %v: %w", addr, err)
		}

		scripts[i] = string(pkScript)
	}

	// Install keys under s.mu and release the lock before delegating so
	// any synchronous notification emitted during WatchAddrsFromTip sees
	// the watch without reentering s.mu.
	client, err := registerWatchKeys(
		ctx, s.stream, s.listener, s.canceled,
		&s.stream.scriptListeners, &s.listener.scripts, scripts,
	)
	if err != nil {
		return err
	}

	err = client.WatchAddrsFromTip(ctx, addrs)
	if err != nil {
		rollbackWatchKeys(
			s.stream, s.listener, &s.stream.scriptListeners,
			&s.listener.scripts, scripts,
		)

		return fmt.Errorf("register address watches: %w", err)
	}

	return nil
}

// WatchOutputs registers points on this subscription and delegates to
// NotifySpent, keeping its no-complete-mempool-snapshot contract (Neutrino's
// NotifySpent is a no-op so it only scopes txns surfaced by its active scan).
func (s eventSubscription) WatchOutputs(ctx context.Context,
	points []*wire.OutPoint) error {

	err := ctx.Err()
	if err != nil {
		return err
	}

	flat := make([]wire.OutPoint, len(points))
	for i, op := range points {
		if op == nil {
			return fmt.Errorf("%w: nil op %d", ErrInvalidParam, i)
		}

		flat[i] = *op
	}

	// Install keys under s.mu and release the lock before delegating so
	// synchronous spend delivery during NotifySpent (for example, Bitcoin
	// Core reporting an existing mempool spend) sees the watch without
	// reentering s.mu.
	client, err := registerWatchKeys(
		ctx, s.stream, s.listener, s.canceled,
		&s.stream.outpointListeners, &s.listener.outpoints, flat,
	)
	if err != nil {
		return err
	}

	err = client.NotifySpent(points)
	if err != nil {
		rollbackWatchKeys(
			s.stream, s.listener, &s.stream.outpointListeners,
			&s.listener.outpoints, flat,
		)

		return fmt.Errorf("register output watches: %w", err)
	}

	return nil
}

// eventListener owns the writable ends for one subscription.
type eventListener struct {
	// blockEvents holds this listener's bounded strictly-ordered block
	// event buffer.
	blockEvents chan Event

	// mempoolTxns holds this listener's bounded best-effort mempool tx
	// buffer.
	mempoolTxns chan *wtxmgr.TxRecord

	// done signals that no further events will be sent to this listener.
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

// close publishes the terminal result and closes both delivery channels before
// releasing callers waiting on Done.
func (l *eventListener) close(err error) {
	l.err = err
	l.scripts = nil
	l.outpoints = nil
	l.autoOutpoints = nil
	close(l.blockEvents)
	close(l.mempoolTxns)
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

// rollbackWatchKeys decrements each key in keys for l after a failed backend
// registration, unindexing only keys whose reference count reaches zero.
func rollbackWatchKeys[K comparable](s *chainEventStream, l *eventListener,
	index *watchIndex[K], owned *map[K]int, keys []K) {

	if len(keys) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.members[l]; !ok {
		return
	}

	for _, key := range keys {
		if count := (*owned)[key] - 1; count > 0 {
			(*owned)[key] = count

			continue
		}

		delete(*owned, key)
		delete((*index)[key], l)

		if len((*index)[key]) == 0 {
			delete(*index, key)
		}
	}

	if len(*owned) == 0 {
		*owned = nil
	}
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

// mayHavePubKeyEquivalence reports whether pkScript can be a standard P2PK
// (35- or 67-byte script ending in OP_CHECKSIG) or bare multisig (ending in
// OP_CHECKMULTISIG) script, gating ExtractPkScriptAddrs so P2PKH, P2WPKH,
// P2SH, and P2TR outputs incur no fallback parsing.
func mayHavePubKeyEquivalence(pkScript []byte) bool {
	n := len(pkScript)
	if n == 0 {
		return false
	}

	last := pkScript[n-1]
	if last == txscript.OP_CHECKMULTISIG {
		return true
	}

	return last == txscript.OP_CHECKSIG &&
		(n == compressedP2PKScriptLen || n == uncompressedP2PKScriptLen)
}

// matchExtractedPubKey matches one pubkey extracted from a P2PK or bare
// multisig output against P2PK watches (for bare multisig) and equivalent
// P2PKH watches (for both P2PK and bare multisig). Caller must hold s.mu.
func (s *chainEventStream) matchExtractedPubKey(class txscript.ScriptClass,
	addr address.Address, op wire.OutPoint,
	matched *map[*eventListener]struct{}) {

	if class == txscript.MultiSigTy {
		subScript, err := txscript.PayToAddrScript(addr)
		if err == nil {
			s.recordOutputMatches(
				s.scriptListeners[string(subScript)], op,
				matched,
			)
		}
	}

	pka, ok := addr.(*address.AddressPubKey)
	if !ok {
		return
	}

	pkhScript, err := txscript.PayToAddrScript(pka.AddressPubKeyHash())
	if err != nil {
		return
	}

	s.recordOutputMatches(
		s.scriptListeners[string(pkhScript)], op, matched,
	)
}

// matchOutput checks whether pkScript matches any watched script directly or
// via extracted P2PK and bare-multisig pubkeys (including their equivalent
// P2PKH scripts for legacy btcd+KVDB key equivalence), adding matching
// listeners to matched and auto-indexing op for them. Caller must hold s.mu.
func (s *chainEventStream) matchOutput(pkScript []byte, op wire.OutPoint,
	matched *map[*eventListener]struct{}) {

	s.recordOutputMatches(s.scriptListeners[string(pkScript)], op, matched)

	if !mayHavePubKeyEquivalence(pkScript) {
		return
	}

	class, addrs, _, err := txscript.ExtractPkScriptAddrs(
		pkScript, s.params,
	)
	if err != nil ||
		(class != txscript.PubKeyTy && class != txscript.MultiSigTy) {

		return
	}

	for _, addr := range addrs {
		s.matchExtractedPubKey(class, addr, op, matched)
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
func (s *chainEventStream) subscribe(ctx context.Context) *eventSubscription {
	l := &eventListener{
		blockEvents: make(chan Event, chainEventSubscriberBufferSize),
		mempoolTxns: make(
			chan *wtxmgr.TxRecord, chainMempoolSubscriberBufferSize,
		),
		done: make(chan struct{}),
	}
	sub := &eventSubscription{
		stream:   s,
		listener: l,
		canceled: ctx.Done(),
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

// hasSubscribers reports whether at least one subscriber is enrolled.
func (s *chainEventStream) hasSubscribers() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.members) > 0
}

// sendBlockEvent attempts a non-blocking send of ev to l.blockEvents and
// removes l with ErrEventSubscriptionBufferFull if its block buffer is full.
// Caller must hold s.mu.
func (s *chainEventStream) sendBlockEvent(l *eventListener, ev Event) {
	select {
	case l.blockEvents <- ev:
	default:
		// End delivery at the first block gap, unindex the removed
		// subscriber's watches, and release its cancellation callback
		// even if the context stays live.
		s.removeSubscriber(l, ErrEventSubscriptionBufferFull)
	}
}

// sendMempoolTx attempts a best-effort non-blocking send of rec to
// l.mempoolTxns. When the mempool buffer is full, the tx notification is
// dropped without I/O, blocking block delivery, or retiring l. Caller must
// hold s.mu.
func (s *chainEventStream) sendMempoolTx(l *eventListener,
	rec *wtxmgr.TxRecord) {

	select {
	case l.mempoolTxns <- rec:
	default:
		// Intentionally drop without logging or other I/O under s.mu so
		// a stalled mempool reader cannot delay BlockEvents delivery.
	}
}

// publishFilteredBlock routes each tx in n to matching listeners in block
// order and sends one EventBlockConnected per active listener. Caller must hold
// s.mu.
func (s *chainEventStream) publishFilteredBlock(n FilteredBlockConnected) {
	var byListener map[*eventListener][]*wtxmgr.TxRecord
	if len(n.RelevantTxs) > 0 {
		byListener = make(map[*eventListener][]*wtxmgr.TxRecord)
	}

	for _, rec := range n.RelevantTxs {
		for l := range s.matchTx(rec) {
			byListener[l] = append(byListener[l], rec)
		}
	}

	for l := range s.members {
		s.sendBlockEvent(l, Event{
			Type:        EventBlockConnected,
			Block:       n.Block,
			RelevantTxs: byListener[l],
		})
	}
}

// publishBlockDisconnected sends one EventBlockDisconnected for n to every
// active listener. Caller must hold s.mu.
func (s *chainEventStream) publishBlockDisconnected(n BlockDisconnected) {
	blk := wtxmgr.BlockMeta(n)

	ev := Event{
		Type:  EventBlockDisconnected,
		Block: &blk,
	}
	for l := range s.members {
		s.sendBlockEvent(l, ev)
	}
}

// publishMempoolTx routes an unconfirmed tx in n to each matching listener's
// MempoolTxns channel after auto-indexing matched outputs. Confirmed RelevantTx
// notifications are ignored because block-confirmed txns are delivered in
// FilteredBlockConnected. Caller must hold s.mu.
func (s *chainEventStream) publishMempoolTx(n RelevantTx) {
	if n.Block != nil {
		return
	}

	matched := s.matchTx(n.TxRecord)
	if len(matched) == 0 {
		return
	}

	for l := range matched {
		s.sendMempoolTx(l, n.TxRecord)
	}
}

// publish synchronously normalizes and sends event to each matching subscriber
// on the native owner. Overflowing BlockEvents removes only that subscriber
// and leaves its accepted items readable; a full MempoolTxns buffer drops the
// mempool notification without retiring the subscriber.
func (s *chainEventStream) publish(event any) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch n := event.(type) {
	case FilteredBlockConnected:
		s.publishFilteredBlock(n)

	case BlockDisconnected:
		s.publishBlockDisconnected(n)

	case RelevantTx:
		s.publishMempoolTx(n)
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
