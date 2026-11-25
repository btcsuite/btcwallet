package chain

import (
	"context"
	"sync"
)

// chainEventSubscriberBufferSize fits two four-event Neutrino
// rescan-boundary batches and one ordinary two-event block pair. Larger
// bursts can overflow a subscriber's buffer.
const chainEventSubscriberBufferSize = 10

// EventSubscription delivers best-effort native events in source order.
// Event payloads may be shared across subscribers. Copy any data you intend
// to modify.
type EventSubscription struct {
	// Events carries buffered notifications published after enrollment.
	Events <-chan any

	// Done closes after Events on cancellation or source shutdown, even
	// when the subscriber cannot drain Events.
	Done <-chan struct{}
}

// eventListener owns the writable ends for one subscription.
type eventListener struct {
	// events holds this listener's bounded buffer.
	events chan any

	// done signals that the listener can receive no further offers.
	done chan struct{}
}

// close retires Events before publishing completion to the consumer.
func (l *eventListener) close() {
	close(l.events)
	close(l.done)
}

// chainEventStream tracks listeners for one native notification handler.
type chainEventStream struct {
	// mu protects admission, publication and channel closure.
	mu sync.Mutex

	// members maps each listener to the function that stops its context
	// cancellation callback. A nil map means the owner retired the stream.
	members map[*eventListener]func() bool
}

// newChainEventStream creates the registry for one running native owner.
func newChainEventStream() *chainEventStream {
	return &chainEventStream{
		members: make(map[*eventListener]func() bool),
	}
}

// subscribe registers the listener directly at the publication boundary.
func (s *chainEventStream) subscribe(ctx context.Context) EventSubscription {
	l := &eventListener{
		events: make(chan any, chainEventSubscriberBufferSize),
		done:   make(chan struct{}),
	}
	sub := EventSubscription{Events: l.events, Done: l.done}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Close rejected handles before returning so callers can observe
	// completion even if the native owner has already exited.
	if ctx.Err() != nil || s.members == nil {
		l.close()

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

	// Shutdown may have retired the listener while its callback waited
	// for the mutex.
	if _, ok := s.members[l]; !ok {
		return
	}

	delete(s.members, l)
	l.close()
}

// publish performs fan-out synchronously on the native owner. Each subscriber
// consumes its buffered events asynchronously. A full buffer drops the new
// offer for that subscriber without waiting for it to drain.
func (s *chainEventStream) publish(event any) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for l := range s.members {
		select {
		case l.events <- event:
		default:
		}
	}
}

// close retires the remaining listeners and rejects subsequent registrations.
func (s *chainEventStream) close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for l, stop := range s.members {
		stop()
		l.close()
	}

	// A stopped client can outlive its subscriptions and their buffers.
	s.members = nil
}
