package chain

import (
	"context"
	"errors"
	"sync"
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
}

// close publishes the terminal result before releasing callers waiting on Done.
func (l *eventListener) close(err error) {
	l.err = err
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

	// Shutdown or overflow may retire the listener while its cancellation
	// callback is waiting for the mutex.
	if _, ok := s.members[l]; !ok {
		return
	}

	delete(s.members, l)
	l.close(nil)
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
			delete(s.members, l)
			stop()
			l.close(ErrEventSubscriptionBufferFull)
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
}
