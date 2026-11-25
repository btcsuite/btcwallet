package chain

import (
	"container/list"
)

// ConcurrentQueue is a concurrent-safe FIFO queue with unbounded capacity.
// Clients interact with the queue by pushing items into the in channel and
// popping items from the out channel. There is a goroutine that manages moving
// items from the in channel to the out channel in the correct order that must
// be started by calling Start().
type ConcurrentQueue struct {
	chanIn   chan interface{}
	chanOut  chan interface{}
	quit     chan struct{}
	overflow *list.List
}

// NewConcurrentQueue constructs a ConcurrentQueue. The bufferSize parameter is
// the capacity of the output channel. When the size of the queue is below this
// threshold, pushes do not incur the overhead of the less efficient overflow
// structure.
func NewConcurrentQueue(bufferSize int) *ConcurrentQueue {
	return &ConcurrentQueue{
		chanIn:   make(chan interface{}),
		chanOut:  make(chan interface{}, bufferSize),
		quit:     make(chan struct{}),
		overflow: list.New(),
	}
}

// ChanIn returns a channel that can be used to push new items into the queue.
func (cq *ConcurrentQueue) ChanIn() chan<- interface{} {
	return cq.chanIn
}

// ChanOut returns a channel that can be used to pop items from the queue.
func (cq *ConcurrentQueue) ChanOut() <-chan interface{} {
	return cq.chanOut
}

// Start begins a goroutine that manages moving items from the in channel to
// the out channel. The queue tries to move items directly to the out channel
// minimize overhead, but if the out channel is full it pushes items to an
// overflow queue. This must be called before using the queue.
func (cq *ConcurrentQueue) Start() {
	// A standalone queue only needs its original FIFO path.
	go cq.run(nil, nil)
}

// run owns FIFO buffering and offers events to the optional live stream.
// Stop retires the queue. A backing source can also retire it.
func (cq *ConcurrentQueue) run(stream *chainEventStream,
	sourceQuit <-chan struct{}) {

	for {
		// Offer the legacy overflow head only while a backlog exists.
		var (
			out  chan<- any
			next any
		)

		head := cq.overflow.Front()
		if head != nil {
			out, next = cq.chanOut, head.Value
		}

		select {
		case item := <-cq.chanIn:
			// A live offer does not depend on the FIFO reader.
			if stream != nil {
				stream.publish(item)
			}

			cq.enqueue(item)

		case out <- next:
			cq.overflow.Remove(head)

		case <-cq.quit:
			return

		case <-sourceQuit:
			return
		}
	}
}

// enqueue preserves FIFO order when called before startup or by the owner.
func (cq *ConcurrentQueue) enqueue(item any) {
	// Bypass the overflow list only when no older event is there.
	if cq.overflow.Len() == 0 {
		select {
		case cq.chanOut <- item:
			return
		default:
		}
	}

	cq.overflow.PushBack(item)
}

// Stop ends the goroutine that moves items from the in channel to the out
// channel.
func (cq *ConcurrentQueue) Stop() {
	close(cq.quit)
}
