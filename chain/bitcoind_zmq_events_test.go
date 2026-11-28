package chain

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// fakeZMQConn is a deterministic zmqConn test double that blocks in Receive
// until Close unblocks it with a wrapped net.ErrClosed error.
type fakeZMQConn struct {
	quit           <-chan struct{}
	entered        chan struct{}
	enterOnce      sync.Once
	closed         chan struct{}
	closeOnce      sync.Once
	closeDelay     time.Duration
	receiveCalls   atomic.Int32
	sawQuitOnClose atomic.Bool
}

// newFakeZMQConn initializes a fakeZMQConn observing quit.
func newFakeZMQConn(quit <-chan struct{},
	closeDelay time.Duration) *fakeZMQConn {

	return &fakeZMQConn{
		quit:       quit,
		entered:    make(chan struct{}),
		closed:     make(chan struct{}),
		closeDelay: closeDelay,
	}
}

// Receive records the call, signals the first entry, waits until Close is
// invoked, and returns a wrapped net.ErrClosed matching a closed TCP socket.
func (f *fakeZMQConn) Receive([][]byte) ([][]byte, error) {
	f.receiveCalls.Add(1)
	f.enterOnce.Do(func() {
		close(f.entered)
	})

	<-f.closed

	return nil, &net.OpError{
		Op:  "read",
		Net: "tcp",
		Err: net.ErrClosed,
	}
}

// Close records whether quit was already closed, unblocks Receive, and
// optionally sleeps briefly to expose any shutdown race window.
func (f *fakeZMQConn) Close() error {
	select {
	case <-f.quit:
		f.sawQuitOnClose.Store(true)
	default:
	}

	f.closeOnce.Do(func() {
		close(f.closed)
	})

	if f.closeDelay > 0 {
		time.Sleep(f.closeDelay)
	}

	return nil
}

// RemoteAddr returns a deterministic loopback address for startup logging.
func (f *fakeZMQConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10062}
}

// fakeTimeoutError implements net.Error with Timeout() == true.
type fakeTimeoutError struct{}

// Error returns a static timeout description.
func (fakeTimeoutError) Error() string { return "i/o timeout" }

// Timeout reports true.
func (fakeTimeoutError) Timeout() bool { return true }

// Temporary reports true.
func (fakeTimeoutError) Temporary() bool { return true }

// TestBitcoindZMQEventsStopClosesQuitBeforeSockets verifies that Stop signals
// quit before closing the ZMQ connections so neither txEventHandler nor
// blockEventHandler spins on closed-socket Receive errors during shutdown.
func TestBitcoindZMQEventsStopClosesQuitBeforeSockets(t *testing.T) {
	t.Parallel()

	// Arrange: start bitcoindZMQEvents with fake sockets where
	// blockConn.Close delays briefly to widen the window after
	// txConn.Close returns.
	quit := make(chan struct{})
	txConn := newFakeZMQConn(quit, 0)
	blockConn := newFakeZMQConn(quit, 20*time.Millisecond)

	events := &bitcoindZMQEvents{
		cfg:           &ZMQConfig{},
		blockConn:     blockConn,
		txConn:        txConn,
		hasPrevoutRPC: true,
		blockNtfns:    make(chan *wire.MsgBlock),
		txNtfns:       make(chan *wire.MsgTx),
		mempool:       newMempool(&mempoolConfig{}),
		quit:          quit,
	}

	require.NoError(t, events.Start())

	select {
	case <-txConn.entered:
	case <-time.After(defaultTestTimeout):
		require.FailNow(t, "txEventHandler did not enter Receive")
	}

	select {
	case <-blockConn.entered:
	case <-time.After(defaultTestTimeout):
		require.FailNow(t, "blockEventHandler did not enter Receive")
	}

	// Act: stop bitcoindZMQEvents while both handlers are blocked in
	// Receive.
	err := events.Stop()

	// Assert: Stop succeeded, quit was closed before either socket closed,
	// and each handler exited after a single Receive without spinning.
	require.NoError(t, err)
	require.True(t, txConn.sawQuitOnClose.Load())
	require.True(t, blockConn.sawQuitOnClose.Load())
	require.Equal(t, int32(1), txConn.receiveCalls.Load())
	require.Equal(t, int32(1), blockConn.receiveCalls.Load())
}

// TestHandleZMQReceiveError verifies that handleZMQReceiveError exits quietly
// on shutdown, io.EOF, and wrapped net.ErrClosed while keeping the loop alive
// for timeouts and transient errors.
func TestHandleZMQReceiveError(t *testing.T) {
	t.Parallel()

	closedQuit := make(chan struct{})
	close(closedQuit)

	openQuit := make(chan struct{})

	testCases := []struct {
		name       string
		quit       <-chan struct{}
		err        error
		wantReturn bool
	}{
		{
			name:       "closed quit exits on any error",
			quit:       closedQuit,
			err:        errors.New("transient read failure"),
			wantReturn: true,
		},
		{
			name:       "eof exits",
			quit:       openQuit,
			err:        io.EOF,
			wantReturn: true,
		},
		{
			name: "wrapped closed conn exits",
			quit: openQuit,
			err: &net.OpError{
				Op:  "read",
				Net: "tcp",
				Err: net.ErrClosed,
			},
			wantReturn: true,
		},
		{
			name:       "timeout continues",
			quit:       openQuit,
			err:        fakeTimeoutError{},
			wantReturn: false,
		},
		{
			name:       "unexpected error continues",
			quit:       openQuit,
			err:        errors.New("unexpected zmq frame"),
			wantReturn: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act: classify the Receive error under the case's quit
			// channel state.
			got := handleZMQReceiveError(
				tc.quit, rawTxZMQCommand, tc.err,
			)

			// Assert: handler exit decision matches expectation.
			require.Equal(t, tc.wantReturn, got)
		})
	}
}
