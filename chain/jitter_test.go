package chain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestCalculateMinMax tests the calculation of the min and max jitter values.
func TestCalculateMinMax(t *testing.T) {
	tests := []struct {
		name     string
		duration int64
		scaler   float64
		expected struct {
			min int64
			max int64
		}
	}{
		{
			name:     "Scaler is 0",
			duration: 1000,
			scaler:   0,
			expected: struct{ min, max int64 }{1000, 1000},
		},
		{
			name:     "Scaler is 0.5",
			duration: 1000,
			scaler:   0.5,
			expected: struct{ min, max int64 }{500, 1500},
		},
		{
			name:     "Scaler is 1",
			duration: 1000,
			scaler:   1,
			expected: struct{ min, max int64 }{0, 2000},
		},
		{
			name:     "Scaler is greater than 1",
			duration: 1000,
			scaler:   1.5,
			expected: struct{ min, max int64 }{0, 2500},
		},
		{
			name:     "Negative scaler",
			duration: 1000,
			scaler:   -0.5,
			expected: struct{ min, max int64 }{0, 0},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Catch the panic if the scaler is negative.
			if tc.scaler < 0 {
				defer func() {
					require.NotNil(t, recover(),
						"expect panic")
				}()
			}

			min, max := calculateMinMax(
				time.Duration(tc.duration), tc.scaler,
			)
			require.Equal(t, tc.expected.min, min)
			require.Equal(t, tc.expected.max, max)
		})
	}
}

func TestJitterTicker(t *testing.T) {
	// Create a new JitterTicker with a duration of 100ms and a scaler of
	// 0.2.
	ticker := NewJitterTicker(100*time.Millisecond, 0.2)

	// Wait for the ticker to tick 5 times and collect the tick times.
	var tickTimes []time.Time
	for i := 0; i < 5; i++ {
		tickTime := <-ticker.C
		tickTimes = append(tickTimes, tickTime)
	}

	// Stop the ticker.
	ticker.Stop()

	// Check that the tick times are within the expected range.
	for i := 1; i < len(tickTimes); i++ {
		diff := tickTimes[i].Sub(tickTimes[i-1])

		// Tick duration should be between 80ms and 120ms.
		require.True(t, diff >= 80*time.Millisecond, "diff: %v", diff)

		// We give 1ms more to account for the time it takes to run the
		// code.
		require.True(t, diff < 121*time.Millisecond, "diff: %v", diff)
	}
}

// newTestJitterTicker starts a ticker and returns a channel that is closed
// when the ticker's start goroutine exits.
func newTestJitterTicker(d time.Duration) (*JitterTicker, <-chan struct{}) {
	minimum, maximum := calculateMinMax(d, 0)
	ticker := &JitterTicker{
		c:        make(chan time.Time, 1),
		duration: d,
		min:      minimum,
		max:      maximum,
		quit:     make(chan struct{}),
	}
	ticker.C = (<-chan time.Time)(ticker.c)

	done := make(chan struct{})
	go func() {
		ticker.start()
		close(done)
	}()

	return ticker, done
}

func TestJitterTickerStop(t *testing.T) {
	t.Parallel()

	ticker, done := newTestJitterTicker(time.Hour)
	ticker.Stop()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ticker start goroutine did not exit")
	}
}

func TestJitterTickerStopIdempotent(t *testing.T) {
	t.Parallel()

	ticker, done := newTestJitterTicker(time.Hour)

	require.NotPanics(t, func() {
		ticker.Stop()
		ticker.Stop()
	})

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ticker start goroutine did not exit")
	}
}

func TestJitterTickerStopConcurrentWithTick(t *testing.T) {
	t.Parallel()

	// A zero duration keeps the timer ready while Stop is called, exercising
	// the select interleaving between a timer tick and the quit signal.
	ticker, done := newTestJitterTicker(0)
	select {
	case <-ticker.C:
	case <-time.After(time.Second):
		t.Fatal("ticker did not produce a tick")
	}

	ticker.Stop()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ticker start goroutine did not exit")
	}
}
