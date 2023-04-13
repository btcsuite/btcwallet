package chain

import (
	"errors"
	"math"
	"math/rand"
	"time"
)

// JitterTicker is a ticker that adds jitter to the tick duration.
type JitterTicker struct {
	// C is a read-only channel that receives ticks.
	C <-chan time.Time

	// c is the internal channel that receives ticks.
	c chan time.Time

	// duration is the base duration of the ticker.
	duration time.Duration

	// scaler defines the jitter scaler. The jitter is calculated as,
	// - min: duration * (1 - scaler) or 0 if scaler > 1,
	// - max: duration * (1 + scaler).
	//
	// NOTE: when scaler is 0, this ticker behaves as a normal ticker.
	scaler float64

	// min and max store the duration values.
	min int64
	max int64

	// quit is closed when the ticker is stopped.
	quit chan struct{}
}

// NewJitterTicker returns a new JitterTicker.
func NewJitterTicker(d time.Duration, jitter float64) *JitterTicker {
	// Calculate the min and max duration values.
	min, max := calculateMinMax(d, jitter)

	// Create a new ticker.
	t := &JitterTicker{
		c:        make(chan time.Time, 1),
		scaler:   jitter,
		duration: d,
		min:      min,
		max:      max,
		quit:     make(chan struct{}),
	}

	// Mount the tick channel to a read-only channel.
	t.C = (<-chan time.Time)(t.c)

	// Start the ticker.
	go t.start()

	return t
}

// calculateMinMax calculates the min and max duration values. If the
// calculated min is negative, it will be set to 0.
func calculateMinMax(d time.Duration, scaler float64) (int64, int64) {
	// If the scaler is negative, we will panic.
	if scaler < 0 {
		panic(errors.New("scaler must be positive"))
	}

	// Calculate the min and max jitter values.
	min := math.Floor(float64(d) * (1 - scaler))
	max := math.Ceil(float64(d) * (1 + scaler))

	// If the scaler is greater than 1, we would use a zero min instead of
	// a negative one.
	if 1-scaler < 0 {
		min = 0
	}

	return int64(min), int64(max)
}

// Stop stops the ticker.
func (jt *JitterTicker) Stop() {
	close(jt.quit)
}

// start starts the ticker.
func (jt *JitterTicker) start() {
	// Create a new timer with a random duration.
	timer := time.NewTimer(jt.rand())

	for {
		select {
		case t := <-timer.C:
			// Reset the timer when it fires.
			timer.Reset(jt.rand())

			// Send the tick to the channel.
			//
			// NOTE: must be non-blocking.
			select {
			case jt.c <- t:
			default:
			}

		case <-jt.quit:
			// Stop the timer and clean the channel when it stops.
			if !timer.Stop() {
				<-timer.C
			}
		}
	}
}

// rand returns a random duration between the min and max values.
func (jt *JitterTicker) rand() time.Duration {
	if jt.max == jt.min {
		return jt.duration
	}

	d := rand.Int63n(jt.max-jt.min) + jt.min //nolint:gosec
	return time.Duration(d)
}
