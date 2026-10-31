package runtime

import (
	"context"
	"testing"
	"time"

	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
)

// BenchmarkReadSuccess measures a successful read with no retries.
func BenchmarkReadSuccess(b *testing.B) {
	hooks := &fakeStore{}
	for range b.N {
		_, _ = readWithConfig(
			context.Background(), hooks, struct{}{},
			func(context.Context, struct{}) (struct{}, error) {
				return struct{}{}, nil
			},
			readConfig{
				attempts: 1,
				base:     time.Millisecond,
				max:      time.Millisecond,
				timer:    time.NewTimer,
				jitter: func(delay time.Duration) time.Duration {
					return delay
				},
			},
		)
	}
}

// BenchmarkReadTransientRetry measures one retry before success.
func BenchmarkReadTransientRetry(b *testing.B) {
	hooks := &fakeStore{classifyFn: func(err error) error {
		return dberr.NewSQLError(
			dberr.BackendSQLite, dberr.ReasonBusy, "5", err,
		)
	}}

	for range b.N {
		attempts := 0
		_, _ = readWithConfig(
			context.Background(), hooks, struct{}{},
			func(context.Context, struct{}) (struct{}, error) {
				attempts++
				if attempts == 1 {
					return struct{}{}, errRuntimeBusy
				}

				return struct{}{}, nil
			},
			readConfig{
				attempts: 2,
				base:     time.Millisecond,
				max:      time.Millisecond,
				timer:    immediateTimer,
				jitter: func(delay time.Duration) time.Duration {
					return delay
				},
			},
		)
	}
}
