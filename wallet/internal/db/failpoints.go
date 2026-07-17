// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package db

import "context"

// Failpoints is the per-call, deterministic failure-injection seam the Stage 3
// runtime tests use to exercise the transaction contract. It is carried on the
// operation's context.Context rather than on the RuntimeStore request, so the
// neutral request contract stays free of test fields and one call can be
// injected independently of the store's construction.
//
// It is nil in production: WithFailpoints is only wired by tests, and every
// accessor below is nil-safe, so production paths pay a single context lookup
// and never branch. Both the SQL and KV backends and the runtime Coordinator
// consult the same seam, so a test drives all three the same way.
//
// The hooks fire, in order, around one semantic operation:
//
//	BeforeStatement -> [domain mutations] -> BeforeCommit -> (commit) ->
//	AfterCommit -> (mutation gate released) -> BeforeNotify -> (notify)
//
// The SQL backend additionally honors ForceTxRetries by returning a
// serialization error at the end of its first attempts, driving the executor's
// real callback-retry path. The KV backend is a single writer with atomic,
// non-retried transactions, so it ignores ForceTxRetries and OnTxAttempt.
type Failpoints struct {
	// BeforeStatement runs inside the write transaction, before the
	// operation's first domain mutation. A non-nil error aborts the
	// transaction before any durable change.
	BeforeStatement func() error

	// BeforeCommit runs inside the write transaction, after the domain
	// mutations and before the transaction commits. A non-nil error rolls the
	// whole transaction back, proving no durable or cache state changed before
	// a successful commit.
	BeforeCommit func() error

	// ForceTxRetries makes the SQL backend return a serialization error at the
	// end of its first ForceTxRetries transaction attempts, after that
	// attempt's durable work ran, so the executor rolls back and re-runs the
	// body. It exercises idempotency under callback retry.
	ForceTxRetries int

	// OnTxAttempt observes each SQL transaction attempt by its zero-based
	// number, letting a test count callback retries.
	OnTxAttempt func(attempt int)

	// AfterCommit runs after the durable commit and before the result is
	// returned. Returning ErrAmbiguousCommit models a commit whose durable
	// outcome is unknown to the caller, exercising ambiguous-commit
	// resolution.
	AfterCommit func() error

	// BeforeNotify runs after the mutation gate is released and before a
	// post-commit event is published. A test blocks here to model a delayed
	// notification.
	BeforeNotify func()

	// DropNotify drops post-commit event delivery to model a lost
	// notification that restart reconciliation must recover.
	DropNotify bool
}

// failpointsKey is the unexported context key the failure-injection seam is
// stored under.
type failpointsKey struct{}

// WithFailpoints returns a context that carries fp so the runtime backends and
// Coordinator injecting from it observe the same per-call faults. It is a test
// helper; production code never calls it.
func WithFailpoints(ctx context.Context, fp *Failpoints) context.Context {
	return context.WithValue(ctx, failpointsKey{}, fp)
}

// FailpointsFromContext returns the failure-injection seam carried by ctx, or
// nil when none is set. The returned value is safe to use even when nil: every
// accessor method below tolerates a nil receiver.
func FailpointsFromContext(ctx context.Context) *Failpoints {
	fp, _ := ctx.Value(failpointsKey{}).(*Failpoints)

	return fp
}

// RunBeforeStatement runs the before-statement hook, if any.
func (fp *Failpoints) RunBeforeStatement() error {
	if fp == nil || fp.BeforeStatement == nil {
		return nil
	}

	return fp.BeforeStatement()
}

// RunBeforeCommit runs the before-commit hook, if any.
func (fp *Failpoints) RunBeforeCommit() error {
	if fp == nil || fp.BeforeCommit == nil {
		return nil
	}

	return fp.BeforeCommit()
}

// RunAfterCommit runs the after-commit hook, if any.
func (fp *Failpoints) RunAfterCommit() error {
	if fp == nil || fp.AfterCommit == nil {
		return nil
	}

	return fp.AfterCommit()
}

// RunBeforeNotify runs the before-notify hook, if any.
func (fp *Failpoints) RunBeforeNotify() {
	if fp == nil || fp.BeforeNotify == nil {
		return
	}

	fp.BeforeNotify()
}

// RunOnTxAttempt reports one zero-based transaction attempt to the observer, if
// any.
func (fp *Failpoints) RunOnTxAttempt(attempt int) {
	if fp == nil || fp.OnTxAttempt == nil {
		return
	}

	fp.OnTxAttempt(attempt)
}

// Retries returns how many leading transaction attempts should be forced to
// fail with a serialization error, or zero when unset.
func (fp *Failpoints) Retries() int {
	if fp == nil {
		return 0
	}

	return fp.ForceTxRetries
}

// Dropped reports whether post-commit event delivery should be dropped.
func (fp *Failpoints) Dropped() bool {
	return fp != nil && fp.DropNotify
}
