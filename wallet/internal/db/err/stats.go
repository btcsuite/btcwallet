package dberr

import (
	"errors"
	"sync/atomic"
)

// StatsSnapshot is a read-only copy of the SQL backend error counters.
type StatsSnapshot struct {
	// Backend identifies which SQL backend produced the snapshot.
	Backend Backend

	// TotalErrs counts all classified SQL backend errors.
	TotalErrs uint64

	// TransientErrs counts classified transient SQL backend errors.
	TransientErrs uint64

	// PermanentErrs counts classified permanent SQL backend errors.
	PermanentErrs uint64

	// FatalErrs counts classified fatal SQL backend errors.
	FatalErrs uint64

	// Serialization counts serialization failures.
	Serialization uint64

	// Deadlocks counts deadlock failures.
	Deadlocks uint64

	// Busy counts SQLite busy failures.
	Busy uint64

	// Locked counts lock-not-available failures.
	Locked uint64

	// Unavailable counts backend availability failures.
	Unavailable uint64

	// PoolExhausted counts connection exhaustion failures.
	PoolExhausted uint64

	// ResourceExhausted counts disk, memory, or similar failures.
	ResourceExhausted uint64

	// ReadOnly counts read-only backend failures.
	ReadOnly uint64

	// Permission counts backend permission failures.
	Permission uint64

	// Corrupt counts corruption failures.
	Corrupt uint64

	// SchemaMismatch counts schema mismatch failures.
	SchemaMismatch uint64

	// Constraint counts backend constraint failures.
	Constraint uint64

	// Unknown counts classified backend failures with an unknown reason.
	Unknown uint64
}

// Stats stores low-overhead atomic counters for classified SQL errors.
type Stats struct {
	// totalErrs counts all classified SQL backend errors.
	totalErrs atomic.Uint64

	// transientErrs counts transient SQL backend errors.
	transientErrs atomic.Uint64

	// permanentErrs counts permanent SQL backend errors.
	permanentErrs atomic.Uint64

	// fatalErrs counts fatal SQL backend errors.
	fatalErrs atomic.Uint64

	// serialization counts serialization failures.
	serialization atomic.Uint64

	// deadlocks counts deadlock failures.
	deadlocks atomic.Uint64

	// busy counts SQLite busy failures.
	busy atomic.Uint64

	// locked counts lock-not-available failures.
	locked atomic.Uint64

	// unavailable counts backend availability failures.
	unavailable atomic.Uint64

	// poolExhausted counts connection exhaustion failures.
	poolExhausted atomic.Uint64

	// resourceExhausted counts resource exhaustion failures.
	resourceExhausted atomic.Uint64

	// readOnly counts read-only backend failures.
	readOnly atomic.Uint64

	// permission counts backend permission failures.
	permission atomic.Uint64

	// corrupt counts corruption failures.
	corrupt atomic.Uint64

	// schemaMismatch counts schema mismatch failures.
	schemaMismatch atomic.Uint64

	// constraint counts backend constraint failures.
	constraint atomic.Uint64

	// unknown counts classified backend failures with an unknown reason.
	unknown atomic.Uint64
}

// reasonRecorder updates one per-reason counter on Stats.
type reasonRecorder func(*Stats)

// reasonRecorders maps each valid reason to its per-reason counter update.
var reasonRecorders = [...]reasonRecorder{
	ReasonSerialization: func(s *Stats) {
		s.serialization.Add(1)
	},
	ReasonDeadlock: func(s *Stats) {
		s.deadlocks.Add(1)
	},
	ReasonBusy: func(s *Stats) {
		s.busy.Add(1)
	},
	ReasonLocked: func(s *Stats) {
		s.locked.Add(1)
	},
	ReasonUnavailable: func(s *Stats) {
		s.unavailable.Add(1)
	},
	ReasonPoolExhausted: func(s *Stats) {
		s.poolExhausted.Add(1)
	},
	ReasonSchemaMismatch: func(s *Stats) {
		s.schemaMismatch.Add(1)
	},
	ReasonConstraint: func(s *Stats) {
		s.constraint.Add(1)
	},
	ReasonUnknown: func(s *Stats) {
		s.unknown.Add(1)
	},
	ReasonResourceExhausted: func(s *Stats) {
		s.resourceExhausted.Add(1)
	},
	ReasonReadOnly: func(s *Stats) {
		s.readOnly.Add(1)
	},
	ReasonPermission: func(s *Stats) {
		s.permission.Add(1)
	},
	ReasonCorrupt: func(s *Stats) {
		s.corrupt.Add(1)
	},
}

// Record updates counters from a classified SQL backend error.
func (s *Stats) Record(err error) {
	var sqlErr *SQLError
	if !errors.As(err, &sqlErr) {
		return
	}

	s.totalErrs.Add(1)

	switch sqlErr.Class() {
	case ClassTransient:
		s.transientErrs.Add(1)

	case ClassPermanent:
		s.permanentErrs.Add(1)

	case ClassFatal:
		s.fatalErrs.Add(1)
	}

	s.recordReason(sqlErr.Reason)
}

// Snapshot returns a read-only copy of the current SQL error counters.
func (s *Stats) Snapshot(backend Backend) StatsSnapshot {
	return StatsSnapshot{
		Backend:           backend,
		TotalErrs:         s.totalErrs.Load(),
		TransientErrs:     s.transientErrs.Load(),
		PermanentErrs:     s.permanentErrs.Load(),
		FatalErrs:         s.fatalErrs.Load(),
		Serialization:     s.serialization.Load(),
		Deadlocks:         s.deadlocks.Load(),
		Busy:              s.busy.Load(),
		Locked:            s.locked.Load(),
		Unavailable:       s.unavailable.Load(),
		PoolExhausted:     s.poolExhausted.Load(),
		ResourceExhausted: s.resourceExhausted.Load(),
		ReadOnly:          s.readOnly.Load(),
		Permission:        s.permission.Load(),
		Corrupt:           s.corrupt.Load(),
		SchemaMismatch:    s.schemaMismatch.Load(),
		Constraint:        s.constraint.Load(),
		Unknown:           s.unknown.Load(),
	}
}

// recordReason updates counters for one classified SQL error reason.
func (s *Stats) recordReason(reason Reason) {
	if !reason.Valid() {
		s.unknown.Add(1)
		return
	}

	record := reasonRecorders[reason]
	if record == nil {
		s.unknown.Add(1)
		return
	}

	record(s)
}
