package dberr

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	errTestSerialization = errors.New("serialization")
	errTestConstraint    = errors.New("constraint")
	errTestPlain         = errors.New("plain")
)

// TestStatsRecord verifies that the stats collector updates class and reason
// counters from classified SQL backend errors.
func TestStatsRecord(t *testing.T) {
	t.Parallel()

	var stats Stats

	stats.Record(NewSQLError(
		BackendPostgres,
		ReasonSerialization,
		"40001",
		errTestSerialization,
	))
	stats.Record(NewSQLError(
		BackendSQLite,
		ReasonConstraint,
		"2067",
		errTestConstraint,
	))

	snapshot := stats.Snapshot(BackendPostgres)
	require.EqualValues(t, 2, snapshot.TotalErrs)
	require.EqualValues(t, 1, snapshot.TransientErrs)
	require.EqualValues(t, 1, snapshot.PermanentErrs)
	require.EqualValues(t, 1, snapshot.Serialization)
	require.EqualValues(t, 1, snapshot.Constraint)
}

// TestStatsRecordReasonAll verifies that each reason increments its expected
// counter.
func TestStatsRecordReasonAll(t *testing.T) {
	t.Parallel()

	reasons := []Reason{
		ReasonSerialization,
		ReasonDeadlock,
		ReasonBusy,
		ReasonLocked,
		ReasonUnavailable,
		ReasonPoolExhausted,
		ReasonResourceExhausted,
		ReasonReadOnly,
		ReasonPermission,
		ReasonCorrupt,
		ReasonSchemaMismatch,
		ReasonConstraint,
		ReasonUnknown,
	}

	var stats Stats
	for _, reason := range reasons {
		stats.recordReason(reason)
	}

	snapshot := stats.Snapshot(BackendPostgres)
	require.EqualValues(t, 1, snapshot.Serialization)
	require.EqualValues(t, 1, snapshot.Deadlocks)
	require.EqualValues(t, 1, snapshot.Busy)
	require.EqualValues(t, 1, snapshot.Locked)
	require.EqualValues(t, 1, snapshot.Unavailable)
	require.EqualValues(t, 1, snapshot.PoolExhausted)
	require.EqualValues(t, 1, snapshot.ResourceExhausted)
	require.EqualValues(t, 1, snapshot.ReadOnly)
	require.EqualValues(t, 1, snapshot.Permission)
	require.EqualValues(t, 1, snapshot.Corrupt)
	require.EqualValues(t, 1, snapshot.SchemaMismatch)
	require.EqualValues(t, 1, snapshot.Constraint)
	require.EqualValues(t, 1, snapshot.Unknown)
}

// TestStatsRecordUnknown verifies that fallback reasons are counted as
// permanent unknown failures.
func TestStatsRecordUnknown(t *testing.T) {
	t.Parallel()

	var stats Stats
	stats.Record(NewSQLError(BackendSQLite, ReasonUnknown, "", errTestPlain))
	stats.recordReason(Reason(99))

	snapshot := stats.Snapshot(BackendSQLite)
	require.EqualValues(t, 1, snapshot.TotalErrs)
	require.Zero(t, snapshot.TransientErrs)
	require.EqualValues(t, 1, snapshot.PermanentErrs)
	require.Zero(t, snapshot.FatalErrs)
	require.EqualValues(t, 2, snapshot.Unknown)
}

// TestStatsRecordIgnoresPlainErr verifies that only classified SQL backend
// errors affect the stats collector.
func TestStatsRecordIgnoresPlainErr(t *testing.T) {
	t.Parallel()

	var stats Stats

	stats.Record(errTestPlain)

	snapshot := stats.Snapshot(BackendSQLite)
	require.Zero(t, snapshot.TotalErrs)
	require.Zero(t, snapshot.Unknown)
}
