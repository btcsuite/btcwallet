package dberr

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

var errConstraint = errors.New("constraint")

// noOpMapper is a test helper that leaves backend-specific classification to
// later Normalize fallbacks.
func noOpMapper(error) *SQLError {
	return nil
}

// TestBackendString verifies the string forms of the SQL backend identifiers.
func TestBackendString(t *testing.T) {
	t.Parallel()

	require.Equal(t, "postgres", BackendPostgres.String())
	require.Equal(t, "sqlite", BackendSQLite.String())
	require.Equal(t, unknownString, Backend("mysql").String())
	require.True(t, BackendPostgres.Valid())
	require.False(t, Backend("mysql").Valid())
}

// TestClassString verifies the string forms of the exported error classes.
func TestClassString(t *testing.T) {
	t.Parallel()

	require.Equal(t, "transient", ClassTransient.String())
	require.Equal(t, "permanent", ClassPermanent.String())
	require.Equal(t, "fatal", ClassFatal.String())
	require.Equal(t, unknownString, Class(99).String())
	require.True(t, ClassFatal.Valid())
	require.False(t, Class(99).Valid())
}

// TestReasonMetadata verifies the string and class metadata of the exported
// reasons.
func TestReasonMetadata(t *testing.T) {
	t.Parallel()

	var zero Reason
	require.Equal(t, ReasonUnknown, zero)

	require.Equal(t, "serialization", ReasonSerialization.String())
	require.Equal(t, ClassTransient, ReasonBusy.Class())
	require.Equal(t, ClassPermanent, ReasonUnknown.Class())
	require.Equal(t, ClassFatal, ReasonCorrupt.Class())
	require.Equal(t, unknownString, Reason(99).String())
	require.False(t, Reason(99).Valid())
}

// TestReasonClassCoverage verifies that every valid reason maps to the
// expected caller-facing policy bucket.
func TestReasonClassCoverage(t *testing.T) {
	t.Parallel()

	tests := map[Reason]Class{
		ReasonUnknown:           ClassPermanent,
		ReasonSerialization:     ClassTransient,
		ReasonDeadlock:          ClassTransient,
		ReasonBusy:              ClassTransient,
		ReasonLocked:            ClassTransient,
		ReasonUnavailable:       ClassTransient,
		ReasonPoolExhausted:     ClassTransient,
		ReasonSchemaMismatch:    ClassPermanent,
		ReasonConstraint:        ClassPermanent,
		ReasonResourceExhausted: ClassFatal,
		ReasonReadOnly:          ClassFatal,
		ReasonPermission:        ClassFatal,
		ReasonCorrupt:           ClassFatal,
	}

	for reason := ReasonUnknown; reason <= ReasonCorrupt; reason++ {
		wantClass, ok := tests[reason]
		require.Truef(t, ok, "missing class expectation for reason %v", reason)
		require.Equal(t, wantClass, reason.Class())
	}
}

// TestSQLErrorFormatting verifies the formatting helpers on nil and populated
// SQL errors.
func TestSQLErrorFormatting(t *testing.T) {
	t.Parallel()

	var nilErr *SQLError
	require.Equal(t, "<nil>", nilErr.Error())
	require.NoError(t, nilErr.Unwrap())
	require.Equal(t, ClassPermanent, nilErr.Class())

	err := &SQLError{
		Backend: BackendSQLite,
		Reason:  ReasonUnknown,
	}
	require.Equal(t, "sqlite unknown sql error", err.Error())
	require.NoError(t, err.Unwrap())
}

// TestExtractSQLErrorClass verifies that callers can recover a wrapped SQL
// error and inspect its derived class with the standard errors.As pattern.
func TestExtractSQLErrorClass(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("wrap: %w", NewSQLError(
		BackendPostgres,
		ReasonSerialization,
		"40001",
		driver.ErrBadConn,
	))

	sqlErr := extractSQLError(err)
	require.NotNil(t, sqlErr)
	require.Equal(t, ClassTransient, sqlErr.Class())

	require.Nil(t, extractSQLError(errConstraint))
}

// TestExtractSQLError verifies that callers can recover structured SQL
// metadata with the standard errors.As pattern.
func TestExtractSQLError(t *testing.T) {
	t.Parallel()

	wrapped := fmt.Errorf("outer: %w", NewSQLError(
		BackendSQLite,
		ReasonConstraint,
		"2067",
		errConstraint,
	))

	sqlErr := extractSQLError(wrapped)
	require.NotNil(t, sqlErr)
	require.Equal(t, BackendSQLite, sqlErr.Backend)
	require.Equal(t, ReasonConstraint, sqlErr.Reason)
	require.Equal(t, "2067", sqlErr.Code)
	require.Equal(t, ClassPermanent, sqlErr.Class())
}

// TestClassifyConnErr verifies that generic connection failures are classified
// as transient availability problems.
func TestClassifyConnErr(t *testing.T) {
	t.Parallel()

	err := classifyConnErr(BackendPostgres, driver.ErrBadConn)
	require.NotNil(t, err)
	require.Equal(t, BackendPostgres, err.Backend)
	require.Equal(t, ReasonUnavailable, err.Reason)
	require.Equal(t, ClassTransient, err.Class())

	err = classifyConnErr(BackendSQLite, sql.ErrConnDone)
	require.NotNil(t, err)
	require.Equal(t, ReasonUnavailable, err.Reason)

	err = classifyConnErr(BackendSQLite, netTimeoutError{})
	require.NotNil(t, err)
	require.Equal(t, ReasonUnavailable, err.Reason)

	err = classifyConnErr(BackendSQLite, temporaryNetError{err: io.EOF})
	require.Nil(t, err)

	require.Nil(t, classifyConnErr(Backend(""), driver.ErrBadConn))
	require.Nil(t, classifyConnErr(BackendSQLite, sql.ErrNoRows))
}

// TestCoreHelpers verifies the remaining backend-agnostic helper branches.
func TestCoreHelpers(t *testing.T) {
	t.Parallel()

	require.Equal(t, context.Canceled, unwrapContextErr(context.Canceled))
	require.Equal(t, context.DeadlineExceeded,
		unwrapContextErr(context.DeadlineExceeded))

	wrappedCanceled := fmt.Errorf("query accounts: %w", context.Canceled)
	require.Same(t, wrappedCanceled, unwrapContextErr(wrappedCanceled))
	require.NoError(t, unwrapContextErr(sql.ErrNoRows))
}

// TestNormalize verifies the backend-aware normalization flow that keeps
// context errors untouched and preserves backend-specific mapping.
func TestNormalize(t *testing.T) {
	t.Parallel()

	err := Normalize(BackendPostgres, noOpMapper, context.Canceled)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, extractSQLError(err))

	wrappedCanceled := fmt.Errorf("query accounts: %w", context.Canceled)
	err = Normalize(BackendPostgres, noOpMapper, wrappedCanceled)
	require.Same(t, wrappedCanceled, err)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, extractSQLError(err))

	err = Normalize(BackendPostgres, noOpMapper, driver.ErrBadConn)

	sqlErr := extractSQLError(err)
	require.NotNil(t, sqlErr)
	require.Equal(t, BackendPostgres, sqlErr.Backend)
	require.Equal(t, ClassTransient, sqlErr.Class())
	require.Equal(t, ReasonUnavailable, sqlErr.Reason)

	err = Normalize(BackendSQLite, func(in error) *SQLError {
		return NewSQLError(BackendSQLite, ReasonUnknown, "", in)
	}, errConstraint)
	sqlErr = extractSQLError(err)
	require.NotNil(t, sqlErr)
	require.Equal(t, ClassPermanent, sqlErr.Class())
	require.Equal(t, ReasonUnknown, sqlErr.Reason)

	existing := NewSQLError(Backend(""), ReasonCorrupt, "", io.EOF)
	err = Normalize(BackendPostgres, noOpMapper, existing)
	require.Same(t, existing, err)
	require.Equal(t, Backend(""), extractSQLError(err).Backend)

	wrapped := fmt.Errorf("outer: %w", existing)
	err = Normalize(BackendSQLite, noOpMapper, wrapped)
	require.Same(t, wrapped, err)
	require.Equal(t, Backend(""), extractSQLError(err).Backend)

	require.Same(t, errConstraint,
		Normalize(Backend(""), noOpMapper, errConstraint))
}

// temporaryNetError is a test helper that exposes only the legacy Temporary
// signal without reporting a timeout.
type temporaryNetError struct {
	// err is the wrapped error string returned by Error.
	err error
}

// Error returns the wrapped error string.
func (e temporaryNetError) Error() string {
	return e.err.Error()
}

// Timeout reports that the test error is not a timeout.
func (e temporaryNetError) Timeout() bool {
	return false
}

// Temporary reports that the test error should be treated as temporary.
func (e temporaryNetError) Temporary() bool {
	return true
}

// netTimeoutError is a test helper that reports a timeout without a legacy
// Temporary method.
type netTimeoutError struct{}

// Error returns the static timeout error string.
func (e netTimeoutError) Error() string {
	return "timeout"
}

// Timeout reports that the test error is a timeout.
func (e netTimeoutError) Timeout() bool {
	return true
}

// Temporary reports that the test error is not a legacy temporary error.
func (e netTimeoutError) Temporary() bool {
	return false
}
