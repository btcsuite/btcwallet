// Package dberr contains the shared SQL error taxonomy and normalization logic
// used by backend-specific db packages.
package dberr

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
)

// unknownString is the fallback text for invalid enum values.
const unknownString = "unknown"

// Backend identifies which SQL backend produced a classified SQL error.
//
// The backend is preserved on SQLError so callers can log raw backend codes,
// maintain per-backend stats, and keep backend-specific handling separate from
// the shared error model.
type Backend string

// Backend constants identify supported SQL backends.
const (
	// BackendPostgres identifies the PostgreSQL SQL backend.
	BackendPostgres Backend = "postgres"

	// BackendSQLite identifies the SQLite SQL backend.
	BackendSQLite Backend = "sqlite"
)

// String returns the canonical string form of the backend.
func (b Backend) String() string {
	switch b {
	case BackendPostgres:
		return string(b)

	case BackendSQLite:
		return string(b)

	default:
		return unknownString
	}
}

// Valid reports whether the backend is one of the known SQL backends.
func (b Backend) Valid() bool {
	switch b {
	case BackendPostgres:
		return true

	case BackendSQLite:
		return true

	default:
		return false
	}
}

// Class describes the caller-facing policy bucket for a classified SQL backend
// error.
//
// The class answers what runtime code should do next:
//
//   - Transient: retry the operation when it is safe to retry.
//   - Permanent: fail the operation immediately without poisoning the store.
//   - Fatal: fail the operation and mark the store unhealthy so later calls
//     fail fast until the backend is reopened or repaired.
type Class uint8

// Class constants identify caller-facing SQL error policy buckets.
const (
	// ClassTransient marks failures that may succeed on a later retry.
	ClassTransient Class = iota

	// ClassPermanent marks failures that should fail the current
	// operation without retrying or poisoning the store.
	ClassPermanent

	// ClassFatal marks failures that should fail the current operation
	// and take the store out of service.
	ClassFatal
)

// String returns the canonical string form of the class.
func (c Class) String() string {
	switch c {
	case ClassTransient:
		return "transient"

	case ClassPermanent:
		return "permanent"

	case ClassFatal:
		return "fatal"

	default:
		return unknownString
	}
}

// Valid reports whether the class is recognized.
func (c Class) Valid() bool {
	switch c {
	case ClassTransient:
		return true

	case ClassPermanent:
		return true

	case ClassFatal:
		return true

	default:
		return false
	}
}

// Reason describes the specific backend failure bucket for a classified SQL
// error.
//
// Callers use Reason for diagnosis and metrics, then derive runtime policy
// through Class(). New or unmapped backend codes should fall back to
// ReasonUnknown while preserving the raw backend code on SQLError.
type Reason uint8

// Reason constants identify shared SQL backend failure buckets.
const (
	// ReasonUnknown is the fallback reason for uncategorized backend codes.
	ReasonUnknown Reason = iota

	// ReasonSerialization marks transaction serialization failures
	// caused by concurrent updates.
	ReasonSerialization

	// ReasonDeadlock marks deadlock failures where the backend aborts
	// one participant to break a lock cycle.
	ReasonDeadlock

	// ReasonBusy marks SQLite busy failures where a lock cannot be
	// acquired in time.
	ReasonBusy

	// ReasonLocked marks lock-not-available failures.
	ReasonLocked

	// ReasonUnavailable marks backend availability and transport
	// failures.
	ReasonUnavailable

	// ReasonPoolExhausted marks connection-pool or backend
	// connection-limit failures.
	ReasonPoolExhausted

	// ReasonSchemaMismatch marks schema drift or schema version
	// mismatches.
	ReasonSchemaMismatch

	// ReasonConstraint marks backend constraint failures.
	ReasonConstraint

	// ReasonResourceExhausted marks disk, memory, or similar hard
	// resource failures.
	ReasonResourceExhausted

	// ReasonReadOnly marks read-only backend failures.
	ReasonReadOnly

	// ReasonPermission marks backend permission failures.
	ReasonPermission

	// ReasonCorrupt marks corruption failures.
	ReasonCorrupt
)

// Class returns the caller-facing policy bucket derived from the reason.
func (r Reason) Class() Class {
	switch r {
	case ReasonSerialization, ReasonDeadlock, ReasonBusy, ReasonLocked,
		ReasonUnavailable, ReasonPoolExhausted:

		return ClassTransient

	// Unknown or caller-fixable backend states fail the current operation
	// without retrying or taking the store out of service.
	case ReasonSchemaMismatch, ReasonConstraint, ReasonUnknown:
		return ClassPermanent

	case ReasonResourceExhausted, ReasonReadOnly, ReasonPermission,
		ReasonCorrupt:

		return ClassFatal

	default:
		return ClassPermanent
	}
}

// String returns the canonical string form of the reason.
//
//nolint:cyclop // One explicit enum-to-string switch is the clearest form here.
func (r Reason) String() string {
	switch r {
	case ReasonSerialization:
		return "serialization"

	case ReasonDeadlock:
		return "deadlock"

	case ReasonBusy:
		return "busy"

	case ReasonLocked:
		return "locked"

	case ReasonUnavailable:
		return "unavailable"

	case ReasonPoolExhausted:
		return "pool_exhausted"

	case ReasonSchemaMismatch:
		return "schema_mismatch"

	case ReasonConstraint:
		return "constraint"

	case ReasonUnknown:
		return unknownString

	case ReasonResourceExhausted:
		return "resource_exhausted"

	case ReasonReadOnly:
		return "read_only"

	case ReasonPermission:
		return "permission"

	case ReasonCorrupt:
		return "corrupt"

	default:
		return unknownString
	}
}

// Valid reports whether the reason is recognized.
func (r Reason) Valid() bool {
	return r <= ReasonCorrupt
}

// SQLError wraps a backend or transport error with stable SQL classification
// metadata.
//
// The wrapper keeps classification data inside ordinary error chains so callers
// can recover backend, reason, class, and raw codes with errors.As after higher
// layers add their own context.
type SQLError struct {
	// Backend identifies which SQL backend produced the error.
	Backend Backend

	// Reason identifies the specific backend failure bucket.
	Reason Reason

	// Code stores the raw backend code used for classification.
	Code string

	// Err stores the wrapped backend or transport error.
	Err error
}

// NewSQLError builds a classified SQL backend error wrapper.
func NewSQLError(backend Backend, reason Reason, code string,
	err error) *SQLError {

	return &SQLError{
		Backend: backend,
		Reason:  reason,
		Code:    code,
		Err:     err,
	}
}

// Class returns the caller-facing policy bucket derived from the reason.
func (e *SQLError) Class() Class {
	if e == nil {
		// A missing wrapper is treated like an unknown classified error so
		// defensive callers do not retry or poison store state based on
		// absent classification data.
		return ReasonUnknown.Class()
	}

	return e.Reason.Class()
}

// Error returns the printable form of the wrapped backend error.
func (e *SQLError) Error() string {
	if e == nil {
		return "<nil>"
	}

	// Normal wrappers carry the backend or transport error, so preserve that
	// message and leave the remaining branches as defensive fallbacks.
	if e.Err != nil {
		return e.Err.Error()
	}

	// Fall back to synthesized text only for malformed or test-built
	// wrappers that do not carry an underlying cause.
	return fmt.Sprintf("%s %s sql error", e.Backend.String(), e.Reason)
}

// Unwrap returns the wrapped backend error.
func (e *SQLError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.Err
}

// Normalize converts one backend error into the shared SQL error model.
//
// It handles errors in this order:
//
//  1. A nil error stays nil.
//  2. Context cancellation and deadline errors are returned unchanged,
//     including any caller-added wrapping context.
//  3. Existing SQLError wrappers are returned unchanged so Normalize does not
//     rebuild or strip the original error chain.
//  4. The mapper gets the first chance to translate backend-native driver
//     errors into SQLError values.
//  5. Generic connection and transport failures are classified as
//     ReasonUnavailable.
//  6. If the backend is known and no earlier rule matches, err is wrapped as
//     ReasonUnknown.
//  7. If the backend is unknown, err is returned unchanged.
//
// Normalize is intentionally side-effect free. Callers own follow-up actions
// such as stats recording or unhealthy-store transitions.
//
// The mapper keeps backend-specific matching outside the shared error package
// so backend packages can return shared SQL errors without introducing import
// cycles. Callers should pass a no-op mapper when they have no backend-
// specific codes to inspect.
func Normalize(backend Backend, mapper func(error) *SQLError, err error) error {
	if err == nil {
		return nil
	}

	// Preserve caller-driven cancellation semantics, including any wrapping
	// context, instead of reclassifying them as backend errors.
	contextErr := unwrapContextErr(err)
	if contextErr != nil {
		return contextErr
	}

	// Preserve existing SQL wrappers so caller-added context is not dropped
	// from the original error chain.
	if extractSQLError(err) != nil {
		return err
	}

	// Ask the backend-specific mapper first so driver-native codes stay as
	// specific as possible.
	sqlErr := mapper(err)
	if sqlErr != nil {
		return sqlErr
	}

	// Fall back to transport-level classification for connection-oriented
	// failures that are not backend-code specific.
	transportErr := classifyConnErr(backend, err)
	if transportErr != nil {
		return transportErr
	}

	// Unknown backends are left untouched so callers do not accidentally invent
	// a backend identity the error never had.
	if !backend.Valid() {
		return err
	}

	// Keep backend identity even when the exact backend code is not recognized
	// so logs and stats retain useful diagnosis data.
	return NewSQLError(backend, ReasonUnknown, "", err)
}

// extractSQLError extracts the shared SQL error wrapper from err, if present.
func extractSQLError(err error) *SQLError {
	var sqlErr *SQLError
	if errors.As(err, &sqlErr) {
		return sqlErr
	}

	return nil
}

// classifyConnErr classifies generic connection and transport failures that do
// not come with backend-specific codes.
func classifyConnErr(backend Backend, err error) *SQLError {
	if !backend.Valid() {
		return nil
	}

	badConn := errors.Is(err, driver.ErrBadConn)
	connDone := errors.Is(err, sql.ErrConnDone)

	// Broken-connection sentinels and EOF all mean the caller lost the SQL
	// transport path before receiving a normal backend result.
	if badConn || connDone || errors.Is(err, io.EOF) {
		return NewSQLError(backend, ReasonUnavailable, "", err)
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		// Timeout-only net errors are still transport failures even when the
		// backend never returned a backend-specific code.
		if netErr.Timeout() {
			return NewSQLError(backend, ReasonUnavailable, "", err)
		}
	}

	return nil
}

// unwrapContextErr preserves caller-driven context cancellation and deadlines.
func unwrapContextErr(err error) error {
	if errors.Is(err, context.Canceled) {
		return err
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	return nil
}
