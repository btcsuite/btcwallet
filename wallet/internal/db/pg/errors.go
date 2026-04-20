package pg

import (
	"errors"

	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/jackc/pgx/v5/pgconn"
)

// SQLSTATE helper constants support PostgreSQL error classification.
const (
	// connectionExceptionClass identifies PostgreSQL SQLSTATE class 08,
	// which covers connection exceptions.
	connectionExceptionClass = "08"

	// sqlStateClassLen is the length of a SQLSTATE class prefix.
	sqlStateClassLen = 2
)

// SQLSTATE code constants capture the PostgreSQL errors mapped here.
const (
	// The SQLSTATE codes below follow PostgreSQL's documented error code
	// appendix. The wallet intentionally collapses many backend-specific
	// codes into a smaller caller-facing reason set.
	//
	// Reference:
	// https://www.postgresql.org/docs/current/errcodes-appendix.html
	codeSerializationFailure = "40001"
	codeDeadlockDetected     = "40P01"
	codeLockNotAvailable     = "55P03"
	codeQueryCanceled        = "57014"
	codeAdminShutdown        = "57P01"
	codeCrashShutdown        = "57P02"
	codeCannotConnectNow     = "57P03"
	codeTooManyConnections   = "53300"
	codeDiskFull             = "53100"
	codeOutOfMemory          = "53200"
	codeConfigLimitExceeded  = "53400"
	codeReadOnlyTxn          = "25006"
	codeInsufficientPriv     = "42501"
	codeCorruptData          = "XX001"
	codeCorruptIndex         = "XX002"
	codeUndefinedTable       = "42P01"
	codeUndefinedColumn      = "42703"
	codeUniqueViolation      = "23505"
	codeForeignKeyViolation  = "23503"
	codeCheckViolation       = "23514"
	codeNotNullViolation     = "23502"
	codeExclusionViolation   = "23P01"
)

// reasonByCode maps PostgreSQL SQLSTATE codes into the shared SQL error model.
var reasonByCode = map[string]dberr.Reason{
	codeSerializationFailure: dberr.ReasonSerialization,
	codeDeadlockDetected:     dberr.ReasonDeadlock,
	codeLockNotAvailable:     dberr.ReasonLocked,
	codeQueryCanceled:        dberr.ReasonUnknown,
	codeAdminShutdown:        dberr.ReasonUnavailable,
	codeCrashShutdown:        dberr.ReasonUnavailable,
	codeCannotConnectNow:     dberr.ReasonUnavailable,
	codeTooManyConnections:   dberr.ReasonPoolExhausted,
	codeDiskFull:             dberr.ReasonResourceExhausted,
	codeOutOfMemory:          dberr.ReasonResourceExhausted,
	codeConfigLimitExceeded:  dberr.ReasonResourceExhausted,
	codeReadOnlyTxn:          dberr.ReasonReadOnly,
	codeInsufficientPriv:     dberr.ReasonPermission,
	codeCorruptData:          dberr.ReasonCorrupt,
	codeCorruptIndex:         dberr.ReasonCorrupt,
	codeUndefinedTable:       dberr.ReasonSchemaMismatch,
	codeUndefinedColumn:      dberr.ReasonSchemaMismatch,
	codeUniqueViolation:      dberr.ReasonConstraint,
	codeForeignKeyViolation:  dberr.ReasonConstraint,
	codeCheckViolation:       dberr.ReasonConstraint,
	codeNotNullViolation:     dberr.ReasonConstraint,
	codeExclusionViolation:   dberr.ReasonConstraint,
}

// mapErr maps PostgreSQL driver and transport errors into SQLError.
func mapErr(err error) *dberr.SQLError {
	// Prefer SQLSTATE-based mapping first so a completed PostgreSQL statement
	// keeps its specific backend code instead of being collapsed into a generic
	// transport fallback.
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return mapCode(pgErr.Code, err)
	}

	var connectErr *pgconn.ConnectError

	// ConnectError means the driver failed while establishing or maintaining
	// the connection, so callers see the same transient unavailable bucket used
	// for other connection-path failures.
	if errors.As(err, &connectErr) {
		return dberr.NewSQLError(
			dberr.BackendPostgres, dberr.ReasonUnavailable, "", err,
		)
	}

	// Safe-to-retry and timeout failures happen on the connection or transport
	// path rather than as a completed SQL statement outcome, so they share the
	// transient backend-unavailable bucket with SQLSTATE connection exceptions.
	if pgconn.SafeToRetry(err) || pgconn.Timeout(err) {
		return dberr.NewSQLError(
			dberr.BackendPostgres, dberr.ReasonUnavailable, "", err,
		)
	}

	return nil
}

// mapCode maps one PostgreSQL SQLSTATE into SQLError.
func mapCode(code string, err error) *dberr.SQLError {
	reason, ok := reasonByCode[code]
	if ok {
		return dberr.NewSQLError(dberr.BackendPostgres, reason, code, err)
	}

	if sqlStateClass(code) == connectionExceptionClass {
		// SQLSTATE class 08 reports connection exceptions rather than completed
		// statement outcomes, so it maps to the shared unavailable reason.
		return dberr.NewSQLError(
			dberr.BackendPostgres, dberr.ReasonUnavailable, code, err,
		)
	}

	return dberr.NewSQLError(
		dberr.BackendPostgres, dberr.ReasonUnknown, code, err,
	)
}

// sqlStateClass returns the SQLSTATE class prefix.
func sqlStateClass(code string) string {
	if len(code) < sqlStateClassLen {
		return ""
	}

	return code[:sqlStateClassLen]
}
