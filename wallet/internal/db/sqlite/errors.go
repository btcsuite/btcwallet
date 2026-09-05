package sqlite

import (
	"errors"
	"strconv"

	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// SQLite result-code helper constants support error classification.
const (
	// primaryCodeMask strips a SQLite extended result code to its primary
	// result code.
	primaryCodeMask = 0xff
)

// reasonByCode maps SQLite primary result codes into the shared SQL error
// model.
var reasonByCode = map[int]dberr.Reason{
	sqlite3.SQLITE_BUSY:       dberr.ReasonBusy,
	sqlite3.SQLITE_LOCKED:     dberr.ReasonLocked,
	sqlite3.SQLITE_INTERRUPT:  dberr.ReasonUnknown,
	sqlite3.SQLITE_CONSTRAINT: dberr.ReasonConstraint,
	sqlite3.SQLITE_FULL:       dberr.ReasonResourceExhausted,
	sqlite3.SQLITE_NOMEM:      dberr.ReasonResourceExhausted,
	sqlite3.SQLITE_IOERR:      dberr.ReasonResourceExhausted,
	sqlite3.SQLITE_PROTOCOL:   dberr.ReasonUnavailable,
	sqlite3.SQLITE_READONLY:   dberr.ReasonReadOnly,
	sqlite3.SQLITE_PERM:       dberr.ReasonPermission,
	sqlite3.SQLITE_CORRUPT:    dberr.ReasonCorrupt,
	sqlite3.SQLITE_NOTADB:     dberr.ReasonCorrupt,
	sqlite3.SQLITE_NOTFOUND:   dberr.ReasonUnknown,
	sqlite3.SQLITE_SCHEMA:     dberr.ReasonSchemaMismatch,
	sqlite3.SQLITE_CANTOPEN:   dberr.ReasonUnknown,
}

// mapErr maps SQLite result codes into SQLError.
func mapErr(err error) *dberr.SQLError {
	// Start by extracting the SQLite driver error so the backend package can
	// inspect its numeric result code.
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		return nil
	}

	code := sqliteErr.Code()

	// Reduce extended result codes to their primary code before consulting the
	// shared reason map so related variants share one caller-facing bucket.
	primaryCode := primaryCode(code)
	codeString := codeString(code)

	reason, ok := reasonByCode[primaryCode]
	if !ok {
		reason = dberr.ReasonUnknown
	}

	return dberr.NewSQLError(dberr.BackendSQLite, reason, codeString, err)
}

// codeString formats a SQLite numeric result code for logs and stats.
func codeString(code int) string {
	return strconv.Itoa(code)
}

// primaryCode strips a SQLite extended result code to its primary code.
func primaryCode(code int) int {
	return code & primaryCodeMask
}
