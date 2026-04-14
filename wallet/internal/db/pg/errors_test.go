package pg

import (
	"io"
	"testing"

	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// codeClassificationTestCase defines one SQLSTATE mapping expectation.
type codeClassificationTestCase struct {
	// name describes the subtest.
	name string

	// code is the PostgreSQL SQLSTATE under test.
	code string

	// wantReason is the expected shared SQL error reason.
	wantReason dberr.Reason
}

// TestMapCode verifies that representative SQLSTATEs map to the expected
// reason and class buckets.
func TestMapCode(t *testing.T) {
	t.Parallel()

	tests := []codeClassificationTestCase{
		{
			name:       "serialization",
			code:       codeSerializationFailure,
			wantReason: dberr.ReasonSerialization,
		},
		{
			name:       "deadlock",
			code:       codeDeadlockDetected,
			wantReason: dberr.ReasonDeadlock,
		},
		{
			name:       "too many connections",
			code:       codeTooManyConnections,
			wantReason: dberr.ReasonPoolExhausted,
		},
		{
			name:       "disk full",
			code:       codeDiskFull,
			wantReason: dberr.ReasonResourceExhausted,
		},
		{
			name:       "schema mismatch",
			code:       codeUndefinedTable,
			wantReason: dberr.ReasonSchemaMismatch,
		},
		{
			name:       "constraint",
			code:       codeUniqueViolation,
			wantReason: dberr.ReasonConstraint,
		},
		{
			name:       "not null constraint",
			code:       codeNotNullViolation,
			wantReason: dberr.ReasonConstraint,
		},
		{
			name:       "exclusion constraint",
			code:       codeExclusionViolation,
			wantReason: dberr.ReasonConstraint,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := mapCode(testCase.code, io.EOF)
			require.NotNil(t, err)
			require.Equal(t, dberr.BackendPostgres, err.Backend)
			require.Equal(t, testCase.wantReason, err.Reason)
			require.Equal(t, testCase.wantReason.Class(), err.Class())
			require.Equal(t, testCase.code, err.Code)
		})
	}
}

// TestMapCodeFallback verifies the fallback mapping paths for connection
// exception classes and unknown SQLSTATEs.
func TestMapCodeFallback(t *testing.T) {
	t.Parallel()

	connectionErr := mapCode("08006", io.EOF)
	require.NotNil(t, connectionErr)
	require.Equal(t, dberr.ReasonUnavailable, connectionErr.Reason)
	require.Equal(t, dberr.ClassTransient, connectionErr.Class())

	unknownErr := mapCode("99999", io.EOF)
	require.NotNil(t, unknownErr)
	require.Equal(t, dberr.ReasonUnknown, unknownErr.Reason)
	require.Equal(t, dberr.ClassPermanent, unknownErr.Class())

	require.Equal(t, "08", sqlStateClass("08006"))
	require.Empty(t, sqlStateClass("0"))
}

// TestMapErr verifies that driver-specific PostgreSQL errors are recognized and
// wrapped as SQL errors.
func TestMapErr(t *testing.T) {
	t.Parallel()

	err := mapErr(&pgconn.PgError{
		Code:    codeReadOnlyTxn,
		Message: "read only",
	})
	require.NotNil(t, err)
	require.Equal(t, dberr.BackendPostgres, err.Backend)
	require.Equal(t, dberr.ReasonReadOnly, err.Reason)
	require.Equal(t, dberr.ClassFatal, err.Class())
}
