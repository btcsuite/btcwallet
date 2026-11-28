package pg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/mock"
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

// TestMapErrAccountNameConflict keeps name and number collision identities
// distinct without classifying unrelated unique failures.
func TestMapErrAccountNameConflict(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		constraint string
		want       bool
		wantNumber bool
	}{
		{
			name:       "account name",
			constraint: accountNameConstraint,
			want:       true,
		},
		{
			name:       "account number",
			constraint: accountNumberConstraint,
			wantNumber: true,
		},
		{
			name:       "other unique index",
			constraint: "uidx_accounts_wallet_scope_account_number",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: Wrap a unique violation as Store operations do.
			cause := fmt.Errorf("write: %w", &pgconn.PgError{
				Code:           codeUniqueViolation,
				ConstraintName: test.constraint,
			})

			// Act: Classify the driver failure through the backend mapper.
			err := mapErr(cause)

			// Assert: Each known index gains only its matching Store identity.
			require.ErrorIs(t, err, cause)
			require.Equal(t, test.want, errors.Is(
				err, db.ErrAccountNameConflict,
			))
			require.Equal(t, test.wantNumber, errors.Is(
				err, db.ErrAccountNumberConflict,
			))
		})
	}
}

// TestIsCommitAmbiguous verifies sent cancellation and EOF remain ambiguous
// while an explicit server rollback is definite.
func TestIsCommitAmbiguous(t *testing.T) {
	t.Parallel()

	// Arrange: Use plain native errors for sent cancellation, explicit
	// rollback, and EOF. The public Store test covers UnexpectedEOF.
	tests := []struct {
		name      string
		err       error
		ambiguous bool
	}{
		{
			name:      "canceled after send",
			err:       context.Canceled,
			ambiguous: true,
		},
		{
			name:      "deadline after send",
			err:       context.DeadlineExceeded,
			ambiguous: true,
		},
		{
			name: "commit rollback",
			err:  pgx.ErrTxCommitRollback,
		},
		{
			name:      "end of file",
			err:       io.EOF,
			ambiguous: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Act: Classify the native commit evidence for this outcome.
			ambiguous := isCommitAmbiguous(test.err)

			// Assert: A lost reply or sent cancellation leaves the outcome
			// unknown, while the explicit rollback guarantees no commit.
			require.Equal(t, test.ambiguous, ambiguous)
		})
	}
}

// safeRetryError models pgconn's positive before-send evidence with explicit
// expectations; ordinary error traversal remains visible to the test.
type safeRetryError struct {
	mock.Mock
}

// Error forwards any requested printable error text to the configured mock.
func (e *safeRetryError) Error() string {
	args := e.Called()

	return args.String(0)
}

// Unwrap supplies the configured cancellation cause during errors.Is traversal.
func (e *safeRetryError) Unwrap() error {
	args := e.Called()

	return args.Error(0)
}

// SafeToRetry supplies the transport's configured before-send guarantee.
func (e *safeRetryError) SafeToRetry() bool {
	args := e.Called()

	return args.Bool(0)
}

// TestIsCommitAmbiguousBeforeSend verifies native proof of an unsent commit
// keeps cancellation definite regardless of error traversal order.
func TestIsCommitAmbiguousBeforeSend(t *testing.T) {
	t.Parallel()

	causes := []error{
		context.Canceled,
		context.DeadlineExceeded,
	}
	for _, cause := range causes {
		t.Run(cause.Error(), func(t *testing.T) {
			t.Parallel()

			// Arrange: Wrap cancellation with positive before-send proof.
			// Error traversal is optional because the classifier may ask
			// SafeToRetry before inspecting the wrapped cause.
			unsent := &safeRetryError{}
			unsent.Test(t)
			unsent.On("Error").Return(cause.Error()).Maybe()
			unsent.On("Unwrap").Return(cause).Maybe()
			unsent.On("SafeToRetry").Return(true).Once()
			t.Cleanup(func() { unsent.AssertExpectations(t) })

			// Act: Classify the commit error using its native unsent proof.
			ambiguous := isCommitAmbiguous(unsent)

			// Assert: No commit bytes reached the server, so cancellation
			// cannot represent an unknown commit outcome. Cleanup verifies
			// the required proof once without fixing traversal order.
			require.False(t, ambiguous)
		})
	}
}
