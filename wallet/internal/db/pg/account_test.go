package pg

import (
	"errors"
	"fmt"
	"testing"

	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// TestIsAccountNameConflictMatchesNameIndex verifies a unique violation on the
// account-name index is reported as a name conflict, whether the driver error
// arrives bare or wrapped for context. The wrapped case is why the classifier
// unwraps instead of asserting the driver type directly.
func TestIsAccountNameConflictMatchesNameIndex(t *testing.T) {
	t.Parallel()

	err := &pgconn.PgError{
		Code:           codeUniqueViolation,
		ConstraintName: accountNameConstraint,
	}

	store := &Store{}
	classified := store.ClassifyError(err)

	require.True(t, dberr.IsAccountNameConflict(classified))
	require.ErrorIs(t, classified, err)
	require.True(t, dberr.IsAccountNameConflict(
		store.ClassifyError(fmt.Errorf("insert account: %w", err)),
	))
}

// TestIsAccountNameConflictRejectsOtherFailures verifies every other failure
// is left to another classifier, so a duplicate account name is the only thing
// that can be reported as one.
func TestIsAccountNameConflictRejectsOtherFailures(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		err  error
	}{{
		name: "unique violation on an unrelated index",
		err: &pgconn.PgError{
			Code:           codeUniqueViolation,
			ConstraintName: "other_unique_index",
		},
	}, {
		// The name index appears in errors that are not collisions.
		name: "foreign-key violation naming the account-name index",
		err: &pgconn.PgError{
			Code:           codeForeignKeyViolation,
			ConstraintName: accountNameConstraint,
		},
	}, {
		// Nothing but the driver's own typed error carries a constraint
		// name, so matching on message text would be a false positive.
		name: "untyped error whose text mentions a duplicate",
		err:  errors.New("duplicate key value"),
	}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := &Store{}

			require.False(t, dberr.IsAccountNameConflict(
				store.ClassifyError(tc.err),
			))
			require.False(t, dberr.IsAccountNameConflict(
				store.ClassifyError(fmt.Errorf("insert account: %w", tc.err)),
			))
		})
	}
}

// TestIsAccountNameConflictRejectsNil verifies a successful call is never
// classified as a conflict.
func TestIsAccountNameConflictRejectsNil(t *testing.T) {
	t.Parallel()

	store := &Store{}

	require.False(t, dberr.IsAccountNameConflict(store.ClassifyError(nil)))
}
