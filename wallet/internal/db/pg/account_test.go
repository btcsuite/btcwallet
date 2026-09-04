package pg

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// The unique indexes the accounts table declares. Both are unique-violation
// sources, so the classifier has to tell them apart by name.
const (
	accountNameIndex   = "uidx_accounts_wallet_scope_account_name"
	accountNumberIndex = "uidx_accounts_scope_account_number"
)

// TestIsAccountNameConflictMatchesNameIndex verifies a unique violation on the
// account-name index is reported as a name conflict, whether the driver error
// arrives bare or wrapped for context. The wrapped case is why the classifier
// unwraps instead of asserting the driver type directly.
func TestIsAccountNameConflictMatchesNameIndex(t *testing.T) {
	t.Parallel()

	err := &pgconn.PgError{
		Code:           codeUniqueViolation,
		ConstraintName: accountNameIndex,
	}

	require.True(t, IsAccountNameConflict(err))
	require.True(t, IsAccountNameConflict(
		fmt.Errorf("insert account: %w", err),
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
		// A colliding account number is a distinct outcome the wallet
		// reports separately, even though it shares the SQLSTATE.
		name: "unique violation on the account-number index",
		err: &pgconn.PgError{
			Code:           codeUniqueViolation,
			ConstraintName: accountNumberIndex,
		},
	}, {
		// The name index appears in errors that are not collisions.
		name: "foreign-key violation naming the account-name index",
		err: &pgconn.PgError{
			Code:           codeForeignKeyViolation,
			ConstraintName: accountNameIndex,
		},
	}, {
		// Nothing but the driver's own typed error carries a constraint
		// name, so matching on message text would be a false positive.
		name: "untyped error whose text mentions a duplicate",
		err:  errors.New("duplicate key value"),
	}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.False(t, IsAccountNameConflict(tc.err))
			require.False(t, IsAccountNameConflict(
				fmt.Errorf("insert account: %w", tc.err),
			))
		})
	}
}

// TestIsAccountNameConflictRejectsNil verifies a successful call is never
// classified as a conflict.
func TestIsAccountNameConflictRejectsNil(t *testing.T) {
	t.Parallel()

	require.False(t, IsAccountNameConflict(nil))
}
