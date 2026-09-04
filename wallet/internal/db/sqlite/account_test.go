package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	sqliteschema "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
	"github.com/stretchr/testify/require"
)

// accountConflicts holds a real driver error for each unique constraint the
// accounts table declares.
type accountConflicts struct {
	name   error
	number error
}

// provokeAccountConflicts collides with each unique constraint on the accounts
// table. SQLite names the offending columns in its message rather than the
// index, so the classifier is exercised against the driver's own text instead
// of a handwritten copy that could drift from it.
func provokeAccountConflicts(t *testing.T) accountConflicts {
	t.Helper()

	conn, err := sql.Open("sqlite", ":memory:?_pragma=foreign_keys(1)")
	require.NoError(t, err)
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })

	require.NoError(t, sqliteschema.ApplyMigrations(conn))
	queries := sqlc.New(conn)
	ctx := t.Context()
	walletID, err := queries.CreateWallet(ctx, sqlc.CreateWalletParams{
		WalletName: "test",
	})
	require.NoError(t, err)
	scopeID, err := queries.CreateKeyScope(ctx, sqlc.CreateKeyScopeParams{
		WalletID:       walletID,
		Purpose:        84,
		InternalTypeID: int64(db.WitnessPubKey),
		ExternalTypeID: int64(db.WitnessPubKey),
	})
	require.NoError(t, err)

	params := sqlc.CreateDerivedAccountParams{
		ScopeID:       scopeID,
		AccountName:   "taken",
		AccountNumber: sql.NullInt64{Int64: 7, Valid: true},
	}
	_, err = queries.CreateDerivedAccount(ctx, params)
	require.NoError(t, err)

	// Reuse the seeded name with a free number, then a free name with the
	// seeded number, so each insert can only violate one constraint.
	params.AccountNumber.Int64 = 8
	_, nameErr := queries.CreateDerivedAccount(ctx, params)
	require.Error(t, nameErr)

	params.AccountName = "fresh"
	params.AccountNumber.Int64 = 7
	_, numberErr := queries.CreateDerivedAccount(ctx, params)
	require.Error(t, numberErr)

	return accountConflicts{name: nameErr, number: numberErr}
}

// TestIsAccountNameConflictMatchesNameColumns verifies a real collision on the
// account-name constraint is reported as a name conflict, whether the driver
// error arrives bare or wrapped for context. The wrapped case is why the
// classifier unwraps instead of asserting the driver type directly.
func TestIsAccountNameConflictMatchesNameColumns(t *testing.T) {
	t.Parallel()

	conflicts := provokeAccountConflicts(t)

	require.True(t, IsAccountNameConflict(conflicts.name))
	require.True(t, IsAccountNameConflict(
		fmt.Errorf("insert account: %w", conflicts.name),
	))
}

// TestIsAccountNameConflictRejectsOtherFailures verifies every other failure
// is left to another classifier, so a duplicate account name is the only thing
// that can be reported as one.
func TestIsAccountNameConflictRejectsOtherFailures(t *testing.T) {
	t.Parallel()

	conflicts := provokeAccountConflicts(t)

	for _, tc := range []struct {
		name string
		err  error
	}{{
		// A colliding account number is a distinct outcome the wallet
		// reports separately, even though it shares the result code.
		name: "unique violation on the account-number columns",
		err:  conflicts.number,
	}, {
		// Only the driver's typed error carries the result code, so
		// matching the same words as plain text is a false positive.
		name: "untyped error carrying the same message text",
		err:  errors.New(conflicts.name.Error()),
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
