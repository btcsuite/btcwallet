package dberr

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// TestIsAccountNameConflict rejects unrelated constraints even when they share
// a uniqueness code or contain the same words in their diagnostic message.
func TestIsAccountNameConflict(t *testing.T) {
	t.Parallel()

	conn, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	_, err = conn.ExecContext(t.Context(), `
		CREATE TABLE accounts (
			wallet_id INTEGER, scope_id INTEGER, account_name TEXT,
			account_number INTEGER,
			UNIQUE(wallet_id, scope_id, account_name),
			UNIQUE(scope_id, account_number)
		);
		INSERT INTO accounts VALUES (1, 1, 'taken', 7);
	`)
	require.NoError(t, err)
	_, nameErr := conn.ExecContext(
		t.Context(), "INSERT INTO accounts VALUES (1, 1, 'taken', 8)",
	)
	require.Error(t, nameErr)
	_, numberErr := conn.ExecContext(
		t.Context(), "INSERT INTO accounts VALUES (1, 1, 'fresh', 7)",
	)
	require.Error(t, numberErr)

	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"sqlite name", nameErr, true},
		{"sqlite number", numberErr, false},
		{"untyped message", errors.New(nameErr.Error()), false},
		{"postgres name", &pgconn.PgError{
			Code:           "23505",
			ConstraintName: "uidx_accounts_wallet_scope_account_name",
		}, true},
		{"postgres number", &pgconn.PgError{
			Code:           "23505",
			ConstraintName: "uidx_accounts_scope_account_number",
		}, false},
		{"postgres non-unique", &pgconn.PgError{
			Code:           "23503",
			ConstraintName: "uidx_accounts_wallet_scope_account_name",
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, IsAccountNameConflict(tc.err))

			if tc.err != nil {
				wrapped := fmt.Errorf("insert account: %w", tc.err)
				require.Equal(t, tc.want, IsAccountNameConflict(wrapped))
				require.ErrorIs(t, wrapped, tc.err)
			}
		})
	}
}

// TestIsAccountNumberConflict distinguishes an occupied derived number from
// unrelated uniqueness failures using real SQLite and PostgreSQL diagnostics.
func TestIsAccountNumberConflict(t *testing.T) {
	t.Parallel()

	// Arrange: provoke SQLite's actual number constraint and pair it with
	// PostgreSQL metadata; plain diagnostic text must not gain SQL identity.
	conn, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	conn.SetMaxOpenConns(1)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	_, err = conn.ExecContext(t.Context(), `
		CREATE TABLE accounts (
			scope_id INTEGER, account_number INTEGER,
			UNIQUE(scope_id, account_number)
		);
		INSERT INTO accounts VALUES (1, 7);
	`)
	require.NoError(t, err)
	_, numberErr := conn.ExecContext(
		t.Context(), "INSERT INTO accounts VALUES (1, 7)",
	)
	require.Error(t, numberErr)

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "sqlite number",
			err:  numberErr,
			want: true,
		},
		{
			name: "postgres number",
			err: &pgconn.PgError{
				Code:           "23505",
				ConstraintName: "uidx_accounts_scope_account_number",
			},
			want: true,
		},
		{
			name: "unrelated constraint",
			err: &pgconn.PgError{
				Code:           "23505",
				ConstraintName: "uidx_accounts_wallet_scope_account_name",
			},
		},
		{
			name: "untyped message",
			err:  errors.New(numberErr.Error()),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Act: classify a wrapped failure as returned by the Store.
			conflict := IsAccountNumberConflict(
				fmt.Errorf("create account: %w", test.err),
			)

			// Assert: only the number index acquires the conflict identity.
			require.Equal(t, test.want, conflict)
		})
	}
}
