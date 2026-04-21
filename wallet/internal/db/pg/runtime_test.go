package pg

import (
	"database/sql"
	"io"
	"testing"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dberr "github.com/btcsuite/btcwallet/wallet/internal/db/err"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// TestClassifyErrorReturnsOriginalErrors verifies that PostgreSQL
// classification preserves domain and already-classified errors unchanged.
func TestClassifyErrorReturnsOriginalErrors(t *testing.T) {
	t.Parallel()

	store := &Store{}
	errDup := dberr.NewSQLError(
		dberr.BackendPostgres,
		dberr.ReasonConstraint,
		codeUniqueViolation,
		sql.ErrTxDone,
	)
	tests := []struct {
		name string
		err  error
	}{
		{name: "wallet not found", err: db.ErrWalletNotFound},
		{name: "tx not found", err: db.ErrTxNotFound},
		{name: "generic error", err: io.ErrClosedPipe},
		{name: "existing sql error", err: errDup},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			require.Same(t, test.err, store.ClassifyError(test.err))
		})
	}
}

// TestClassifyErrorTransportError verifies that PostgreSQL transport failures
// are classified as shared unavailable SQL errors.
func TestClassifyErrorTransportError(t *testing.T) {
	t.Parallel()

	store := &Store{}
	classifiedErr := store.ClassifyError(&pgconn.ConnectError{})

	var sqlErr *dberr.SQLError
	require.ErrorAs(t, classifiedErr, &sqlErr)
	require.Equal(t, dberr.ReasonUnavailable, sqlErr.Reason)
}

// TestClassifyErrorBackendErrors verifies that PostgreSQL backend-native
// errors stay wrapped as shared SQL errors for both known and unknown codes.
func TestClassifyErrorBackendErrors(t *testing.T) {
	t.Parallel()

	store := &Store{}
	tests := []struct {
		name       string
		err        error
		wantReason dberr.Reason
	}{
		{
			name: "known code",
			err: &pgconn.PgError{
				Code:    codeUniqueViolation,
				Message: "duplicate key",
			},
			wantReason: dberr.ReasonConstraint,
		},
		{
			name: "unknown code",
			err: &pgconn.PgError{
				Code:    "99999",
				Message: "unknown error",
			},
			wantReason: dberr.ReasonUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			classifiedErr := store.ClassifyError(test.err)

			var sqlErr *dberr.SQLError
			require.ErrorAs(t, classifiedErr, &sqlErr)
			require.Equal(t, test.wantReason, sqlErr.Reason)
			require.Equal(t, dberr.BackendPostgres, sqlErr.Backend)
		})
	}
}
