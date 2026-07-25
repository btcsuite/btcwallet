package sqlstore

import (
	"database/sql"
	"errors"
	"testing"

	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// TestUpdateOnceRunsBodyOnce verifies that a retryable body failure is
// returned to the caller without replaying the callback.
func TestUpdateOnceRunsBodyOnce(t *testing.T) {
	t.Parallel()

	conn, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, conn.Close())
	})

	store := New(conn, 1, func(*sql.Tx) Queries {
		return nil
	})
	var bodyCalls, resetCalls int
	err = store.UpdateOnce(
		t.Context(), func(walletstore.ReadWriteTx) error {
			bodyCalls++
			return errors.New("SQLITE_BUSY")
		}, func() {
			resetCalls++
		},
	)

	var retryable *walletstore.RetryableTransactionError
	require.ErrorAs(t, err, &retryable)
	var ambiguous *walletstore.AmbiguousCommitError
	require.NotErrorAs(t, err, &ambiguous)
	require.Equal(t, 1, bodyCalls)
	require.Equal(t, 1, resetCalls)
}

// TestUpdateOncePublishesHooks verifies that commit hooks run once and only
// after the single SQL attempt commits successfully.
func TestUpdateOncePublishesHooks(t *testing.T) {
	t.Parallel()

	conn, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, conn.Close())
	})

	store := New(conn, 1, func(*sql.Tx) Queries {
		return nil
	})
	var bodyCalls, hookCalls int
	err = store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			bodyCalls++
			tx.Addr().OnCommit(func() {
				hookCalls++
			})
			return nil
		}, nil,
	)
	require.NoError(t, err)
	require.Equal(t, 1, bodyCalls)
	require.Equal(t, 1, hookCalls)
}

// TestMapCommitError verifies that only definitely aborted serialization
// failures are retryable and ordinary commit failures are ambiguous.
func TestMapCommitError(t *testing.T) {
	t.Parallel()

	retryableErr := mapCommitError(errors.New("SQLITE_BUSY"))
	var retryable *walletstore.RetryableTransactionError
	require.ErrorAs(t, retryableErr, &retryable)
	var ambiguous *walletstore.AmbiguousCommitError
	require.NotErrorAs(t, retryableErr, &ambiguous)

	ambiguousErr := mapCommitError(errors.New("connection lost"))
	require.ErrorAs(t, ambiguousErr, &ambiguous)
	require.NotErrorAs(t, ambiguousErr, &retryable)
}
