//go:build itest

package itest

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewTestStore(t *testing.T) {
	t.Parallel()

	// This test store exercises the underlying database connector in a test
	// environment, so we can verify that the store is created successfully with
	// a valid database connection and later properly closed. Will test all
	// backends (SQLite, PostgreSQL) based in the build tags.
	store := NewTestStore(t)

	require.NotNil(t, store)
	require.NotNil(t, store.DB())
	require.NotNil(t, store.Queries())
	require.NoError(t, store.Close())
}
