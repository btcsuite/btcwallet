//go:build itest

package itest

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMigrationsRollbackReapply ensures that the full migration chain
// can be cleanly rolled back and then reapplied without errors.
func TestMigrationsRollbackReapply(t *testing.T) {
	t.Parallel()

	s := NewTestStore(t)

	err := s.RollbackAllMigrations()
	require.NoError(t, err, "failed to rollback all migrations")

	// Reapply all migrations to verify that the database can return to a
	// valid, fully migrated state after a complete rollback.
	err = s.ApplyAllMigrations()
	require.NoError(t, err, "failed to reapply all migrations")
}
