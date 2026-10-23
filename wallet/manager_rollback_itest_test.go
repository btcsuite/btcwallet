//go:build itest

package wallet

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// TestManagerRollbackPostgres verifies the same prepared Manager continuation
// and terminal-error contract on PostgreSQL using isolated scenario databases.
func TestManagerRollbackPostgres(t *testing.T) {
	t.Parallel()

	// Arrange: Each shared outcome owns a disposable PostgreSQL instance.
	// Existing container readiness and cleanup handle the Docker lifecycle;
	// Manager cleanup is registered later and therefore joins Wallets first.
	// Act: The shared scenario submits success and fault-injected disconnects.
	// Assert: Its durable checkpoint/effect and terminal-state assertions are
	// identical to SQLite, without duplicating the Store atomicity matrix.
	testManagerRollbackStore(t, DBBackendPostgres, func(t *testing.T) string {
		t.Helper()

		container, err := postgres.Run(t.Context(), "postgres:18-alpine",
			postgres.WithDatabase("rollback"),
			postgres.WithUsername("postgres"),
			postgres.WithPassword("postgres"),
			postgres.BasicWaitStrategies(),
		)
		testcontainers.CleanupContainer(t, container)
		require.NoError(t, err)

		dsn, err := container.ConnectionString(t.Context(), "sslmode=disable")
		require.NoError(t, err)

		return dsn
	})
}
