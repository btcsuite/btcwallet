//go:build js

package wallet

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
)

// newSQLiteManagerBackend rejects native SQLite startup on JavaScript targets.
// RPC clients can use Wallet types without linking the native SQLite driver.
func newSQLiteManagerBackend(_ context.Context, _ ManagerConfig,
	_ db.DatabaseIdentity) (*sqlManagerBackend, error) {

	// Keep the unsupported capability visible if a caller attempts to open
	// this backend; compiling a client must not pretend to create a store.
	return nil, fmt.Errorf("%w: sqlite on js", errUnsupportedBackend)
}
