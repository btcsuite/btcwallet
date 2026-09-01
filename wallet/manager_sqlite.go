package wallet

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
)

// newSQLiteManagerBackend opens the SQLite Store owned by a Manager and passes
// the Manager's validated network identity into Store startup.
func newSQLiteManagerBackend(ctx context.Context, cfg ManagerConfig,
	identity db.DatabaseIdentity) (*sqlManagerBackend, error) {

	err := os.MkdirAll(filepath.Dir(cfg.DataSource), defaultWalletDBDirPerm)
	if err != nil {
		return nil, fmt.Errorf("create sqlite dir: %w", err)
	}

	store, err := sqlite.NewStore(ctx, sqlite.Config{
		DBPath:         cfg.DataSource,
		MaxConnections: cfg.MaxConnections,
		DeriveAddress:  newSQLAddressDeriver(cfg.ChainParams),
		Identity:       identity,
	})
	if err != nil {
		return nil, fmt.Errorf("open sqlite store: %w", err)
	}

	return &sqlManagerBackend{
		store:   store,
		closeFn: store.Close,
	}, nil
}
