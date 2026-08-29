package wallet

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db/pg"
)

// newPostgresManagerBackend opens the PostgreSQL Store owned by a Manager.
func newPostgresManagerBackend(ctx context.Context,
	cfg ManagerConfig) (*sqlManagerBackend, error) {

	store, err := pg.NewStore(ctx, pg.Config{
		Dsn:            cfg.DataSource,
		MaxConnections: cfg.MaxConnections,
		DeriveAddress:  newSQLAddressDeriver(&cfg.ChainParams),
	})
	if err != nil {
		return nil, fmt.Errorf("open postgres store: %w", err)
	}

	return &sqlManagerBackend{
		store:   store,
		closeFn: store.Close,
	}, nil
}
