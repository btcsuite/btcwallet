package wallet

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/pg"
)

// newPostgresManagerBackend opens the PostgreSQL Store owned by a Manager and
// passes the Manager's validated network identity into Store startup.
func newPostgresManagerBackend(ctx context.Context, cfg ManagerConfig,
	identity db.DatabaseIdentity) (*sqlManagerBackend, error) {

	store, err := pg.NewStore(ctx, pg.Config{
		Dsn:            cfg.DataSource,
		MaxConnections: cfg.MaxConnections,
		DeriveAddress:  newSQLAddressDeriver(cfg.ChainParams),
		Identity:       identity,
	})
	if err != nil {
		return nil, fmt.Errorf("open postgres store: %w", err)
	}

	return &sqlManagerBackend{
		store:   store,
		closeFn: store.Close,
	}, nil
}
