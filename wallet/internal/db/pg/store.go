package pg

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// Store is the PostgreSQL implementation of the
// WalletStore interface.
type Store struct {
	// pool is the native PostgreSQL connection pool used by Store queries.
	pool *pgxpool.Pool

	// queries executes PostgreSQL statements on db.
	queries *sqlc.Queries

	// deriveAddress derives address data for SQL-derived address rows.
	deriveAddress db.AddressDerivationFunc

	// runtimeStats tracks shared runtime counters and unhealthy state.
	runtimeStats dbruntime.Stats
}

// NewStore creates a new PostgreSQL-based WalletStore. It handles
// the full connection setup including config validation, connection opening,
// health checks, connection pool configuration, and migration application.
func NewStore(ctx context.Context, cfg Config) (*Store,
	error) {

	err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	poolConfig, err := pgxpool.ParseConfig(cfg.Dsn)
	if err != nil {
		return nil, fmt.Errorf("parse pool config: %w", err)
	}

	maxConns := db.DefaultMaxConnections
	if cfg.MaxConnections > 0 {
		maxConns = cfg.MaxConnections
	}

	// Config.Validate bounds MaxConnections to int32.
	poolConfig.MaxConns = int32(maxConns) //nolint:gosec
	// TODO(yy): make the idle connection lifetime configurable.
	poolConfig.MaxConnIdleTime = db.DefaultConnIdleLifetime

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	connCtx, cancel := context.WithTimeout(ctx, db.DefaultConnectionTimeout)
	defer cancel()

	err = pool.Ping(connCtx)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	migrationDB := stdlib.OpenDBFromPool(pool)

	err = pg.ApplyMigrations(ctx, migrationDB)
	if err != nil {
		_ = migrationDB.Close()
		pool.Close()

		return nil, fmt.Errorf("apply migrations: %w", err)
	}

	err = migrationDB.Close()
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("close migration database: %w", err)
	}

	return &Store{
		pool:          pool,
		queries:       sqlc.New(pool),
		deriveAddress: cfg.DeriveAddress,
	}, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	s.pool.Close()

	return nil
}
