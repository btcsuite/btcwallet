package pg

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Store is the PostgreSQL implementation of the
// WalletStore interface.
type Store struct {
	// db is the shared PostgreSQL connection pool.
	db *sql.DB

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

	connConfig, err := pgx.ParseConfig(cfg.Dsn)
	if err != nil {
		return nil, fmt.Errorf("parse database config: %w", err)
	}

	// Put pg_temp last so it cannot shadow unqualified wallet objects.
	connConfig.RuntimeParams["search_path"] = "btcwallet, pg_temp"

	dbConn := stdlib.OpenDB(*connConfig)

	connCtx, cancel := context.WithTimeout(ctx, db.DefaultConnectionTimeout)
	defer cancel()

	err = dbConn.PingContext(connCtx)
	if err != nil {
		_ = dbConn.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	maxConns := db.DefaultMaxConnections
	if cfg.MaxConnections > 0 {
		maxConns = cfg.MaxConnections
	}

	dbConn.SetMaxOpenConns(maxConns)
	dbConn.SetMaxIdleConns(maxConns)
	dbConn.SetConnMaxIdleTime(db.DefaultConnIdleLifetime)

	err = initializeDatabaseIdentity(ctx, dbConn, cfg.Identity)
	if err != nil {
		_ = dbConn.Close()

		return nil, fmt.Errorf("initialize database identity: %w", err)
	}

	err = pg.ApplyMigrations(dbConn)
	if err != nil {
		_ = dbConn.Close()
		return nil, fmt.Errorf("apply migrations: %w", err)
	}

	queries := sqlc.New(dbConn)

	return &Store{
		db:            dbConn,
		queries:       queries,
		deriveAddress: cfg.DeriveAddress,
	}, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	err := s.db.Close()
	if err != nil {
		return fmt.Errorf("close database: %w", err)
	}

	return nil
}
