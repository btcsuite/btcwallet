package db

import (
	"context"
	"database/sql"
	"fmt"

	sqlcpg "github.com/btcsuite/btcwallet/wallet/internal/db/sqlc/postgres"
	_ "github.com/jackc/pgx/v5/stdlib" // Import pgx driver for postgres database/sql support.
)

// PostgresStore is the PostgreSQL implementation of the
// WalletStore interface.
type PostgresStore struct {
	db      *sql.DB
	queries *sqlcpg.Queries
}

// NewPostgresStore creates a new PostgreSQL-based WalletStore. It handles
// the full connection setup including config validation, connection opening,
// health checks, connection pool configuration, and migration application.
func NewPostgresStore(ctx context.Context, cfg PostgresConfig) (*PostgresStore,
	error) {

	err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	db, err := sql.Open("pgx", cfg.Dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	connCtx, cancel := context.WithTimeout(ctx, DefaultConnectionTimeout)
	defer cancel()

	err = db.PingContext(connCtx)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	maxConns := DefaultMaxConnections
	if cfg.MaxConnections > 0 {
		maxConns = cfg.MaxConnections
	}

	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns)
	db.SetConnMaxIdleTime(DefaultConnIdleLifetime)

	queries := sqlcpg.New(db)

	err = ApplyPostgresMigrations(db)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply migrations: %w", err)
	}

	return &PostgresStore{
		db:      db,
		queries: queries,
	}, nil
}

// Close closes the database connection.
func (s *PostgresStore) Close() error {
	err := s.db.Close()
	if err != nil {
		return fmt.Errorf("close database: %w", err)
	}

	return nil
}

// ExecuteTx executes a function within a database transaction. The function
// receives a transactional query executor and should perform all database
// operations using it. The transaction will be automatically committed on
// success or rolled back on error.
func (s *PostgresStore) ExecuteTx(ctx context.Context,
	fn func(*sqlcpg.Queries) error) error {

	return execInTx(ctx, s.db, func(tx *sql.Tx) error {
		qtx := s.queries.WithTx(tx)
		return fn(qtx)
	})
}
