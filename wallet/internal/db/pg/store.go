package pg

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/pg/sqlc"
	_ "github.com/jackc/pgx/v5/stdlib" // Import pgx driver for postgres database/sql support.
)

// Store is the PostgreSQL implementation of the
// WalletStore interface.
type Store struct {
	db      *sql.DB
	queries *sqlc.Queries
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

	dbConn, err := sql.Open("pgx", cfg.Dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

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

	queries := sqlc.New(dbConn)

	err = pg.ApplyMigrations(dbConn)
	if err != nil {
		_ = dbConn.Close()
		return nil, fmt.Errorf("apply migrations: %w", err)
	}

	return &Store{
		db:      dbConn,
		queries: queries,
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

// ExecuteTx executes a function within a database transaction. The function
// receives a transactional query executor and should perform all database
// operations using it. The transaction will be automatically committed on
// success or rolled back on error.
func (s *Store) ExecuteTx(ctx context.Context,
	fn func(*sqlc.Queries) error) error {

	return db.ExecInTx(ctx, s.db, func(tx *sql.Tx) error {
		qtx := s.queries.WithTx(tx)
		return fn(qtx)
	})
}
