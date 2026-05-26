package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/btcsuite/btcwallet/wallet/internal/db"
	dbruntime "github.com/btcsuite/btcwallet/wallet/internal/db/runtime"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite"
	"github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
	_ "modernc.org/sqlite" // Import sqlite driver for sqlite database/sql support.
)

// Store is the SQLite implementation of the WalletStore interface.
type Store struct {
	// db is the shared SQLite connection pool.
	db *sql.DB

	// queries executes SQLite statements on db.
	queries *sqlc.Queries

	// deriveAddress derives address data for SQL-derived address rows.
	deriveAddress db.AddressDerivationFunc

	// runtimeStats tracks shared runtime counters and unhealthy state.
	runtimeStats dbruntime.Stats
}

// NewStore creates a new SQLite-based WalletStore. It handles the full
// connection setup including DSN construction with pragmas, connection
// opening, health checks, connection pool configuration, and migration
// application.
func NewStore(ctx context.Context, cfg Config) (*Store,
	error) {

	err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	dsn := cfg.DBPath + "?_pragma=foreign_keys=on"
	dsn += "&_pragma=journal_mode=WAL"
	dsn += "&_txlock=immediate"
	dsn += "&_pragma=busy_timeout=5000"
	dsn += "&_time_format=sqlite"

	dbConn, err := sql.Open("sqlite", dsn)
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

	err = sqlite.ApplyMigrations(dbConn)
	if err != nil {
		_ = dbConn.Close()
		return nil, fmt.Errorf("apply migrations: %w", err)
	}

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
