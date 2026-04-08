package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	sqlassetsqlite "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite"
	sqlcsqlite "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite/sqlc"
	_ "modernc.org/sqlite" // Import sqlite driver for sqlite database/sql support.
)

// SqliteStore is the SQLite implementation of the WalletStore interface.

type SqliteStore struct {
	db      *sql.DB
	queries *sqlcsqlite.Queries
}

// NewSqliteStore creates a new SQLite-based WalletStore. It handles the full
// connection setup including DSN construction with pragmas, connection
// opening, health checks, connection pool configuration, and migration
// application.
func NewSqliteStore(ctx context.Context, cfg db.SqliteConfig) (*SqliteStore,
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

	queries := sqlcsqlite.New(dbConn)

	err = sqlassetsqlite.ApplyMigrations(dbConn)
	if err != nil {
		_ = dbConn.Close()
		return nil, fmt.Errorf("apply migrations: %w", err)
	}

	return &SqliteStore{
		db:      dbConn,
		queries: queries,
	}, nil
}

// Close closes the database connection.
func (s *SqliteStore) Close() error {
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
func (s *SqliteStore) ExecuteTx(ctx context.Context,
	fn func(*sqlcsqlite.Queries) error) error {

	return db.ExecInTx(ctx, s.db, func(tx *sql.Tx) error {
		qtx := s.queries.WithTx(tx)
		return fn(qtx)
	})
}
