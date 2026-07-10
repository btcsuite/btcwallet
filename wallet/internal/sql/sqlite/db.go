package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"time"

	_ "modernc.org/sqlite"
)

const defaultOpenTimeout = 10 * time.Second

// Open opens and verifies a SQLite connection pool.
func Open(ctx context.Context, cfg Config) (*sql.DB, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid sqlite config: %w", err)
	}

	options := url.Values{}
	defaultPragmas := []string{
		"foreign_keys=on",
		"journal_mode=WAL",
		fmt.Sprintf("busy_timeout=%d", cfg.busyTimeout().Milliseconds()),
		"synchronous=full",
		"fullfsync=true",
		"auto_vacuum=incremental",
	}
	for _, pragma := range append(defaultPragmas, cfg.Pragmas...) {
		options.Add("_pragma", pragma)
	}

	dsn := fmt.Sprintf(
		"%s?%s&_txlock=immediate&_time_format=sqlite", cfg.DBPath,
		options.Encode(),
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(cfg.maxConnections())
	db.SetMaxIdleConns(cfg.maxIdleConnections())
	db.SetConnMaxLifetime(cfg.connectionLifetime())

	openCtx, cancel := context.WithTimeout(ctx, defaultOpenTimeout)
	defer cancel()

	if err := db.PingContext(openCtx); err != nil {
		_ = db.Close()

		return nil, fmt.Errorf("ping sqlite database: %w", err)
	}

	return db, nil
}
