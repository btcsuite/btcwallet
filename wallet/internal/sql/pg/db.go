package pg

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
)

const defaultOpenTimeout = 10 * time.Second

// Open opens and verifies a PostgreSQL connection pool.
func Open(ctx context.Context, cfg Config) (*sql.DB, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid postgres config: %w", err)
	}

	connConfig, err := cfg.connectionConfig()
	if err != nil {
		return nil, err
	}

	db := stdlib.OpenDB(*connConfig)

	db.SetMaxOpenConns(cfg.maxConnections())
	db.SetMaxIdleConns(cfg.maxIdleConnections())
	db.SetConnMaxLifetime(cfg.connectionLifetime())
	db.SetConnMaxIdleTime(cfg.connectionMaxIdleTime())

	openCtx, cancel := context.WithTimeout(ctx, defaultOpenTimeout)
	defer cancel()

	err = db.PingContext(openCtx)
	if err != nil {
		_ = db.Close()

		return nil, fmt.Errorf("ping postgres database: %w", err)
	}

	return db, nil
}
