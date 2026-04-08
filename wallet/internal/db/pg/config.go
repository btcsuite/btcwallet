package pg

import (
	"fmt"

	db "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/jackc/pgx/v5"
)

// Config holds the configuration for the PostgreSQL database.
type Config struct {
	// Dsn is the database connection string.
	Dsn string

	// MaxConnections is the maximum number of open connections to the
	// database. Set to zero to use db.DefaultMaxConnections.
	MaxConnections int
}

// Validate checks that the Config values are valid.
func (c *Config) Validate() error {
	if c.Dsn == "" {
		return db.ErrEmptyDSN
	}

	_, err := pgx.ParseConfig(c.Dsn)
	if err != nil {
		return fmt.Errorf("invalid DSN: %w", err)
	}

	if c.MaxConnections < 0 {
		return db.ErrNegativeMaxConns
	}

	return nil
}
