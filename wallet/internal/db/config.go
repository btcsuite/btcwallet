package db

import (
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	// DefaultMaxConnections is the default maximum number of permitted
	// connections (both active and idle) to the database. We want to limit
	// this so it isn't unlimited. The same value is used for the maximum
	// number of idle connections, which can improve performance by avoiding
	// the overhead of establishing a new connection for each query.
	DefaultMaxConnections = 25

	// DefaultConnIdleLifetime is the default amount of time a connection
	// can be idle before being closed.
	DefaultConnIdleLifetime = 5 * time.Minute

	// DefaultConnectionTimeout is the default timeout for establishing
	// a new database connection.
	DefaultConnectionTimeout = 5 * time.Second
)

var (
	// ErrEmptyDBPath is returned when an empty database path is provided.
	ErrEmptyDBPath = errors.New("database path cannot be empty")

	// ErrNegativeMaxConns is returned when MaxConnections is negative.
	ErrNegativeMaxConns = errors.New("max connections must be non-negative")

	// ErrEmptyDSN is returned when the DSN string is empty.
	ErrEmptyDSN = errors.New("DSN is required")
)

// PostgresConfig holds the configuration for the PostgreSQL database.
type PostgresConfig struct {
	// Dsn is the database connection string.
	Dsn string

	// MaxConnections is the maximum number of open connections to the
	// database. Set to zero to use DefaultMaxConnections.
	MaxConnections int
}

// Validate checks that the PostgresConfig values are valid.
func (c *PostgresConfig) Validate() error {
	if c.Dsn == "" {
		return ErrEmptyDSN
	}

	// Parse the DSN using pgx to ensure it's a valid PostgreSQL
	// connection string.
	_, err := pgx.ParseConfig(c.Dsn)
	if err != nil {
		return fmt.Errorf("invalid DSN: %w", err)
	}

	if c.MaxConnections < 0 {
		return ErrNegativeMaxConns
	}

	return nil
}
