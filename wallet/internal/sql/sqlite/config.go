package sqlite

import (
	"errors"
	"time"

	"github.com/lightningnetwork/lnd/sqldb"
)

const (
	// DefaultMaxConnections limits SQLite contention to one writer and one
	// reader.
	DefaultMaxConnections = sqldb.DefaultSqliteMaxConns

	// DefaultBusyTimeout is the time SQLite waits for a locked database.
	DefaultBusyTimeout = sqldb.DefaultSqliteBusyTimeout

	// DefaultConnectionLifetime bounds connection reuse in the pool.
	DefaultConnectionLifetime = 10 * time.Minute
)

// Config holds the settings used to open a SQLite database.
type Config struct {
	DBPath             string
	BusyTimeout        time.Duration
	MaxConnections     int
	MaxIdleConnections int
	ConnectionLifetime time.Duration
	Pragmas            []string
}

// Validate checks that the SQLite configuration can be opened safely.
func (c Config) Validate() error {
	if c.DBPath == "" {
		return errors.New("database path is required")
	}

	if c.MaxConnections < 0 {
		return errors.New("maximum connections cannot be negative")
	}

	if c.MaxIdleConnections < 0 {
		return errors.New("maximum idle connections cannot be negative")
	}

	return nil
}

func (c Config) maxConnections() int {
	if c.MaxConnections > 0 {
		return c.MaxConnections
	}

	return DefaultMaxConnections
}

func (c Config) maxIdleConnections() int {
	if c.MaxIdleConnections > 0 {
		return c.MaxIdleConnections
	}

	return c.maxConnections()
}

func (c Config) busyTimeout() time.Duration {
	if c.BusyTimeout > 0 {
		return c.BusyTimeout
	}

	return DefaultBusyTimeout
}

func (c Config) connectionLifetime() time.Duration {
	if c.ConnectionLifetime > 0 {
		return c.ConnectionLifetime
	}

	return DefaultConnectionLifetime
}
