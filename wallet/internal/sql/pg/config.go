package pg

import (
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	// DefaultMaxConnections bounds the PostgreSQL connection pool.
	DefaultMaxConnections = 25

	// DefaultMaxIdleConnections bounds idle PostgreSQL connections.
	DefaultMaxIdleConnections = 6

	// DefaultConnectionLifetime bounds connection reuse in the pool.
	DefaultConnectionLifetime = 10 * time.Minute

	// DefaultConnectionIdleTime closes connections that remain idle.
	DefaultConnectionIdleTime = 5 * time.Minute
)

// Config holds the settings used to open a PostgreSQL database.
type Config struct {
	DSN                   string
	RequireSSL            bool
	MaxConnections        int
	MaxIdleConnections    int
	ConnectionLifetime    time.Duration
	ConnectionMaxIdleTime time.Duration
}

// Validate checks that the PostgreSQL configuration can be opened safely.
func (c Config) Validate() error {
	if c.DSN == "" {
		return errors.New("database DSN is required")
	}

	_, err := c.connectionConfig()
	if err != nil {
		return fmt.Errorf("invalid database DSN: %w", err)
	}

	if c.MaxConnections < 0 {
		return errors.New("maximum connections cannot be negative")
	}

	if c.MaxIdleConnections < 0 {
		return errors.New("maximum idle connections cannot be negative")
	}

	return nil
}

func (c Config) connectionConfig() (*pgx.ConnConfig, error) {
	config, err := pgx.ParseConfig(c.DSN)
	if err != nil {
		return nil, err
	}

	if !c.RequireSSL {
		return config, nil
	}

	if config.TLSConfig == nil {
		config.TLSConfig = requiredTLSConfig(config.Host)
	}

	for _, fallback := range config.Fallbacks {
		if fallback.TLSConfig == nil {
			fallback.TLSConfig = requiredTLSConfig(fallback.Host)
		}
	}

	return config, nil
}

func requiredTLSConfig(host string) *tls.Config {
	return &tls.Config{
		ServerName: host,
		// RequireSSL matches PostgreSQL's sslmode=require behavior, which
		// encrypts the connection without verifying the server identity.
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS12,
	}
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

	return DefaultMaxIdleConnections
}

func (c Config) connectionLifetime() time.Duration {
	if c.ConnectionLifetime > 0 {
		return c.ConnectionLifetime
	}

	return DefaultConnectionLifetime
}

func (c Config) connectionMaxIdleTime() time.Duration {
	if c.ConnectionMaxIdleTime > 0 {
		return c.ConnectionMaxIdleTime
	}

	return DefaultConnectionIdleTime
}
