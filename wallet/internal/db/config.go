package db

import (
	"errors"
	"time"
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
