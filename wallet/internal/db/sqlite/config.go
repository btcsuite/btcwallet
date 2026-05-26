package sqlite

import "github.com/btcsuite/btcwallet/wallet/internal/db"

// Config holds the configuration for the SQLite database.
type Config struct {
	// DBPath is the filesystem path to the SQLite database file.
	DBPath string

	// MaxConnections is the maximum number of open connections to the
	// database. Set to zero to use db.DefaultMaxConnections.
	MaxConnections int

	// DeriveAddress derives address data for NewDerivedAddress after the
	// store allocates an account branch/index. It may be nil when the store
	// is used only for operations that do not create derived addresses.
	DeriveAddress db.AddressDerivationFunc
}

// Validate checks that the Config values are valid.
func (c *Config) Validate() error {
	if c.DBPath == "" {
		return db.ErrEmptyDBPath
	}

	if c.MaxConnections < 0 {
		return db.ErrNegativeMaxConns
	}

	return nil
}
