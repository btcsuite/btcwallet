package wallet

import (
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
)

const (
	// defaultKVDBTimeout is the walletdb open/create timeout used when the
	// configuration leaves it unset.
	defaultKVDBTimeout = 60 * time.Second
)

// DBBackend identifies the wallet database backend a Manager owns.
type DBBackend string

const (
	// DBBackendKVDB selects the legacy walletdb backend.
	//
	// Deprecated: remove this backend after kvdb wallet migration and
	// support are removed.
	DBBackendKVDB DBBackend = "kvdb"

	// DBBackendSQLite selects the SQLite store.
	DBBackendSQLite DBBackend = "sqlite"
)

// errUnsupportedBackend reports a Backend this build does not serve.
var errUnsupportedBackend = errors.New("unsupported database backend")

// ManagerConfig configures a Manager and the one database it owns.
//
// Every wallet a Manager owns shares that database and that network, which is
// why the backend selection and the chain parameters live here rather than on
// the per-wallet Config. Create and Load take no database or network selection.
//
// The struct is flat on purpose: there are no per-backend sub-structs to
// populate at once, so it cannot describe a backend it is not set to. Some
// fields apply to only one backend, which is documented here rather than
// prevented by a second validation layer:
//
//	field                      kvdb    sqlite
//	DataSource, ChainParams    both backends
//	MaxConnections             sqlite only
//	NoFreelistSync, Timeout    kvdb only
type ManagerConfig struct {
	// Backend selects the database implementation. Required.
	Backend DBBackend

	// DataSource locates the database: a filesystem path for kvdb and
	// SQLite, and a DSN once a networked backend is added. Required.
	DataSource string

	// MaxConnections bounds the SQL connection pool. Zero uses the store
	// default.
	MaxConnections int

	// ChainParams identifies the network every wallet in this Manager runs
	// on. Required; the Manager copies it into each wallet's config.
	ChainParams *chaincfg.Params

	// NoFreelistSync controls bbolt freelist synchronization.
	//
	// Deprecated: this field is used only by the legacy kvdb backend and
	// will be removed with kvdb support.
	NoFreelistSync bool

	// Timeout is the walletdb open/create timeout. Zero uses the default.
	//
	// Deprecated: this field is used only by the legacy kvdb backend and
	// will be removed with kvdb support.
	Timeout time.Duration
}

// validate checks a ManagerConfig once, at construction. There is no
// defaulting: an unset backend or data source is an error rather than a guess,
// so a wallet is never opened somewhere the caller did not name.
func (c ManagerConfig) validate() error {
	switch c.Backend {
	case DBBackendKVDB, DBBackendSQLite:

	case "":
		return fmt.Errorf("%w: Backend", ErrMissingParam)

	default:
		return fmt.Errorf("%w: %q", errUnsupportedBackend, c.Backend)
	}

	if c.DataSource == "" {
		return fmt.Errorf("%w: DataSource", ErrMissingParam)
	}

	if c.ChainParams == nil {
		return fmt.Errorf("%w: ChainParams", ErrMissingParam)
	}

	// MaxConnections is a SQL pool bound; kvdb ignores it, so only the SQL
	// backends validate it.
	if c.Backend == DBBackendSQLite && c.MaxConnections < 0 {
		return fmt.Errorf("%w: MaxConnections must not be negative",
			ErrInvalidParam)
	}

	return nil
}

// timeout returns the configured walletdb timeout or the default.
func (c ManagerConfig) timeout() time.Duration {
	if c.Timeout == 0 {
		return defaultKVDBTimeout
	}

	return c.Timeout
}
