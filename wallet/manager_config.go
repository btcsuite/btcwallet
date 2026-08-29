package wallet

import (
	"errors"
	"fmt"
	"math/big"
	"slices"
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

	// DBBackendPostgres selects the PostgreSQL store.
	DBBackendPostgres DBBackend = "postgres"
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
// fields apply to only certain backends, which is documented here rather than
// prevented by a second validation layer:
//
//	field                      kvdb    sqlite    postgres
//	DataSource, ChainParams    all backends
//	MaxConnections             SQL backends
//	NoFreelistSync, Timeout    kvdb only
type ManagerConfig struct {
	// Backend selects the database implementation. Required.
	Backend DBBackend

	// DataSource locates the database: a filesystem path for kvdb and
	// SQLite, and a DSN for PostgreSQL. Required.
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
	case DBBackendKVDB, DBBackendSQLite, DBBackendPostgres:

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
	if c.Backend != DBBackendKVDB && c.MaxConnections < 0 {
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

// cloneChainParams returns an ownership-isolated network snapshot. The copy
// includes every nested mutable value so later caller or Info mutations cannot
// change the network policy retained by a Manager or Wallet.
func cloneChainParams(params chaincfg.Params) (chaincfg.Params, error) {
	cloned := params
	cloned.DNSSeeds = slices.Clone(params.DNSSeeds)

	cloned.GenesisBlock = params.GenesisBlock.Copy()
	genesisHash := *params.GenesisHash
	cloned.GenesisHash = &genesisHash
	cloned.PowLimit = new(big.Int).Set(params.PowLimit)

	// RegressionNetParams has no BIP0034Hash, so preserve that legitimate
	// absence while isolating the hash used by networks that define one.
	if params.BIP0034Hash != nil {
		bip0034Hash := *params.BIP0034Hash
		cloned.BIP0034Hash = &bip0034Hash
	}

	cloned.Checkpoints = slices.Clone(params.Checkpoints)
	for i := range cloned.Checkpoints {
		checkpointHash := *params.Checkpoints[i].Hash
		cloned.Checkpoints[i].Hash = &checkpointHash
	}

	for i, deployment := range params.Deployments {
		deployment, err := cloneDeployment(deployment)
		if err != nil {
			return chaincfg.Params{}, fmt.Errorf(
				"clone deployment %d: %w", i, err,
			)
		}

		cloned.Deployments[i] = deployment
	}

	return cloned, nil
}

// cloneDeployment recreates supported time boundaries without retaining their
// mutable clock state. Unknown implementations fail closed because copying an
// interface value would silently share caller state.
func cloneDeployment(deployment chaincfg.ConsensusDeployment) (
	chaincfg.ConsensusDeployment, error) {

	cloned := deployment
	switch starter := deployment.DeploymentStarter.(type) {
	case *chaincfg.MedianTimeDeploymentStarter:
		cloned.DeploymentStarter = chaincfg.NewMedianTimeDeploymentStarter(
			starter.StartTime(),
		)

	default:
		return chaincfg.ConsensusDeployment{}, fmt.Errorf(
			"%w: unsupported deployment starter %T",
			ErrInvalidParam, starter)
	}

	switch ender := deployment.DeploymentEnder.(type) {
	case *chaincfg.MedianTimeDeploymentEnder:
		cloned.DeploymentEnder = chaincfg.NewMedianTimeDeploymentEnder(
			ender.EndTime(),
		)

	default:
		return chaincfg.ConsensusDeployment{}, fmt.Errorf(
			"%w: unsupported deployment ender %T",
			ErrInvalidParam, ender)
	}

	return cloned, nil
}
