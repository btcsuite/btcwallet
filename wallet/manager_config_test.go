package wallet

import (
	"math/big"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/stretchr/testify/require"
)

// testSQLiteDBName is the SQLite data source the config tests share.
const testSQLiteDBName = "wallet.sqlite"

// validRuntimeManagerConfig builds a complete SQLite configuration. Validation
// tests mutate one field at a time so failures cannot be masked by an unrelated
// missing input.
func validRuntimeManagerConfig() ManagerConfig {
	cfg := ManagerConfig{
		Backend:     DBBackendSQLite,
		DataSource:  testSQLiteDBName,
		ChainParams: chaincfg.SimNetParams,
		ChainSource: &bwmock.Chain{},
	}

	return cfg
}

// TestManagerConfigValidate verifies database and runtime policy are checked
// together before Manager construction can open caller-selected storage.
func TestManagerConfigValidate(t *testing.T) {
	t.Parallel()

	// Arrange: Derive runtime cases from complete backend configurations and
	// mutate one field at a time, alongside the existing database boundaries,
	// so no unrelated missing input can mask the decision under test.
	unknownSync := validRuntimeManagerConfig()
	unknownSync.SyncMethod = SyncMethodFullBlocks + 1
	negativeRetry := validRuntimeManagerConfig()
	negativeRetry.WalletSyncRetryInterval = -time.Second
	maximumRetry := validRuntimeManagerConfig()
	maximumRetry.WalletSyncRetryInterval = maxBackoff
	aboveMaximumRetry := validRuntimeManagerConfig()
	aboveMaximumRetry.WalletSyncRetryInterval = maxBackoff + 1
	aboveMaximumRecovery := validRuntimeManagerConfig()
	aboveMaximumRecovery.RecoveryWindow = MaxRecoveryWindow + 1
	tests := []struct {
		name    string
		cfg     ManagerConfig
		wantIs  error
		wantMsg string
	}{
		{
			name: "kvdb",
			cfg: ManagerConfig{
				Backend:     DBBackendKVDB,
				DataSource:  WalletDBName,
				ChainParams: chaincfg.SimNetParams,
				ChainSource: &bwmock.Chain{},
			},
		},
		{
			name: "sqlite",
			cfg: ManagerConfig{
				Backend:     DBBackendSQLite,
				DataSource:  testSQLiteDBName,
				ChainParams: chaincfg.SimNetParams,
				ChainSource: &bwmock.Chain{},
			},
		},
		{
			name: "postgres",
			cfg: ManagerConfig{
				Backend:     DBBackendPostgres,
				DataSource:  "postgres://user:pass@localhost/wallet",
				ChainParams: chaincfg.SimNetParams,
				ChainSource: &bwmock.Chain{},
			},
		},
		{
			// kvdb reads these; sqlite ignores them. Neither is an
			// error, which is what makes the flat shape workable.
			name: "kvdb knobs on sqlite are ignored",
			cfg: ManagerConfig{
				Backend:        DBBackendSQLite,
				DataSource:     testSQLiteDBName,
				ChainParams:    chaincfg.SimNetParams,
				ChainSource:    &bwmock.Chain{},
				NoFreelistSync: true,
				Timeout:        time.Second,
			},
		},
		{
			name:    "no backend",
			cfg:     ManagerConfig{DataSource: WalletDBName},
			wantIs:  ErrMissingParam,
			wantMsg: "Backend",
		},
		{
			name: "unknown backend",
			cfg: ManagerConfig{
				Backend:     DBBackend("mysql"),
				DataSource:  WalletDBName,
				ChainParams: chaincfg.SimNetParams,
			},
			wantIs:  errUnsupportedBackend,
			wantMsg: "mysql",
		},
		{
			name: "no data source",
			cfg: ManagerConfig{
				Backend:     DBBackendKVDB,
				ChainParams: chaincfg.SimNetParams,
			},
			wantIs:  ErrMissingParam,
			wantMsg: "DataSource",
		},
		{
			name: "no chain params",
			cfg: ManagerConfig{
				Backend:    DBBackendKVDB,
				DataSource: WalletDBName,
			},
			wantIs:  ErrMissingParam,
			wantMsg: "ChainParams",
		},
		{
			name: "negative max connections",
			cfg: ManagerConfig{
				Backend:        DBBackendSQLite,
				DataSource:     testSQLiteDBName,
				ChainParams:    chaincfg.SimNetParams,
				ChainSource:    &bwmock.Chain{},
				MaxConnections: -1,
			},
			wantIs:  ErrInvalidParam,
			wantMsg: "MaxConnections",
		},
		{
			name: "postgres negative max connections",
			cfg: ManagerConfig{
				Backend:        DBBackendPostgres,
				DataSource:     "postgres://localhost/wallet",
				ChainParams:    chaincfg.SimNetParams,
				ChainSource:    &bwmock.Chain{},
				MaxConnections: -1,
			},
			wantIs:  ErrInvalidParam,
			wantMsg: "MaxConnections",
		},
		{
			name:    "unknown sync method",
			cfg:     unknownSync,
			wantIs:  ErrInvalidParam,
			wantMsg: "SyncMethod",
		},
		{
			name:    "negative retry interval",
			cfg:     negativeRetry,
			wantIs:  ErrInvalidParam,
			wantMsg: "WalletSyncRetryInterval",
		},
		{
			name: "maximum retry interval",
			cfg:  maximumRetry,
		},
		{
			name:    "retry interval above maximum",
			cfg:     aboveMaximumRetry,
			wantIs:  ErrInvalidParam,
			wantMsg: "WalletSyncRetryInterval",
		},
		{
			name:    "recovery window above maximum",
			cfg:     aboveMaximumRecovery,
			wantIs:  ErrInvalidParam,
			wantMsg: "RecoveryWindow",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Act: Validate only the case's immutable constructor input,
			// without opening the configured data source.
			err := test.cfg.validate()

			// Assert: Successful cases remain accepted, while failures
			// preserve both their sentinel and caller-facing field context.
			if test.wantIs == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, test.wantIs)
			require.ErrorContains(t, err, test.wantMsg)
		})
	}
}

// TestManagerRetainsRuntimeSnapshot verifies NewManager copies and normalizes
// caller policy before that snapshot is assembled into a managed Wallet.
func TestManagerRetainsRuntimeSnapshot(t *testing.T) {
	t.Parallel()

	// Arrange: Give a kvdb Manager mutable network inputs plus distinctive
	// scalar policy. Prepare independent data sources for negative and zero
	// auto-lock durations so both default predicates are exercised through the
	// public constructor before any Wallet receives the policy.
	params, err := cloneChainParams(chainParams)
	require.NoError(t, err)

	chainSource := &bwmock.Chain{}
	cfg := ManagerConfig{
		Backend:          DBBackendKVDB,
		DataSource:       testKVDBPath(t),
		ChainParams:      params,
		ChainSource:      chainSource,
		SyncMethod:       SyncMethodFullBlocks,
		RecoveryWindow:   12,
		AutoLockDuration: -time.Second,
		MaxCFilterItems:  50,
	}

	// Act: Construct Managers with both non-positive auto-lock duration forms.
	// Mutate the caller-owned input, then create a Wallet so assembly must
	// consume only the retained immutable snapshot.
	m, err := NewManager(t.Context(), cfg)
	require.NoError(t, err)

	zeroCfg := cfg
	zeroCfg.DataSource = testKVDBPath(t)
	zeroCfg.AutoLockDuration = 0
	zeroManager, err := NewManager(t.Context(), zeroCfg)
	require.NoError(t, err)

	params.Name = "mutated"
	params.PowLimit.SetInt64(1)

	w, err := m.Create(CreateWalletParams{
		Name:          testWalletName,
		Mode:          ModeShell,
		WatchOnly:     true,
		PubPassphrase: []byte("public"),
	})
	require.NoError(t, err)

	// Assert: Verify constructor copying and both normalization paths first,
	// then require the assembled Wallet to carry that exact policy and
	// independent mutable values before releasing each Manager-owned backend.
	require.NotEqual(t, params.Name, m.config.ChainParams.Name)
	require.NotEqual(t, params.PowLimit, m.config.ChainParams.PowLimit)
	require.Equal(t, SyncMethodFullBlocks, m.config.SyncMethod)
	require.Equal(t, initialBackoff, m.config.WalletSyncRetryInterval)
	require.Equal(t, uint32(12), m.config.RecoveryWindow)
	require.Equal(t, defaultLockDuration, m.config.AutoLockDuration)
	require.Equal(t, defaultLockDuration,
		zeroManager.config.AutoLockDuration)
	require.Equal(t, uint32(50), m.config.MaxCFilterItems)

	require.Same(t, chainSource, w.cfg.Chain)
	require.Equal(t, m.config.ChainParams, *w.cfg.ChainParams)
	require.Equal(t, m.config.SyncMethod, w.cfg.SyncMethod)
	require.Equal(t, m.config.WalletSyncRetryInterval,
		w.cfg.WalletSyncRetryInterval)
	require.Equal(t, m.config.RecoveryWindow, w.cfg.RecoveryWindow)
	require.Equal(t, m.config.AutoLockDuration, w.cfg.AutoLockDuration)
	require.Equal(t, m.config.MaxCFilterItems, w.cfg.MaxCFilterItems)
	require.NoError(t, m.Close())
	require.NoError(t, zeroManager.Close())
}

// TestNewManagerRejectsInvalidSQLIdentity proves identity precedes SQL setup.
func TestNewManagerRejectsInvalidSQLIdentity(t *testing.T) {
	t.Parallel()

	// Arrange: A missing signet digest and unusable data source expose ordering
	// after every unrelated Manager runtime input passes validation.
	for _, backend := range []DBBackend{DBBackendSQLite, DBBackendPostgres} {
		cfg := ManagerConfig{
			Backend:     backend,
			DataSource:  "\x00/db",
			ChainParams: chaincfg.SigNetParams,
			ChainSource: &bwmock.Chain{},
		}

		// Act: Construct the Manager through the selected SQL backend.
		manager, err := NewManager(t.Context(), cfg)

		// Assert: Invalid identity wins before the unusable source is read.
		require.ErrorIs(t, err, ErrInvalidDatabaseIdentity, backend)
		require.Nil(t, manager, backend)
	}
}

// TestManagerConfigTimeout verifies that an unset walletdb timeout falls
// back to the default instead of zero, which walletdb treats as no wait.
func TestManagerConfigTimeout(t *testing.T) {
	t.Parallel()

	require.Equal(t, defaultKVDBTimeout, ManagerConfig{}.timeout())
	require.Equal(
		t, time.Second, ManagerConfig{Timeout: time.Second}.timeout(),
	)
}

// testDeploymentStarter supplies an intentionally unsupported deployment
// boundary so the clone test can prove unknown mutable implementations fail
// closed instead of being retained through an interface value.
type testDeploymentStarter struct{}

// HasStarted implements the deployment boundary; its result is irrelevant
// because cloneChainParams must reject this type without invoking it.
func (*testDeploymentStarter) HasStarted(*wire.BlockHeader) (bool, error) {
	return false, nil
}

// TestChainParamsCloneIsolated verifies every nested mutable network value is
// owned by the clone, including consensus deployment boundary instances.
func TestChainParamsCloneIsolated(t *testing.T) {
	t.Parallel()

	// Arrange: Build a compact parameter set with every mutable field backed
	// by test-owned storage, then snapshot the original values for comparison.
	genesisBlock := chaincfg.MainNetParams.GenesisBlock.Copy()
	genesisHash := chainhash.Hash{1}
	bip0034Hash := chainhash.Hash{2}
	checkpointHash := chainhash.Hash{3}
	startTime := time.Unix(10, 0)
	endTime := time.Unix(20, 0)
	params := chaincfg.MainNetParams
	params.DNSSeeds = []chaincfg.DNSSeed{{Host: "seed.example"}}
	params.GenesisBlock = genesisBlock
	params.GenesisHash = &genesisHash
	params.PowLimit = big.NewInt(100)
	params.BIP0034Hash = &bip0034Hash
	params.Checkpoints = []chaincfg.Checkpoint{{Hash: &checkpointHash}}
	params.Deployments[0] = chaincfg.ConsensusDeployment{
		DeploymentStarter: chaincfg.NewMedianTimeDeploymentStarter(
			startTime,
		),
		DeploymentEnder: chaincfg.NewMedianTimeDeploymentEnder(
			endTime,
		),
	}
	originalNonce := genesisBlock.Header.Nonce
	originalScriptByte := genesisBlock.Transactions[0].TxOut[0].PkScript[0]

	// Act: Clone the parameters, then mutate every caller-owned nested value
	// that could otherwise alter the retained network definition.
	cloned, err := cloneChainParams(params)
	require.NoError(t, err)

	params.DNSSeeds[0].Host = "mutated.example"
	params.GenesisBlock.Header.Nonce++
	params.GenesisBlock.Transactions[0].TxOut[0].PkScript[0]++
	params.GenesisHash[0]++
	params.PowLimit.SetInt64(200)
	params.BIP0034Hash[0]++
	params.Checkpoints[0].Hash[0]++

	// Assert: Verify scalar content survived every mutation and deployment
	// boundaries were recreated rather than sharing mutable clock instances.
	require.Equal(t, "seed.example", cloned.DNSSeeds[0].Host)
	require.Equal(t, originalNonce, cloned.GenesisBlock.Header.Nonce)
	require.Equal(
		t, originalScriptByte,
		cloned.GenesisBlock.Transactions[0].TxOut[0].PkScript[0],
	)
	require.Equal(t, byte(1), cloned.GenesisHash[0])
	require.Equal(t, int64(100), cloned.PowLimit.Int64())
	require.Equal(t, byte(2), cloned.BIP0034Hash[0])
	require.Equal(t, byte(3), cloned.Checkpoints[0].Hash[0])
	require.NotSame(
		t, params.Deployments[0].DeploymentStarter,
		cloned.Deployments[0].DeploymentStarter,
	)
	require.NotSame(
		t, params.Deployments[0].DeploymentEnder,
		cloned.Deployments[0].DeploymentEnder,
	)
}

// TestChainParamsCloneRejectsUnknownDeployment verifies a clone never falls
// back to retaining an implementation whose mutable state it cannot copy.
func TestChainParamsCloneRejectsUnknownDeployment(t *testing.T) {
	t.Parallel()

	// Arrange: Install an otherwise valid deployment with an implementation
	// outside the two chaincfg time-boundary types the clone understands.
	params := chaincfg.SimNetParams
	params.Deployments[0].DeploymentStarter = &testDeploymentStarter{}

	// Act: Attempt to cross the ownership boundary with the unknown type.
	_, err := cloneChainParams(params)

	// Assert: Require the invalid-parameter sentinel and type context so the
	// caller can correct the configuration without any state being retained.
	require.ErrorIs(t, err, ErrInvalidParam)
	require.ErrorContains(t, err, "testDeploymentStarter")
}
