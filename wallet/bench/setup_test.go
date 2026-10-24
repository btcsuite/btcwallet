package bench

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/pg"
	"github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	dockercontainer "github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// benchmarkPostgresImage fixes the server build across measurements and keeps
// its pg_dump/pg_restore tools matched to the database being measured.
const benchmarkPostgresImage = "postgres:18-alpine@sha256:" +
	"9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"

// newBenchmarkChain reuses the normal genesis-only mock fixture. Optional
// startup/retry calls vary with scheduling; no chain work belongs in the read.
func newBenchmarkChain(tb testing.TB) *bwmock.Chain {
	tb.Helper()

	params := &chaincfg.RegressionNetParams
	chain := &bwmock.Chain{}
	chain.On("BackEnd").Return("mock").Maybe()
	chain.On("WatchAddrsFromTip", mock.Anything, mock.Anything).
		Return(nil).Maybe()
	chain.On("NotifySpent", mock.Anything).Return(nil).Maybe()
	chain.On("IsCurrent").Return(false).Maybe()
	chain.On("GetBestBlock").Return(params.GenesisHash, int32(0), nil).
		Maybe()
	chain.On("GetBlockHash", int64(0)).Return(params.GenesisHash, nil).
		Maybe()
	chain.On("GetBlockHeader", params.GenesisHash).
		Return(&params.GenesisBlock.Header, nil).Maybe()
	tb.Cleanup(func() { chain.AssertExpectations(tb) })

	return chain
}

// setupSQLBenchmarkWallet restores private storage before starting and
// unlocking
// the measured Wallet. A missing snapshot uses the common node seed; first and
// subsequent runs share the same restore/reopen path outside measurement.
func setupSQLBenchmarkWallet(tb testing.TB, backend wallet.DBBackend,
	workload bwtest.ListUnspentWorkload) *wallet.Wallet {

	tb.Helper()

	fixtureDir := os.Getenv("BTCWALLET_BENCH_FIXTURE_DIR")
	if fixtureDir == "" {
		fixtureDir = tb.TempDir()
	}

	fixture := filepath.Join(
		fixtureDir, string(backend), workload.ID+".db",
	)
	config := wallet.ManagerConfig{
		Backend:     backend,
		DataSource:  filepath.Join(tb.TempDir(), "wallet.sqlite"),
		ChainParams: chaincfg.RegressionNetParams,
		ChainSource: newBenchmarkChain(tb),
	}

	var container *postgres.PostgresContainer

	if backend == wallet.DBBackendPostgres {
		// SQL readiness waits through the image's bootstrap
		// server. Register
		// termination immediately, including partial container
		// setup failure.
		readiness := wait.ForSQL("5432/tcp", "pgx",
			func(host string, port nat.Port) string {
				return fmt.Sprintf(
					"postgres://postgres:postgres@%s/postgres?sslmode=disable",
					net.JoinHostPort(host, port.Port()),
				)
			},
		)

		var err error

		container, err = postgres.Run(tb.Context(), benchmarkPostgresImage,
			postgres.WithDatabase("postgres"),
			postgres.WithUsername("postgres"),
			postgres.WithPassword("postgres"),
			testcontainers.WithWaitStrategyAndDeadline(
				2*time.Minute, readiness,
			),
			testcontainers.WithHostConfigModifier(
				func(config *dockercontainer.HostConfig) {
					config.NanoCPUs = 1_000_000_000
					config.Memory = 1 << 30
				},
			),
		)
		if container != nil {
			tb.Cleanup(func() {
				ctx, cancel := context.WithTimeout(
					context.WithoutCancel(tb.Context()), time.Minute,
				)
				defer cancel()

				require.NoError(tb, container.Terminate(
					ctx, testcontainers.StopTimeout(0),
				))
			})
		}

		require.NoError(tb, err)
		config.DataSource, err = container.ConnectionString(
			tb.Context(), "sslmode=disable",
		)
		require.NoError(tb, err)
	}

	// Missing data is built through normal APIs. Closing the seeding Store
	// before Manager.Stop releases every SQL connection before
	// snapshotting.
	_, err := os.Stat(filepath.Clean(fixture))
	if errors.Is(err, os.ErrNotExist) {
		preparationStarted := time.Now()
		manager, _ := startSQLBenchmarkManager(tb, config)
		func() {
			store, closeStore := openSQLBenchmarkStore(tb, config)
			defer func() { require.NoError(tb, closeStore()) }()

			seedSQLBenchmarkWallet(tb, manager, store, workload)
		}()
		require.NoError(tb, manager.Stop())
		saveSQLBenchmarkFixture(tb, config, container, fixture)
		tb.Logf("fixture preparation: %s", time.Since(preparationStarted))
	} else {
		require.NoError(tb, err)
	}

	// Even the first run restores a snapshot, avoiding seeding caches
	// in the
	// measured Wallet. Each PostgreSQL invocation owns its fresh container;
	// SQLite always opens a temporary copy, never the persisted original.
	// Measure only snapshot restoration here; runtime reopen and container
	// provisioning remain separate untimed work in the invocation receipt.
	restoreStarted := time.Now()

	restoreSQLBenchmarkFixture(tb, config, container, fixture)
	tb.Logf("fixture restoration: %s", time.Since(restoreStarted))
	_, wallets := startSQLBenchmarkManager(tb, config)

	w := wallets[0]
	require.NoError(tb, w.Unlock(tb.Context(), wallet.UnlockRequest{
		Passphrase: []byte("private"), Timeout: -1,
	}))

	return w
}

// startSQLBenchmarkManager registers shutdown before startup can fail. Stop
// joins workers before the earlier chain mock and container cleanup run.
func startSQLBenchmarkManager(tb testing.TB, config wallet.ManagerConfig) (
	*wallet.Manager, []*wallet.Wallet) {

	tb.Helper()

	manager, err := wallet.NewManager(tb.Context(), config)
	require.NoError(tb, err)
	tb.Cleanup(func() { require.NoError(tb, manager.Stop()) })
	wallets, err := manager.Start(tb.Context())
	require.NoError(tb, err)

	return manager, wallets
}

// openSQLBenchmarkStore gives the shared seeder normal database writes without
// adding a Wallet hook. Its caller closes this pool before stopping Manager.
func openSQLBenchmarkStore(tb testing.TB, config wallet.ManagerConfig) (
	db.Store, func() error) {

	tb.Helper()

	identity, err := db.NewDatabaseIdentity(&config.ChainParams, nil)
	require.NoError(tb, err)

	if config.Backend == wallet.DBBackendPostgres {
		store, err := pg.NewStore(tb.Context(), pg.Config{
			Dsn: config.DataSource, Identity: identity,
		})
		require.NoError(tb, err)

		return store, store.Close
	}

	store, err := sqlite.NewStore(tb.Context(), sqlite.Config{
		DBPath: config.DataSource, Identity: identity,
	})
	require.NoError(tb, err)

	return store, store.Close
}

// saveSQLBenchmarkFixture publishes complete snapshots for serial reuse. The
// caller closes all SQL pools first: SQLite's final close checkpoints WAL, and
// PostgreSQL's archive captures the database without active Wallet workers.
func saveSQLBenchmarkFixture(tb testing.TB, config wallet.ManagerConfig,
	container *postgres.PostgresContainer, fixture string) {

	tb.Helper()

	var source io.ReadCloser
	if config.Backend == wallet.DBBackendPostgres {
		// Dump inside the pinned server image so client/server
		// versions match.
		// A custom archive carries schema and data across
		// container lifetimes.
		code, output, err := container.Exec(tb.Context(), []string{
			"pg_dump", "-U", "postgres", "-d", "postgres", "-Fc",
			"--no-owner", "--no-acl", "-f", "/tmp/benchmark.dump",
		})
		require.NoError(tb, err)
		diagnostic, err := io.ReadAll(output)
		require.NoError(tb, err)
		require.Zero(tb, code, "pg_dump: %s", diagnostic)
		source, err = container.CopyFileFromContainer(
			tb.Context(), "/tmp/benchmark.dump",
		)
		require.NoError(tb, err)
	} else {
		file, err := os.Open(filepath.Clean(config.DataSource))
		require.NoError(tb, err)

		source = file
	}

	defer func() { require.NoError(tb, source.Close()) }()

	// Only a fully written, closed sibling becomes visible as a cache hit.
	// Cleanup removes interrupted writes without touching previous
	// fixtures.
	require.NoError(tb, os.MkdirAll(filepath.Dir(fixture), 0o700))

	pending := fixture + ".partial"
	defer func() { _ = os.Remove(pending) }()

	func() {
		file, err := os.OpenFile(filepath.Clean(pending),
			os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600,
		)

		require.NoError(tb, err)
		defer func() { require.NoError(tb, file.Close()) }()

		_, err = io.Copy(file, source)
		require.NoError(tb, err)
	}()
	require.NoError(tb, os.Rename(pending, fixture))
}

// restoreSQLBenchmarkFixture restores into storage owned by this invocation.
// No Manager or seeding Store may be open while these files or schemas change.
func restoreSQLBenchmarkFixture(tb testing.TB, config wallet.ManagerConfig,
	container *postgres.PostgresContainer, fixture string) {

	tb.Helper()

	if config.Backend == wallet.DBBackendPostgres {
		// Clean also handles the first run's seeded database. Both
		// misses and
		// hits therefore use the same archive restore before
		// runtime startup.
		require.NoError(tb, container.CopyFileToContainer(
			tb.Context(), fixture, "/tmp/benchmark.dump", 0o600,
		))
		code, output, err := container.Exec(tb.Context(), []string{
			"pg_restore", "-U", "postgres", "-d", "postgres",
			"--exit-on-error", "--clean", "--if-exists", "--no-owner",
			"--no-acl", "/tmp/benchmark.dump",
		})
		require.NoError(tb, err)
		diagnostic, err := io.ReadAll(output)
		require.NoError(tb, err)
		require.Zero(tb, code, "pg_restore: %s", diagnostic)

		// Archives omit planner statistics. Analyze this private
		// restore so
		// timed reads use data-aware plans without rebuilding the
		// saved data.
		code, output, err = container.Exec(tb.Context(), []string{
			"psql", "-X", "-U", "postgres", "-d", "postgres",
			"-v", "ON_ERROR_STOP=1", "-c", "ANALYZE",
		})
		require.NoError(tb, err)
		diagnostic, err = io.ReadAll(output)
		require.NoError(tb, err)
		require.Zero(tb, code, "ANALYZE: %s", diagnostic)

		return
	}

	// The original remains closed and immutable while SQLite owns this
	// copy.
	data, err := os.ReadFile(filepath.Clean(fixture))
	require.NoError(tb, err)
	require.NoError(tb, os.WriteFile(config.DataSource, data, 0o600))
}

// seedSQLBenchmarkWallet uses normal Manager account and key allocation,
// followed by
// Store history writes. The standalone seeding Store has no key deriver.
func seedSQLBenchmarkWallet(tb testing.TB, manager *wallet.Manager,
	store db.Store, workload bwtest.ListUnspentWorkload) {

	tb.Helper()

	phaseStarted := time.Now()
	w, err := manager.Create(wallet.CreateWalletParams{
		Name: "list-unspent-benchmark", Mode: wallet.ModeImportSeed,
		Seed: workload.Seed, Birthday: workload.Birthday,
		PrivatePassphrase: []byte("private"),
	})
	require.NoError(tb, err)
	require.NoError(tb, w.Unlock(tb.Context(), wallet.UnlockRequest{
		Passphrase: []byte("private"), Timeout: -1,
	}))

	// Match the four ordinary defaults and lnd's precreated internal key
	// accounts. Exact SQL account creation supports chain-excluded
	// families.
	for _, scope := range waddrmgr.DefaultKeyScopes {
		number := wallet.AccountNumber(0)
		_, err := w.NewAccount(tb.Context(), wallet.NewAccountParams{
			Scope: scope, Name: "default", AccountNumber: &number,
		})
		require.NoError(tb, err)
	}

	keyScope := waddrmgr.KeyScope{Purpose: 1017, Coin: 1}
	schema := waddrmgr.ScopeAddrMap[waddrmgr.KeyScopeBIP0084]

	families := workload.Accounts - uint32(len(waddrmgr.DefaultKeyScopes))
	for account := range families {
		number := wallet.AccountNumber(account)

		name := "default"
		if account != 0 {
			name = fmt.Sprintf("act:%d", account)
		}

		_, err := w.NewAccount(tb.Context(), wallet.NewAccountParams{
			Scope: keyScope, Name: name, AccountNumber: &number,
			AddrSchema: &schema, NoChainSync: true,
		})
		require.NoError(tb, err)
	}

	tb.Logf("fixture accounts: %s", time.Since(phaseStarted))
	phaseStarted = time.Now()

	// Ordinary bulk allocation registers chain-synced address batches. The
	// public key allocator owns derivation for internal NoChainSync
	// accounts;
	// neither path needs a duplicate benchmark-only cryptographic callback.
	var scripts [][]byte
	for _, batch := range workload.AddressBatches() {
		selector := wallet.NewAccountSelectorByNumber(
			batch.Scope, wallet.AccountNumber(batch.Account),
		)
		if batch.Scope == keyScope {
			for range batch.Count {
				_, err := w.AllocateNextKey(tb.Context(), selector, false)
				require.NoError(tb, err)
			}

			continue
		}

		for remaining := batch.Count; remaining > 0; {
			count := min(remaining, wallet.MaxBulkAddressCount)
			addresses, err := w.NewBulkAddresses(tb.Context(), selector,
				batch.Internal, count,
			)
			require.NoError(tb, err)

			for _, addr := range addresses {
				script, err := txscript.PayToAddrScript(addr.Addr)
				require.NoError(tb, err)

				scripts = append(scripts, script)
			}

			remaining -= count
		}
	}

	tb.Logf("fixture allocation: %s", time.Since(phaseStarted))
	phaseStarted = time.Now()

	// SQL can persist the complete normalized graph and final tip through
	// its existing batch transaction; no legacy sync-tip progression is
	// needed.
	require.NoError(tb, store.ApplyTxBatch(tb.Context(),
		workload.Batch(w.ID(), scripts),
	))
	tb.Logf("fixture history: %s", time.Since(phaseStarted))
}

// RunSQLBenchmark restores each shared case and prepares its API request before
// the common read measurement. Callers own only their selected native
// operation;
// SQL lifecycle and saved node data stay independent of the kvdb suite.
func RunSQLBenchmark(b *testing.B, backend wallet.DBBackend,
	prepare func(*testing.B, *wallet.Wallet,
		bwtest.ListUnspentWorkload) func() error) {

	b.Helper()

	for _, workload := range bwtest.ListUnspentCases() {
		b.Run(workload.ID, func(b *testing.B) {
			w := setupSQLBenchmarkWallet(b, backend, workload)
			read := prepare(b, w, workload)

			bwtest.BenchmarkRead(b, read)
		})
	}
}

// SQLBenchmarkTarget selects a retained cooperative return outside measurement.
// Canonical txid/index order makes all point reads choose the same transaction
// shape regardless of backend enumeration order. No fixture totals are checked.
func SQLBenchmarkTarget(tb testing.TB, w *wallet.Wallet) *wallet.Utxo {
	tb.Helper()

	utxos, err := w.ListUnspent(tb.Context(), wallet.UtxoQuery{
		MaxConfs: math.MaxInt32,
	})
	require.NoError(tb, err)

	var target *wallet.Utxo
	for _, utxo := range utxos {
		if utxo.Amount != bwtest.NodeBenchmarkPointValue {
			continue
		}

		if target == nil ||
			utxo.OutPoint.Hash.String() < target.OutPoint.Hash.String() ||
			(utxo.OutPoint.Hash == target.OutPoint.Hash &&
				utxo.OutPoint.Index < target.OutPoint.Index) {

			target = utxo
		}
	}

	if target == nil {
		tb.Fatal("prepare point read: no cooperative return")
	}

	return target
}
