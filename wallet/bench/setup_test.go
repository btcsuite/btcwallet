package bench

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/wallet/internal/bwtest"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// prepareSQLSyncBenchmarkWallet saves native metadata at the common real base.
// Publish the closed target first so a cache hit needs no graph replay.
func prepareSQLSyncBenchmarkWallet(tb testing.TB,
	scenario bwtest.SyncBenchmarkCase) (*sqlBenchmarkFixture, string, string) {

	tb.Helper()

	ctx, cancel := context.WithTimeout(tb.Context(), 20*time.Minute)
	defer cancel()

	workload := scenario.Workload
	base, target := bwtest.PrepareSyncBenchmarkBase(ctx, tb, scenario)
	native := newSQLBenchmarkFixture(tb)
	config := native.config
	config.SyncMethod = wallet.SyncMethodFullBlocks
	config.WalletSyncRetryInterval = 10 * time.Millisecond
	native.config = config
	fixture := filepath.Join(
		os.Getenv("BTCWALLET_BENCH_FIXTURE_DIR"),
		string(config.Backend), scenario.ID+".db",
	)

	_, err := os.Stat(fixture)
	if !errors.Is(err, os.ErrNotExist) {
		require.NoError(tb, err)
		return native, fixture, target
	}

	// Real preparation allocates the existing inventory while the only
	// available chain is the base, leaving history for measured discovery.
	started := time.Now()
	dir, node, rpc, stopNode := bwtest.RestoreSyncBenchmarkNode(ctx, tb, base)
	source, stopSource := bwtest.NewSyncBenchmarkClient(ctx, tb, node)
	config.ChainSource = source
	manager, err := wallet.NewManager(ctx, config)
	require.NoError(tb, err)
	tb.Cleanup(func() { require.NoError(tb, manager.Stop()) })

	_, err = manager.Start(ctx)
	require.NoError(tb, err)
	w, scripts := allocateSQLBenchmarkWallet(tb, manager, workload)

	var history []*wire.MsgTx

	_, err = os.Stat(target)

	prepareTarget := errors.Is(err, os.ErrNotExist)
	if prepareTarget {
		// Every startup case uses the one-deposit small-node Wallet.
		// Zero-history controls still publish a target after shutdown.
		if len(scenario.HistoryBlocks) != 0 {
			hash, err := rpc.GetBlockHash(1)
			require.NoError(tb, err)
			block, err := rpc.GetBlock(hash)
			require.NoError(tb, err)

			funding := []*wire.MsgTx{block.Transactions[0]}

			history, err = bwtest.BuildSyncBenchmarkHistory(
				ctx, workload, scripts, funding,
				func(ctx context.Context, tx *wire.MsgTx,
					index int, output *wire.TxOut,
					hashes *txscript.TxSigHashes) (wire.TxWitness, error) {

					return signSQLSyncBenchmarkInput(
						ctx, w, tx, index, output, hashes,
					)
				},
			)
			require.NoError(tb, err)
		}
	} else {
		require.NoError(tb, err)
	}

	// Observe the base through the public contract before draining every SQL
	// connection. The subsequent target mining cannot update this baseline.
	hash, height, err := source.GetBestBlock()
	require.NoError(tb, err)

	for {
		info, err := w.Info(ctx)
		require.NoError(tb, err)

		if info.Synced && info.SyncedTo.Height == height &&
			info.SyncedTo.Hash.IsEqual(hash) {

			break
		}

		require.NoError(tb, ctx.Err())
		runtime.Gosched()
	}

	require.NoError(tb, manager.Stop())
	stopSource()

	// Zero-history cases still require a newly mined target; the existing
	// stat result is the publication decision, independently of Wallet signing.
	if prepareTarget {
		bwtest.SaveSyncBenchmarkTarget(
			ctx, tb, dir, target, rpc, stopNode, scenario, history,
		)
	} else {
		stopNode()
	}

	saveSQLBenchmarkFixture(tb, native, fixture)
	tb.Logf("fixture preparation: %s; base=%d:%s",
		time.Since(started), height, hash)

	return native, fixture, target
}

// signSQLSyncBenchmarkInput adapts the public signer to the graph builder.
// Witness-v0 and taproot require different native sighash modes.
func signSQLSyncBenchmarkInput(ctx context.Context, w *wallet.Wallet,
	tx *wire.MsgTx, index int, output *wire.TxOut,
	hashes *txscript.TxSigHashes) (wire.TxWitness, error) {

	hashType := txscript.SigHashAll
	if txscript.IsPayToTaproot(output.PkScript) {
		hashType = txscript.SigHashDefault
	}

	unlock, err := w.ComputeUnlockingScript(ctx,
		&wallet.UnlockingScriptParams{
			Tx: tx, InputIndex: index, Output: output,
			SigHashes: hashes, HashType: hashType,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("sign startup wallet input: %w", err)
	}

	return unlock.Witness, nil
}

// setupSQLBenchmarkWallet restores private storage before Wallet startup and
// unlock. A missing snapshot uses the common node seed; every run follows the
// same restore/reopen path outside measurement.
func setupSQLBenchmarkWallet(tb testing.TB,
	workload bwtest.NodeBenchmarkWorkload) *wallet.Wallet {

	tb.Helper()

	fixtureDir := os.Getenv("BTCWALLET_BENCH_FIXTURE_DIR")
	if fixtureDir == "" {
		fixtureDir = tb.TempDir()
	}

	native := newSQLBenchmarkFixture(tb)
	config := native.config
	fixture := filepath.Join(
		fixtureDir, string(config.Backend), workload.ID+".db",
	)

	// Build missing data through normal APIs. Close the seeding Store and
	// stop Manager to release every SQL connection before snapshotting.
	_, err := os.Stat(filepath.Clean(fixture))
	if errors.Is(err, os.ErrNotExist) {
		preparationStarted := time.Now()
		manager, _ := startSQLBenchmarkManager(tb, config)
		func() {
			store, closeStore := native.openStore(tb)
			defer func() { require.NoError(tb, closeStore()) }()

			seedSQLBenchmarkWallet(tb, manager, store, workload)
		}()
		require.NoError(tb, manager.Stop())
		saveSQLBenchmarkFixture(tb, native, fixture)
		tb.Logf("fixture preparation: %s", time.Since(preparationStarted))
	} else {
		require.NoError(tb, err)
	}

	// Even the first run restores private storage to avoid seeding caches in
	// the measured Wallet. PostgreSQL uses its fresh container; SQLite opens
	// a temporary copy. Log restoration separately from untimed provisioning
	// and runtime startup so the receipt distinguishes their costs.
	restoreStarted := time.Now()

	native.restore(tb, fixture)
	tb.Logf("fixture restoration: %s", time.Since(restoreStarted))
	_, wallets := startSQLBenchmarkManager(tb, config)

	w := wallets[0]
	require.NoError(tb, w.Unlock(tb.Context(), wallet.UnlockRequest{
		Passphrase: []byte("private"),
		Timeout:    -1,
	}))

	return w
}

// startSQLBenchmarkManager registers shutdown before startup can fail. Stop
// joins workers before the earlier chain mock and container cleanup run.
func startSQLBenchmarkManager(tb testing.TB,
	config wallet.ManagerConfig) (*wallet.Manager, []*wallet.Wallet) {

	tb.Helper()

	manager, err := wallet.NewManager(tb.Context(), config)
	require.NoError(tb, err)
	tb.Cleanup(func() { require.NoError(tb, manager.Stop()) })
	wallets, err := manager.Start(tb.Context())
	require.NoError(tb, err)

	return manager, wallets
}

// saveSQLBenchmarkFixture publishes complete snapshots for serial reuse. The
// caller closes all SQL pools first: SQLite's final close checkpoints WAL, and
// PostgreSQL's archive captures the database without active Wallet workers.
func saveSQLBenchmarkFixture(tb testing.TB,
	native *sqlBenchmarkFixture, fixture string) {

	tb.Helper()

	source := native.snapshot(tb)

	defer func() { require.NoError(tb, source.Close()) }()

	// Publish only a fully written, closed sibling. Cleanup removes partial
	// writes without touching the previous fixture.
	require.NoError(tb, os.MkdirAll(filepath.Dir(fixture), 0o700))

	pending := fixture + ".partial"
	defer func() { _ = os.Remove(pending) }()

	func() {
		file, err := os.OpenFile(
			filepath.Clean(pending), os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
			0o600,
		)

		require.NoError(tb, err)
		defer func() { require.NoError(tb, file.Close()) }()

		_, err = io.Copy(file, source)
		require.NoError(tb, err)
	}()
	require.NoError(tb, os.Rename(pending, fixture))
}

// seedSQLBenchmarkWallet retains read fixture history application after
// allocation; startup preparation reuses allocation without synthetic writes.
func seedSQLBenchmarkWallet(tb testing.TB, manager *wallet.Manager,
	store db.Store, workload bwtest.NodeBenchmarkWorkload) {

	tb.Helper()

	w, scripts := allocateSQLBenchmarkWallet(tb, manager, workload)

	phaseStarted := time.Now()

	// SQL can persist the complete normalized graph and final tip through
	// its existing batch transaction; no legacy sync-tip progression is
	// needed.
	require.NoError(tb, store.ApplyTxBatch(
		tb.Context(), workload.Batch(w.ID(), scripts),
	))
	tb.Logf("fixture history: %s", time.Since(phaseStarted))

	// Validate committed data before a newly prepared snapshot can be saved.
	bwtest.AssertNodeBenchmarkWallet(tb, store, w.ID(), workload)
}

// allocateSQLBenchmarkWallet creates the shared accounts and key inventory
// through public APIs, leaving its caller to choose real-chain or read history.
func allocateSQLBenchmarkWallet(tb testing.TB, manager *wallet.Manager,
	workload bwtest.NodeBenchmarkWorkload) (*wallet.Wallet, [][]byte) {

	tb.Helper()

	phaseStarted := time.Now()
	params := wallet.CreateWalletParams{
		Name:              "list-unspent-benchmark",
		Mode:              wallet.ModeImportSeed,
		Seed:              workload.Seed,
		Birthday:          workload.Birthday,
		PrivatePassphrase: []byte("private"),
	}
	w, err := manager.Create(params)
	require.NoError(tb, err)
	require.NoError(tb, w.Unlock(tb.Context(), wallet.UnlockRequest{
		Passphrase: []byte("private"),
		Timeout:    -1,
	}))

	// Match ordinary defaults and lnd's precreated internal key accounts;
	// exact SQL account creation supports chain-excluded key families.
	for _, scope := range waddrmgr.DefaultKeyScopes {
		number := wallet.AccountNumber(0)
		params := wallet.NewAccountParams{
			Scope:         scope,
			Name:          "default",
			AccountNumber: &number,
		}
		_, err := w.NewAccount(tb.Context(), params)
		require.NoError(tb, err)
	}

	keyScope := bwtest.NodeBenchmarkChannelScope()
	schema := waddrmgr.ScopeAddrMap[waddrmgr.KeyScopeBIP0084]

	families := workload.NumAccounts - uint32(len(waddrmgr.DefaultKeyScopes))
	for account := range families {
		number := wallet.AccountNumber(account)

		name := "default"
		if account != 0 {
			name = fmt.Sprintf("act:%d", account)
		}

		params := wallet.NewAccountParams{
			Scope:         keyScope,
			Name:          name,
			AccountNumber: &number,
			AddrSchema:    &schema,
			NoChainSync:   true,
		}
		_, err := w.NewAccount(tb.Context(), params)
		require.NoError(tb, err)
	}

	tb.Logf("fixture accounts: %s", time.Since(phaseStarted))
	phaseStarted = time.Now()

	// Bulk allocation registers ordinary chain-synced address batches. The
	// public key allocator derives internal NoChainSync keys, so neither
	// path needs a benchmark-only cryptographic callback.
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

			// Channel keys fill internal families, not payment addresses.
			// Keep them out of Batch's receiving/change/closing script order.
			continue
		}

		for remaining := batch.Count; remaining > 0; {
			count := min(remaining, wallet.MaxBulkAddressCount)
			addresses, err := w.NewBulkAddresses(
				tb.Context(), selector, batch.Internal, count,
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

	return w, scripts
}

// RunSQLBenchmark restores each shared case using the build-selected backend:
// SQLite by default, or PostgreSQL with test_db_postgres. Callers prepare the
// request outside measurement and return only the native read operation.
// SQL lifecycle and saved node data stay independent of the kvdb suite.
func RunSQLBenchmark(b *testing.B,
	prepare func(*testing.B, *wallet.Wallet,
		bwtest.NodeBenchmarkWorkload) func() error) {

	b.Helper()

	for _, workload := range bwtest.NodeBenchmarkCases() {
		b.Run(workload.ID, func(b *testing.B) {
			w := setupSQLBenchmarkWallet(b, workload)
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

	// Native fields feed the shared rule without adapting the Wallet result.
	target, found := bwtest.SelectNodeBenchmarkTarget(
		utxos, func(utxo *wallet.Utxo) (btcutil.Amount, string, uint32) {
			return utxo.Amount, utxo.OutPoint.Hash.String(),
				utxo.OutPoint.Index
		},
	)
	if !found {
		tb.Fatal("prepare point read: no cooperative return")
	}

	return target
}
