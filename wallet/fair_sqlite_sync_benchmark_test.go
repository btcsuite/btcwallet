package wallet

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	dbsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	storesqlite "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite"
	"github.com/stretchr/testify/require"
	modernsqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const (
	fairWalletName        = "fair-sqlite-sync"
	fairPublicPass        = "public-pass"
	fairPrivatePass       = "private-pass"
	fairRecoveryWindow    = uint32(100)
	fairSQLiteConnections = 1
	fairBaseMatureOutputs = uint32(10)
	fairSparsePayments    = 10
	fairPaymentAmount     = int64(100_000)
	fairPollInterval      = 5 * time.Millisecond
	fairSyncTimeout       = 10 * time.Minute
	fairSQLiteFileMarker  = "fair-sync-"
)

var fairSeed = [32]byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

var fairSQLiteHookOnce sync.Once

// fairExpectedState describes the wallet semantics a workload must produce.
type fairExpectedState struct {
	Transactions int   `json:"transactions"`
	UTXOs        int   `json:"utxos"`
	Balance      int64 `json:"balance"`
}

// fairWorkloadOutput describes one deterministic wallet payment in the chain.
type fairWorkloadOutput struct {
	BlockOffset int    `json:"block_offset"`
	PkScript    string `json:"pk_script"`
	Amount      int64  `json:"amount"`
}

// fairWorkloadShape commits to chain shape without committing to block hashes.
type fairWorkloadShape struct {
	Blocks         int                  `json:"blocks"`
	PaymentOutputs []fairWorkloadOutput `json:"payment_outputs"`
	ExpectedWallet fairExpectedState    `json:"expected_wallet"`
}

// fairUTXOIdentity is the stable outpoint and amount identity of one UTXO.
type fairUTXOIdentity struct {
	OutPoint string `json:"outpoint"`
	Amount   int64  `json:"amount"`
}

// fairSyncSemantic is the complete public wallet state committed by one sync.
type fairSyncSemantic struct {
	TargetHeight   int32              `json:"target_height"`
	TargetHash     string             `json:"target_hash"`
	TransactionIDs []string           `json:"transaction_ids"`
	UTXOs          []fairUTXOIdentity `json:"utxos"`
	Balance        int64              `json:"balance"`
	WorkloadDigest string             `json:"workload_digest"`
}

// fairHashIndependentSemantic omits all chain-derived hash identities.
type fairHashIndependentSemantic struct {
	TargetHeight   int32   `json:"target_height"`
	Transactions   int     `json:"transactions"`
	UTXOAmounts    []int64 `json:"utxo_amounts"`
	Balance        int64   `json:"balance"`
	WorkloadDigest string  `json:"workload_digest"`
}

// fairDigestPair contains hash-specific and hash-independent state digests.
type fairDigestPair struct {
	semantic        [sha256.Size]byte
	hashIndependent [sha256.Size]byte
}

// fairSQLitePragmas records the effective settings of an independent open.
type fairSQLitePragmas struct {
	journalMode    string
	foreignKeys    int
	busyTimeout    int
	synchronous    int
	fullFSync      int
	autoVacuum     int
	txLock         string
	maxConnections int
}

// fairSyncFixture owns one btcd node and one closed base database snapshot.
type fairSyncFixture struct {
	miner        *rpctest.Harness
	snapshotPath string
	base         waddrmgr.BlockStamp
	target       waddrmgr.BlockStamp
	expected     fairExpectedState
	workload     [sha256.Size]byte
	pragmas      fairSQLitePragmas
}

// fairWalletHandle owns one opened wallet, SQLite pool, and chain client.
type fairWalletHandle struct {
	wallet *Wallet
	conn   *sql.DB
	client *chain.RPCClient
}

// fairMemoryDelta accumulates process allocation counters over timed regions.
type fairMemoryDelta struct {
	mallocs    uint64
	totalAlloc uint64
}

// BenchmarkFairSQLiteSync measures equivalent SQLite lifecycle and full-block
// synchronization boundaries against a real btcd regtest node.
func BenchmarkFairSQLiteSync(b *testing.B) {
	fairUseFastScrypt(b)
	fairConfigureSQLiteConnections()
	b.Log("busy/retry counters are not reported because internal retry " +
		"counts are not comparably exposed; every returned error fails " +
		"the sample")

	b.Run("OpenOnly", benchmarkFairOpenOnly)
	b.Run("ActivationOneBlock", benchmarkFairActivationOneBlock)

	b.Run("Backlog", func(b *testing.B) {
		b.Run("Empty", func(b *testing.B) {
			for _, blocks := range []int{100, 1000, 10000} {
				b.Run(fmt.Sprintf("Blocks-%d", blocks),
					func(b *testing.B) {

						benchmarkFairBacklog(
							b, blocks, false, false,
						)
					})
			}
		})

		b.Run("Sparse10", func(b *testing.B) {
			b.Run("Blocks-1000", func(b *testing.B) {
				benchmarkFairBacklog(b, 1000, true, false)
			})
		})
	})

	b.Run("ColdOpenBacklog", func(b *testing.B) {
		b.Run("Empty", func(b *testing.B) {
			for _, blocks := range []int{100, 1000, 10000} {
				b.Run(fmt.Sprintf("Blocks-%d", blocks),
					func(b *testing.B) {

						benchmarkFairBacklog(
							b, blocks, false, true,
						)
					})
			}
		})
	})
}

// fairConfigureSQLiteConnections pins connection-local settings that the role
// configuration cannot expose without changing production code.
func fairConfigureSQLiteConnections() {
	fairSQLiteHookOnce.Do(func() {
		modernsqlite.RegisterConnectionHook(func(
			conn modernsqlite.ExecQuerierContext, dsn string) error {

			if !strings.Contains(dsn, fairSQLiteFileMarker) {
				return nil
			}

			_, err := conn.ExecContext(
				context.Background(), "PRAGMA synchronous=normal; "+
					"PRAGMA fullfsync=false; "+
					"PRAGMA auto_vacuum=none", nil,
			)

			return err
		})
	})
}

// fairUseFastScrypt pins identical low-cost KDF settings for benchmark wallets.
func fairUseFastScrypt(b *testing.B) {
	b.Helper()
	defaultOptions := waddrmgr.DefaultScryptOptions
	waddrmgr.DefaultScryptOptions = waddrmgr.FastScryptOptions
	b.Cleanup(func() {
		waddrmgr.DefaultScryptOptions = defaultOptions
	})
}

// benchmarkFairOpenOnly measures only loading a closed, already-synced SQLite
// snapshot into an unstarted wallet object.
func benchmarkFairOpenOnly(b *testing.B) {
	b.StopTimer()
	b.Log("scope=route-specific lifecycle latency; not cross-route " +
		"throughput")
	fixture := newFairSyncFixture(b, 0, false)
	baseSize := fairFileSize(b, fixture.snapshotPath)

	var (
		digest      fairDigestPair
		digestSet   bool
		totalGrowth int64
	)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dbPath := fairIterationPath(b, i)
		fairCopySnapshot(b, fixture.snapshotPath, dbPath)
		client := fairNewChainClient(b, fixture.miner)

		b.StartTimer()
		handle, err := fairOpenWallet(dbPath, client)
		b.StopTimer()
		if err != nil {
			fairStopChainClient(client)
		}
		require.NoError(b, err)

		fairRequireUnsynced(b, handle.wallet)
		require.NoError(b, fairActivateWallet(b.Context(), handle))
		require.NoError(b, fairWaitForMemorySync(handle.wallet))
		fairRequireTip(b, handle.wallet, fixture.target)
		gotDigest := fairValidateState(
			b, handle.wallet, fixture.target, fixture.expected,
			fixture.workload,
		)
		fairAccumulateDigests(b, &digest, &digestSet, gotDigest)

		require.NoError(b, fairCloseWallet(handle))
		gotPragmas := fairVerifySQLitePragmas(b, dbPath)
		require.Equal(b, fixture.pragmas, gotPragmas)
		totalGrowth += fairFileSize(b, dbPath) - baseSize
		fairRequireClosedSQLite(b, dbPath)
	}

	b.ReportMetric(
		float64(totalGrowth)/float64(b.N), "db-growth-bytes",
	)
	fairLogDigests(
		b, digest, fixture.target, fixture.expected, fixture.workload,
	)
	fairLogSQLitePragmas(b, fixture.pragmas)
}

// benchmarkFairActivationOneBlock measures activation through a guaranteed
// unsynced-to-synced in-memory transition over one block.
func benchmarkFairActivationOneBlock(b *testing.B) {
	b.StopTimer()
	b.Log("scope=route-specific activation latency; not cross-route " +
		"throughput")
	fixture := newFairSyncFixture(b, 1, false)
	baseSize := fairFileSize(b, fixture.snapshotPath)

	var (
		digest      fairDigestPair
		digestSet   bool
		totalGrowth int64
	)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dbPath := fairIterationPath(b, i)
		fairCopySnapshot(b, fixture.snapshotPath, dbPath)
		client := fairNewChainClient(b, fixture.miner)
		handle, err := fairOpenWallet(dbPath, client)
		require.NoError(b, err)
		fairRequireTip(b, handle.wallet, fixture.base)
		fairRequireUnsynced(b, handle.wallet)

		b.StartTimer()
		err = fairActivateWallet(b.Context(), handle)
		if err == nil {
			err = fairWaitForMemorySync(handle.wallet)
		}
		b.StopTimer()
		require.NoError(b, err)

		fairRequireTip(b, handle.wallet, fixture.target)
		gotDigest := fairValidateState(
			b, handle.wallet, fixture.target, fixture.expected,
			fixture.workload,
		)
		fairAccumulateDigests(b, &digest, &digestSet, gotDigest)

		require.NoError(b, fairCloseWallet(handle))
		gotPragmas := fairVerifySQLitePragmas(b, dbPath)
		require.Equal(b, fixture.pragmas, gotPragmas)
		totalGrowth += fairFileSize(b, dbPath) - baseSize
		fairRequireClosedSQLite(b, dbPath)
	}

	b.ReportMetric(
		float64(totalGrowth)/float64(b.N), "db-growth-bytes",
	)
	fairLogDigests(
		b, digest, fixture.target, fixture.expected, fixture.workload,
	)
	fairLogSQLitePragmas(b, fixture.pragmas)
}

// benchmarkFairBacklog measures activation and exact-tip catch-up from one
// closed base snapshot. Cold samples include the database open in the timer.
func benchmarkFairBacklog(b *testing.B, blocks int, sparse, cold bool) {
	b.StopTimer()
	if cold {
		b.Log("scope=route-specific open+activation+sync lifecycle " +
			"latency; not cross-route throughput")
	} else {
		b.Log("scope=strict cross-route sync-throughput comparison")
	}
	fixture := newFairSyncFixture(b, blocks, sparse)
	baseSize := fairFileSize(b, fixture.snapshotPath)

	var (
		digest       fairDigestPair
		digestSet    bool
		totalElapsed time.Duration
		totalGrowth  int64
		memory       fairMemoryDelta
	)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dbPath := fairIterationPath(b, i)
		fairCopySnapshot(b, fixture.snapshotPath, dbPath)
		client := fairNewChainClient(b, fixture.miner)

		var handle *fairWalletHandle
		if !cold {
			var err error
			handle, err = fairOpenWallet(dbPath, client)
			require.NoError(b, err)
			fairRequireTip(b, handle.wallet, fixture.base)
			fairRequireUnsynced(b, handle.wallet)
		}

		var before runtime.MemStats
		if !cold {
			runtime.GC()
			runtime.ReadMemStats(&before)
		}

		b.StartTimer()
		started := time.Now()
		var err error
		if cold {
			handle, err = fairOpenWallet(dbPath, client)
			if err == nil {
				err = fairCheckUnsynced(handle.wallet)
			}
		}
		if err == nil {
			err = fairActivateWallet(b.Context(), handle)
		}
		if err == nil {
			err = fairWaitForMemorySync(handle.wallet)
		}
		totalElapsed += time.Since(started)
		b.StopTimer()
		if err != nil && handle == nil {
			fairStopChainClient(client)
		}
		require.NoError(b, err)

		if !cold {
			var after runtime.MemStats
			runtime.ReadMemStats(&after)
			memory.mallocs += after.Mallocs - before.Mallocs
			memory.totalAlloc += after.TotalAlloc - before.TotalAlloc
		}

		fairRequireTip(b, handle.wallet, fixture.target)
		gotDigest := fairValidateState(
			b, handle.wallet, fixture.target, fixture.expected,
			fixture.workload,
		)
		fairAccumulateDigests(b, &digest, &digestSet, gotDigest)

		require.NoError(b, fairCloseWallet(handle))
		gotPragmas := fairVerifySQLitePragmas(b, dbPath)
		require.Equal(b, fixture.pragmas, gotPragmas)
		totalGrowth += fairFileSize(b, dbPath) - baseSize
		fairRequireClosedSQLite(b, dbPath)
	}

	b.ReportMetric(
		float64(totalGrowth)/float64(b.N), "db-growth-bytes",
	)
	if !cold {
		fairReportBlockMetrics(
			b, blocks, totalElapsed, memory,
		)
	}
	fairLogDigests(
		b, digest, fixture.target, fixture.expected, fixture.workload,
	)
	fairLogSQLitePragmas(b, fixture.pragmas)
}

// newFairSyncFixture creates, syncs, closes, and snapshots a deterministic
// SQLite wallet before mining the requested deterministic backlog.
func newFairSyncFixture(b *testing.B, blocks int,
	sparse bool) *fairSyncFixture {

	b.Helper()
	params := &chaincfg.RegressionNetParams
	miner, err := rpctest.New(params, nil, []string{
		"--txindex",
		"--minrelaytxfee=0.00000001",
	}, "")
	require.NoError(b, err)
	require.NoError(b, miner.SetUp(true, fairBaseMatureOutputs))
	b.Cleanup(func() {
		require.NoError(b, miner.TearDown())
	})

	base := fairMinerTip(b, miner)
	dir := b.TempDir()
	livePath := filepath.Join(dir, fairSQLiteFileMarker+"live.sqlite")
	fairPrepareSQLiteFile(b, livePath)
	preparedPragmas := fairVerifySQLitePragmas(b, livePath)
	fairRequireClosedSQLite(b, livePath)
	loader, err := NewSQLiteLoader(
		b.Context(), params, fairRecoveryWindow,
		fairSQLiteLoaderConfig(livePath),
		WithWalletSyncRetryInterval(10*time.Millisecond),
	)
	require.NoError(b, err)
	wallet, err := loader.CreateNewWallet(
		[]byte(fairPublicPass), []byte(fairPrivatePass), fairSeed[:],
		params.GenesisBlock.Header.Timestamp,
	)
	require.NoError(b, err)
	client := fairNewChainClient(b, miner)
	wallet.SynchronizeRPC(client)
	require.NoError(b, fairWaitForMemorySync(wallet))
	fairRequireTip(b, wallet, base)

	addresses := fairAllocateSparseAddresses(b, wallet, sparse)
	empty := fairExpectedState{}
	baseWorkload := fairWorkloadDigest(b, fairWorkloadShape{
		ExpectedWallet: empty,
	})
	fairValidateState(b, wallet, base, empty, baseWorkload)
	require.NoError(b, loader.UnloadWallet())
	fairStopChainClient(client)
	livePragmas := fairVerifySQLitePragmas(b, livePath)
	require.Equal(b, preparedPragmas, livePragmas)
	fairRequireClosedSQLite(b, livePath)

	snapshotPath := filepath.Join(dir, fairSQLiteFileMarker+"base.sqlite")
	fairCopySnapshot(b, livePath, snapshotPath)
	snapshotPragmas := fairVerifySQLitePragmas(b, snapshotPath)
	require.Equal(b, livePragmas, snapshotPragmas)
	fairRequireClosedSQLite(b, snapshotPath)

	expected := fairExpectedState{}
	if sparse {
		expected.Transactions = fairSparsePayments
		expected.UTXOs = fairSparsePayments
		expected.Balance = fairPaymentAmount * fairSparsePayments
	}
	workloadShape := fairMineBacklog(
		b, miner, blocks, addresses, expected,
	)
	workload := fairWorkloadDigest(b, workloadShape)
	target := fairMinerTip(b, miner)
	require.Equal(b, base.Height+int32(blocks), target.Height)

	return &fairSyncFixture{
		miner:        miner,
		snapshotPath: snapshotPath,
		base:         base,
		target:       target,
		expected:     expected,
		workload:     workload,
		pragmas:      snapshotPragmas,
	}
}

// fairSQLiteLoaderConfig returns the common SQLite connection and pragma
// settings used to create the base wallet.
func fairSQLiteLoaderConfig(dbPath string) SQLiteLoaderConfig {
	return SQLiteLoaderConfig{
		DBPath:             dbPath,
		WalletName:         fairWalletName,
		BusyTimeout:        5 * time.Second,
		MaxConnections:     fairSQLiteConnections,
		MaxIdleConnections: fairSQLiteConnections,
		Pragmas: []string{
			"synchronous=normal",
			"fullfsync=false",
			"auto_vacuum=none",
		},
	}
}

// fairSQLiteStoreConfig returns matching settings for snapshot opens.
func fairSQLiteStoreConfig(dbPath string) storesqlite.Config {
	loaderConfig := fairSQLiteLoaderConfig(dbPath)

	return storesqlite.Config{
		DBPath:             loaderConfig.DBPath,
		BusyTimeout:        loaderConfig.BusyTimeout,
		MaxConnections:     loaderConfig.MaxConnections,
		MaxIdleConnections: loaderConfig.MaxIdleConnections,
		Pragmas:            loaderConfig.Pragmas,
	}
}

// fairOpenWallet opens one copied SQLite snapshot without starting sync.
func fairOpenWallet(dbPath string,
	client *chain.RPCClient) (*fairWalletHandle, error) {

	conn, err := storesqlite.Open(
		context.Background(), fairSQLiteStoreConfig(dbPath),
	)
	if err != nil {
		return nil, err
	}
	if err := storesqlite.ApplyMigrations(conn); err != nil {
		_ = conn.Close()

		return nil, err
	}

	store := dbsqlite.NewNamedStore(conn, fairWalletName)
	wallet, err := OpenFromStore(
		store, []byte(fairPublicPass), &chaincfg.RegressionNetParams,
		fairRecoveryWindow, 10*time.Millisecond,
	)
	if err != nil {
		_ = conn.Close()

		return nil, err
	}

	return &fairWalletHandle{
		wallet: wallet,
		conn:   conn,
		client: client,
	}, nil
}

// fairActivateWallet performs the minimum candidate runtime activation needed
// to begin synchronization.
func fairActivateWallet(_ context.Context, handle *fairWalletHandle) error {
	handle.wallet.Start()
	handle.wallet.SynchronizeRPC(handle.client)

	return nil
}

// fairCloseWallet cleanly stops the wallet, SQLite pool, and client outside
// timing.
func fairCloseWallet(handle *fairWalletHandle) error {
	handle.wallet.Stop()
	handle.wallet.WaitForShutdown()
	fairStopChainClient(handle.client)

	return handle.conn.Close()
}

// fairNewChainClient constructs and starts one btcd RPC client outside timing.
func fairNewChainClient(tb testing.TB,
	miner *rpctest.Harness) *chain.RPCClient {

	tb.Helper()
	rpcConfig := miner.RPCConfig()
	client, err := chain.NewRPCClientWithConfig(&chain.RPCClientConfig{
		Conn:              &rpcConfig,
		Chain:             &chaincfg.RegressionNetParams,
		ReconnectAttempts: 3,
	})
	require.NoError(tb, err)
	require.NoError(tb, client.Start(tb.Context()))

	return client
}

// fairStopChainClient stops one client and waits for all of its goroutines.
func fairStopChainClient(client *chain.RPCClient) {
	client.Stop()
	client.WaitForShutdown()
}

// fairAllocateSparseAddresses uses the public wallet API to create ten fixed
// BIP84 addresses and verifies their seed-derived identity.
func fairAllocateSparseAddresses(b *testing.B, wallet *Wallet,
	sparse bool) []address.Address {

	b.Helper()
	if !sparse {
		return nil
	}

	addresses := make([]address.Address, 0, fairSparsePayments)
	for i := 0; i < fairSparsePayments; i++ {
		addr, err := wallet.NewAddress(
			waddrmgr.DefaultAccountNum, waddrmgr.KeyScopeBIP0084,
		)
		require.NoError(b, err)
		require.Equal(
			b, fairExpectedAddress(b, uint32(i)).String(),
			addr.String(),
		)
		addresses = append(addresses, addr)
	}

	return addresses
}

// fairExpectedAddress derives one BIP84 external address from the shared seed.
func fairExpectedAddress(tb testing.TB, index uint32) address.Address {
	tb.Helper()
	params := &chaincfg.RegressionNetParams
	key, err := hdkeychain.NewMaster(fairSeed[:], params)
	require.NoError(tb, err)
	defer key.Zero()

	for _, child := range []uint32{
		waddrmgr.KeyScopeBIP0084.Purpose + hdkeychain.HardenedKeyStart,
		waddrmgr.KeyScopeBIP0084.Coin + hdkeychain.HardenedKeyStart,
		hdkeychain.HardenedKeyStart, 0, index,
	} {
		key, err = key.Derive(child)
		require.NoError(tb, err)
	}

	pubKey, err := key.ECPubKey()
	require.NoError(tb, err)
	addr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKey.SerializeCompressed()), params,
	)
	require.NoError(tb, err)

	return addr
}

// fairMineBacklog mines empty blocks or ten evenly spaced wallet payments and
// returns a hash-independent description of the resulting workload.
func fairMineBacklog(b *testing.B, miner *rpctest.Harness, blocks int,
	addresses []address.Address,
	expected fairExpectedState) fairWorkloadShape {

	b.Helper()
	shape := fairWorkloadShape{
		Blocks:         blocks,
		ExpectedWallet: expected,
	}
	if blocks == 0 {
		return shape
	}
	if len(addresses) == 0 {
		_, err := miner.Client.Generate(uint32(blocks))
		require.NoError(b, err)

		return shape
	}

	require.Len(b, addresses, fairSparsePayments)
	require.Zero(b, blocks%len(addresses))
	stride := blocks / len(addresses)
	for i, addr := range addresses {
		if stride > 1 {
			_, err := miner.Client.Generate(uint32(stride - 1))
			require.NoError(b, err)
		}

		pkScript, err := txscript.PayToAddrScript(addr)
		require.NoError(b, err)
		shape.PaymentOutputs = append(
			shape.PaymentOutputs, fairWorkloadOutput{
				BlockOffset: (i + 1) * stride,
				PkScript:    fmt.Sprintf("%x", pkScript),
				Amount:      fairPaymentAmount,
			},
		)
		_, err = miner.SendOutputs(
			[]*wire.TxOut{wire.NewTxOut(
				fairPaymentAmount, pkScript,
			)}, 1,
		)
		require.NoError(b, err)
		_, err = miner.Client.Generate(1)
		require.NoError(b, err)
	}

	return shape
}

// fairMinerTip returns the exact current btcd hash and height.
func fairMinerTip(tb testing.TB,
	miner *rpctest.Harness) waddrmgr.BlockStamp {

	tb.Helper()
	hash, height, err := miner.Client.GetBestBlock()
	require.NoError(tb, err)

	return waddrmgr.BlockStamp{Hash: *hash, Height: height}
}

// fairCheckUnsynced verifies that a sample has not already reached the synced
// state.
func fairCheckUnsynced(wallet *Wallet) error {
	if wallet.ChainSynced() {
		return errors.New("wallet unexpectedly started in synced state")
	}

	return nil
}

// fairRequireUnsynced requires an in-memory unsynced state before activation.
func fairRequireUnsynced(tb testing.TB, wallet *Wallet) {
	tb.Helper()
	require.NoError(tb, fairCheckUnsynced(wallet))
}

// fairWaitForMemorySync polls only ChainSynced until synchronization completes.
func fairWaitForMemorySync(wallet *Wallet) error {
	deadline := time.NewTimer(fairSyncTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(fairPollInterval)
	defer ticker.Stop()

	for {
		if wallet.ChainSynced() {
			return nil
		}

		select {
		case <-ticker.C:

		case <-deadline.C:
			return errors.New("wallet in-memory sync timeout")
		}
	}
}

// fairRequireTip checks one exact stored hash and height without waiting.
func fairRequireTip(tb testing.TB, wallet *Wallet,
	target waddrmgr.BlockStamp) {

	tb.Helper()
	stamp := wallet.SyncedTo()
	require.Equal(tb, target.Height, stamp.Height)
	require.Equal(tb, target.Hash, stamp.Hash)
}

// fairValidateState reads transaction, UTXO, and balance semantics only through
// public wallet APIs and returns full and hash-independent digests.
func fairValidateState(tb testing.TB, wallet *Wallet,
	target waddrmgr.BlockStamp, expected fairExpectedState,
	workload [sha256.Size]byte) fairDigestPair {

	tb.Helper()

	transactions, err := wallet.GetTransactions(
		NewBlockIdentifierFromHeight(0),
		NewBlockIdentifierFromHeight(target.Height), "", nil,
	)
	require.NoError(tb, err)
	txIDs := make([]string, 0, expected.Transactions)
	for _, transaction := range transactions.UnminedTransactions {
		require.NotNil(tb, transaction.Hash)
		txIDs = append(txIDs, transaction.Hash.String())
	}
	for _, block := range transactions.MinedTransactions {
		for _, transaction := range block.Transactions {
			require.NotNil(tb, transaction.Hash)
			txIDs = append(txIDs, transaction.Hash.String())
		}
	}
	sort.Strings(txIDs)

	utxos, err := wallet.UnspentOutputs(OutputSelectionPolicy{
		Account:               waddrmgr.DefaultAccountNum,
		RequiredConfirmations: 1,
	})
	require.NoError(tb, err)
	utxoIDs := make([]fairUTXOIdentity, 0, len(utxos))
	for _, utxo := range utxos {
		utxoIDs = append(utxoIDs, fairUTXOIdentity{
			OutPoint: fmt.Sprintf(
				"%s:%d", utxo.OutPoint.Hash, utxo.OutPoint.Index,
			),
			Amount: utxo.Output.Value,
		})
	}
	sort.Slice(utxoIDs, func(i, j int) bool {
		if utxoIDs[i].OutPoint == utxoIDs[j].OutPoint {
			return utxoIDs[i].Amount < utxoIDs[j].Amount
		}

		return utxoIDs[i].OutPoint < utxoIDs[j].OutPoint
	})

	balance, err := wallet.CalculateBalance(1)
	require.NoError(tb, err)
	require.Len(tb, txIDs, expected.Transactions)
	require.Len(tb, utxoIDs, expected.UTXOs)
	require.Equal(tb, expected.Balance, int64(balance))

	actual := fairSyncSemantic{
		TargetHeight:   target.Height,
		TargetHash:     target.Hash.String(),
		TransactionIDs: txIDs,
		UTXOs:          utxoIDs,
		Balance:        int64(balance),
		WorkloadDigest: fmt.Sprintf("%x", workload),
	}
	payload, err := json.Marshal(actual)
	require.NoError(tb, err)

	utxoAmounts := make([]int64, 0, len(utxoIDs))
	for _, utxo := range utxoIDs {
		utxoAmounts = append(utxoAmounts, utxo.Amount)
	}
	sort.Slice(utxoAmounts, func(i, j int) bool {
		return utxoAmounts[i] < utxoAmounts[j]
	})
	hashIndependent := fairHashIndependentSemantic{
		TargetHeight:   target.Height,
		Transactions:   len(txIDs),
		UTXOAmounts:    utxoAmounts,
		Balance:        int64(balance),
		WorkloadDigest: fmt.Sprintf("%x", workload),
	}
	independentPayload, err := json.Marshal(hashIndependent)
	require.NoError(tb, err)

	return fairDigestPair{
		semantic:        sha256.Sum256(payload),
		hashIndependent: sha256.Sum256(independentPayload),
	}
}

// fairWorkloadDigest hashes one deterministic, hash-independent workload shape.
func fairWorkloadDigest(tb testing.TB,
	shape fairWorkloadShape) [sha256.Size]byte {

	tb.Helper()
	payload, err := json.Marshal(shape)
	require.NoError(tb, err)

	return sha256.Sum256(payload)
}

// fairAccumulateDigests requires every sample to produce identical semantics.
func fairAccumulateDigests(tb testing.TB, digest *fairDigestPair,
	digestSet *bool, got fairDigestPair) {

	tb.Helper()
	if !*digestSet {
		*digest = got
		*digestSet = true

		return
	}

	require.Equal(tb, *digest, got)
}

// fairLogDigests records full, hash-independent, and workload digests.
func fairLogDigests(b *testing.B, digest fairDigestPair,
	target waddrmgr.BlockStamp, expected fairExpectedState,
	workload [sha256.Size]byte) {

	b.Helper()
	b.Logf("semantic-digest=%x hash-independent-digest=%x "+
		"workload-digest=%x target=%d:%s txs=%d utxos=%d balance=%d",
		digest.semantic, digest.hashIndependent, workload, target.Height,
		target.Hash, expected.Transactions, expected.UTXOs,
		expected.Balance)
}

// fairReportBlockMetrics reports throughput and process allocation deltas only
// for warm-open backlog rows.
func fairReportBlockMetrics(b *testing.B, blocks int,
	elapsed time.Duration, memory fairMemoryDelta) {

	b.Helper()
	totalBlocks := float64(blocks * b.N)
	b.ReportMetric(totalBlocks/elapsed.Seconds(), "blocks/s")
	b.ReportMetric(
		elapsed.Seconds()*1_000_000/totalBlocks, "us/block",
	)
	b.ReportMetric(float64(memory.totalAlloc)/totalBlocks, "bytes/block")
	b.ReportMetric(float64(memory.mallocs)/totalBlocks, "allocs/block")
}

// fairSQLiteRoleDSN returns the role route's SQLite DSN settings.
func fairSQLiteRoleDSN(dbPath string, busyTimeout int) string {
	options := url.Values{}
	for _, pragma := range []string{
		"foreign_keys=on",
		"journal_mode=WAL",
		fmt.Sprintf("busy_timeout=%d", busyTimeout),
	} {
		options.Add("_pragma", pragma)
	}

	return fmt.Sprintf(
		"%s?%s&_txlock=immediate&_time_format=sqlite", dbPath,
		options.Encode(),
	)
}

// fairPrepareSQLiteFile creates a role-configured database before the salvage
// opener can persist its incompatible incremental auto-vacuum default.
func fairPrepareSQLiteFile(tb testing.TB, dbPath string) {
	tb.Helper()
	conn, err := sql.Open("sqlite", fairSQLiteRoleDSN(dbPath, 5000))
	require.NoError(tb, err)
	conn.SetMaxOpenConns(fairSQLiteConnections)
	conn.SetMaxIdleConns(fairSQLiteConnections)
	require.NoError(tb, conn.PingContext(tb.Context()))
	require.NoError(tb, conn.Close())
}

// fairSQLiteVerificationDSN reproduces the salvage opener's defaults followed
// by the benchmark overrides on an independent connection.
func fairSQLiteVerificationDSN(dbPath string, busyTimeout int) string {
	options := url.Values{}
	for _, pragma := range []string{
		"foreign_keys=on",
		"journal_mode=WAL",
		fmt.Sprintf("busy_timeout=%d", busyTimeout),
		"synchronous=full",
		"fullfsync=true",
		"auto_vacuum=incremental",
		"synchronous=normal",
		"fullfsync=false",
		"auto_vacuum=none",
	} {
		options.Add("_pragma", pragma)
	}

	return fmt.Sprintf(
		"%s?%s&_txlock=immediate&_time_format=sqlite", dbPath,
		options.Encode(),
	)
}

// fairVerifySQLitePragmas checks effective settings and proves that BEGIN uses
// an immediate write lock on a closed candidate database.
func fairVerifySQLitePragmas(tb testing.TB,
	dbPath string) fairSQLitePragmas {

	tb.Helper()
	conn, err := sql.Open(
		"sqlite", fairSQLiteVerificationDSN(dbPath, 5000),
	)
	require.NoError(tb, err)
	conn.SetMaxOpenConns(fairSQLiteConnections)
	conn.SetMaxIdleConns(fairSQLiteConnections)
	require.NoError(tb, conn.PingContext(tb.Context()))

	result := fairSQLitePragmas{
		txLock:         "immediate",
		maxConnections: conn.Stats().MaxOpenConnections,
	}
	require.NoError(tb, conn.QueryRowContext(
		tb.Context(), "PRAGMA journal_mode",
	).Scan(&result.journalMode))
	require.NoError(tb, conn.QueryRowContext(
		tb.Context(), "PRAGMA foreign_keys",
	).Scan(&result.foreignKeys))
	require.NoError(tb, conn.QueryRowContext(
		tb.Context(), "PRAGMA busy_timeout",
	).Scan(&result.busyTimeout))
	require.NoError(tb, conn.QueryRowContext(
		tb.Context(), "PRAGMA synchronous",
	).Scan(&result.synchronous))
	require.NoError(tb, conn.QueryRowContext(
		tb.Context(), "PRAGMA fullfsync",
	).Scan(&result.fullFSync))
	require.NoError(tb, conn.QueryRowContext(
		tb.Context(), "PRAGMA auto_vacuum",
	).Scan(&result.autoVacuum))

	require.Equal(tb, "wal", result.journalMode)
	require.Equal(tb, 1, result.foreignKeys)
	require.Equal(tb, 5000, result.busyTimeout)
	require.Equal(tb, 1, result.synchronous)
	require.Zero(tb, result.fullFSync)
	require.Zero(tb, result.autoVacuum)
	require.Equal(tb, fairSQLiteConnections, result.maxConnections)

	contender, err := sql.Open(
		"sqlite", fairSQLiteVerificationDSN(dbPath, 0),
	)
	require.NoError(tb, err)
	contender.SetMaxOpenConns(fairSQLiteConnections)
	contender.SetMaxIdleConns(fairSQLiteConnections)
	require.NoError(tb, contender.PingContext(tb.Context()))

	tx, err := conn.BeginTx(tb.Context(), nil)
	require.NoError(tb, err)
	contenderTx, contenderErr := contender.BeginTx(tb.Context(), nil)
	if contenderErr == nil {
		require.NoError(tb, contenderTx.Rollback())
	}
	require.Error(tb, contenderErr, "second BEGIN must observe immediate lock")
	var sqliteErr *modernsqlite.Error
	require.ErrorAs(tb, contenderErr, &sqliteErr)
	require.Equal(tb, sqlite3.SQLITE_BUSY, sqliteErr.Code()&0xff)
	require.NoError(tb, tx.Rollback())
	require.NoError(tb, contender.Close())
	require.NoError(tb, conn.Close())

	return result
}

// fairLogSQLitePragmas records settings verified after candidate close.
func fairLogSQLitePragmas(b *testing.B, pragmas fairSQLitePragmas) {
	b.Helper()
	b.Logf("effective-pragmas journal_mode=%s foreign_keys=%d "+
		"busy_timeout=%d synchronous=%d fullfsync=%d auto_vacuum=%d "+
		"txlock=%s max_connections=%d verified=post-close-independent",
		pragmas.journalMode, pragmas.foreignKeys, pragmas.busyTimeout,
		pragmas.synchronous, pragmas.fullFSync, pragmas.autoVacuum,
		pragmas.txLock, pragmas.maxConnections)
}

// fairIterationPath returns a fresh destination for one snapshot copy.
func fairIterationPath(tb testing.TB, iteration int) string {
	tb.Helper()

	return filepath.Join(
		tb.TempDir(), fmt.Sprintf(
			"%siteration-%d.sqlite", fairSQLiteFileMarker, iteration,
		),
	)
}

// fairCopySnapshot copies one closed SQLite main database outside timing.
func fairCopySnapshot(tb testing.TB, source, destination string) {
	tb.Helper()
	src, err := os.Open(source)
	require.NoError(tb, err)
	defer func() {
		require.NoError(tb, src.Close())
	}()

	dst, err := os.OpenFile(
		destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600,
	)
	require.NoError(tb, err)
	_, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	require.NoError(tb, copyErr)
	require.NoError(tb, closeErr)
}

// fairFileSize returns the SQLite main database size.
func fairFileSize(tb testing.TB, dbPath string) int64 {
	tb.Helper()
	info, err := os.Stat(dbPath)
	require.NoError(tb, err)

	return info.Size()
}

// fairRequireClosedSQLite verifies closed-snapshot files and no KV sidecar.
func fairRequireClosedSQLite(tb testing.TB, dbPath string) {
	tb.Helper()
	paths := []string{
		dbPath + "-wal",
		dbPath + "-shm",
		filepath.Join(filepath.Dir(dbPath), WalletDBName),
	}
	for _, path := range paths {
		_, err := os.Stat(path)
		require.Truef(
			tb, errors.Is(err, os.ErrNotExist),
			"unexpected SQLite or KV sidecar %s: %v", path, err,
		)
	}
}
