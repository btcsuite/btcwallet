package wallet

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	dbsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	storesqlite "github.com/btcsuite/btcwallet/wallet/internal/sql/sqlite"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

const (
	salvageBenchmarkWalletName = "sqlite-route-benchmark"
	salvageBenchmarkPubPass    = "public-pass"
	salvageBenchmarkPrivPass   = "private-pass"
	salvageBenchmarkAccount    = uint32(1)
	salvageBenchmarkPathIndex  = uint32(7)
)

var (
	salvageBenchmarkSeed = [32]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	salvageBenchmarkScope = waddrmgr.KeyScope{
		Purpose: 1017,
		Coin:    1,
	}
	salvageBenchmarkSchema = waddrmgr.ScopeAddrSchema{
		ExternalAddrType: waddrmgr.WitnessPubKey,
		InternalAddrType: waddrmgr.WitnessPubKey,
	}
	salvageBenchmarkPath = waddrmgr.DerivationPath{
		InternalAccount: salvageBenchmarkAccount,
		Account:         salvageBenchmarkAccount,
		Branch:          0,
		Index:           salvageBenchmarkPathIndex,
	}
)

// salvageBenchmarkKeyResult holds one allocation for untimed validation.
type salvageBenchmarkKeyResult struct {
	index     uint32
	publicKey [33]byte
	err       error
}

// salvageBenchmarkFixture owns one deterministic Store-backed SQLite wallet.
type salvageBenchmarkFixture struct {
	dbPath          string
	conn            *sql.DB
	loader          *Loader
	wallet          *Wallet
	openViewElapsed time.Duration
}

// salvageTimedViewStore records how long an open holds its Store view.
type salvageTimedViewStore struct {
	// Store delegates the measured transaction execution.
	walletstore.Store

	elapsed time.Duration
}

// salvageFundingTimedStore records complete Store transaction duration for the
// split funding benchmark.
type salvageFundingTimedStore struct {
	// Store delegates the measured transaction execution.
	walletstore.Store

	viewNanos   atomic.Int64
	updateNanos atomic.Int64
}

// View records one funding snapshot transaction.
func (s *salvageFundingTimedStore) View(ctx context.Context,
	body func(walletstore.ReadTx) error, reset func()) error {

	start := time.Now()
	err := s.Store.View(ctx, body, reset)
	s.viewNanos.Add(time.Since(start).Nanoseconds())

	return err
}

// UpdateOnce records one funding apply transaction.
func (s *salvageFundingTimedStore) UpdateOnce(ctx context.Context,
	body func(walletstore.ReadWriteTx) error, reset func()) error {

	start := time.Now()
	err := s.Store.UpdateOnce(ctx, body, reset)
	s.updateNanos.Add(time.Since(start).Nanoseconds())

	return err
}

// View records the complete duration of one delegated read transaction.
func (s *salvageTimedViewStore) View(ctx context.Context,
	body func(walletstore.ReadTx) error, reset func()) error {

	start := time.Now()
	err := s.Store.View(ctx, body, reset)
	s.elapsed += time.Since(start)

	return err
}

// useSalvageBenchmarkScrypt excludes production-strength scrypt setup from
// benchmark wall time while leaving the measured wallet routes unchanged.
func useSalvageBenchmarkScrypt(b *testing.B) {
	b.Helper()

	defaultOptions := waddrmgr.DefaultScryptOptions
	waddrmgr.DefaultScryptOptions = waddrmgr.FastScryptOptions
	b.Cleanup(func() {
		waddrmgr.DefaultScryptOptions = defaultOptions
	})
}

// newSalvageBenchmarkFixture creates and unlocks a deterministic SQLite wallet
// with the lnd key scope and accounts already initialized.
func newSalvageBenchmarkFixture(b *testing.B) *salvageBenchmarkFixture {
	b.Helper()

	dbPath := filepath.Join(b.TempDir(), "wallet.sqlite")
	conn, err := storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: dbPath,
	})
	if err != nil {
		b.Fatalf("open SQLite fixture: %v", err)
	}
	if err := storesqlite.ApplyMigrations(conn); err != nil {
		_ = conn.Close()
		b.Fatalf("apply SQLite migrations: %v", err)
	}

	store := dbsqlite.NewNamedStore(conn, salvageBenchmarkWalletName)
	loader, err := NewLoaderWithStore(&chaincfg.TestNet3Params, 0, store)
	if err != nil {
		_ = conn.Close()
		b.Fatalf("create Store loader: %v", err)
	}

	wallet, err := loader.CreateNewWallet(
		[]byte(salvageBenchmarkPubPass),
		[]byte(salvageBenchmarkPrivPass), salvageBenchmarkSeed[:],
		time.Unix(1_700_000_000, 0),
	)
	if err != nil {
		_ = conn.Close()
		b.Fatalf("create SQLite wallet: %v", err)
	}
	if err := wallet.Unlock([]byte(salvageBenchmarkPrivPass), nil); err != nil {
		_ = loader.UnloadWallet()
		_ = conn.Close()
		b.Fatalf("unlock SQLite wallet: %v", err)
	}
	if err := wallet.InitializeKeyScope(
		salvageBenchmarkScope, salvageBenchmarkSchema,
		[]uint32{0, 1}, false,
	); err != nil {

		_ = loader.UnloadWallet()
		_ = conn.Close()
		b.Fatalf("initialize lnd key scope: %v", err)
	}

	fixture := &salvageBenchmarkFixture{
		dbPath: dbPath,
		conn:   conn,
		loader: loader,
		wallet: wallet,
	}
	b.Cleanup(func() {
		fixture.close(b)
	})

	return fixture
}

// close stops the fixture wallet and closes its caller-owned SQLite pool.
func (f *salvageBenchmarkFixture) close(b *testing.B) {
	b.Helper()

	if f.loader != nil {
		if err := f.loader.UnloadWallet(); err != nil {
			b.Errorf("unload SQLite wallet: %v", err)
		}
		f.loader = nil
		f.wallet = nil
	}
	if f.conn != nil {
		if err := f.conn.Close(); err != nil {
			b.Errorf("close SQLite fixture: %v", err)
		}
		f.conn = nil
	}
}

// openExisting reopens the fixture through the Store-backed loader.
func (f *salvageBenchmarkFixture) openExisting(b *testing.B) Interface {
	b.Helper()

	conn, err := storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: f.dbPath,
	})
	if err != nil {
		b.Fatalf("reopen SQLite fixture: %v", err)
	}

	store := &salvageTimedViewStore{
		Store: dbsqlite.NewNamedStore(conn, salvageBenchmarkWalletName),
	}
	loader, err := NewLoaderWithStore(&chaincfg.TestNet3Params, 0, store)
	if err != nil {
		_ = conn.Close()
		b.Fatalf("recreate Store loader: %v", err)
	}
	wallet, err := loader.OpenExistingWallet(
		[]byte(salvageBenchmarkPubPass), false,
	)
	if err != nil {
		_ = conn.Close()
		b.Fatalf("reopen Store wallet: %v", err)
	}

	f.conn = conn
	f.loader = loader
	f.wallet = wallet
	f.openViewElapsed = store.elapsed

	return wallet
}

// BenchmarkSQLiteRoute measures the unoptimized Store-backed SQLite routes used
// by lnd with the same names and fixed fixtures as the role benchmark.
func BenchmarkSQLiteRoute(b *testing.B) {
	useSalvageBenchmarkScrypt(b)

	b.Run(
		"SequentialExternalKeyAllocation",
		benchmarkSalvageSequentialExternalKey,
	)
	b.Run(
		"ConcurrentExternalKeyAllocation",
		benchmarkSalvageConcurrentExternalKey,
	)
	b.Run("ArbitraryPublicDerivation", benchmarkSalvagePublicDerivation)
	b.Run(
		"ArbitraryPrivateDerivation",
		benchmarkSalvagePrivateDerivation,
	)
	b.Run("ArbitrarySigning", benchmarkSalvageSigning)

	for _, numKeys := range []int{100, 1000} {
		name := fmt.Sprintf("RestartOpen/Keys-%d", numKeys)
		b.Run(name, func(b *testing.B) {
			benchmarkSalvageRestartOpen(b, numKeys)
		})

		name = fmt.Sprintf("ManagerOpenSplit/Keys-%d", numKeys)
		b.Run(name, func(b *testing.B) {
			benchmarkSalvageManagerOpenSplit(b, numKeys)
		})
	}

	benchmarkSalvageControllerSync(b)
}

// BenchmarkStoreFundingTransactionDuration compares the old monolithic hold
// estimate, represented by full operation time, with the measured read and
// final-update transaction durations after the split.
func BenchmarkStoreFundingTransactionDuration(b *testing.B) {
	b.StopTimer()
	fixture := newSalvageBenchmarkFixture(b)
	wallet := fixture.wallet
	wallet.chainClient = &mockChainClient{}
	receive, err := wallet.NewAddress(
		waddrmgr.DefaultAccountNum, waddrmgr.KeyScopeBIP0084,
	)
	if err != nil {
		b.Fatalf("allocate funding address: %v", err)
	}
	prevScript, err := txscript.PayToAddrScript(receive)
	if err != nil {
		b.Fatalf("create funding script: %v", err)
	}
	fundingTx := wire.NewMsgTx(2)
	fundingTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash:  chainhash.Hash{0x51},
		Index: 1,
	}})
	fundingTx.AddTxOut(wire.NewTxOut(1_000_000, prevScript))
	funding, err := wtxmgr.NewTxRecordFromMsgTx(
		fundingTx, time.Unix(1_700_000_100, 0),
	)
	if err != nil {
		b.Fatalf("create funding record: %v", err)
	}
	if err := wallet.store.UpdateOnce(
		b.Context(), func(tx walletstore.ReadWriteTx) error {
			return wallet.addRelevantTxFromStore(tx, funding, nil)
		}, nil,
	); err != nil {

		b.Fatalf("insert funding transaction: %v", err)
	}

	destination, err := address.NewAddressWitnessPubKeyHash(
		make([]byte, 20), &chaincfg.TestNet3Params,
	)
	if err != nil {
		b.Fatalf("create destination: %v", err)
	}
	destinationScript, err := txscript.PayToAddrScript(destination)
	if err != nil {
		b.Fatalf("create destination script: %v", err)
	}
	timedStore := &salvageFundingTimedStore{Store: wallet.store}
	wallet.store = timedStore
	outpoint := wire.OutPoint{Hash: funding.Hash, Index: 0}

	b.ReportAllocs()
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		_, err := wallet.CreateSimpleTx(
			&waddrmgr.KeyScopeBIP0084, waddrmgr.DefaultAccountNum,
			[]*wire.TxOut{wire.NewTxOut(100_000, destinationScript)}, 0,
			1_000, CoinSelectionLargest, false,
			WithCustomSelectUtxos([]wire.OutPoint{outpoint}),
		)
		if err != nil {
			b.Fatalf("create transaction: %v", err)
		}
	}
	operationNanos := time.Since(start).Nanoseconds()
	b.StopTimer()

	b.ReportMetric(
		float64(operationNanos)/float64(b.N),
		"monolithic-hold-estimate-ns/op",
	)
	b.ReportMetric(
		float64(timedStore.viewNanos.Load())/float64(b.N),
		"split-read-tx-ns/op",
	)
	b.ReportMetric(
		float64(timedStore.updateNanos.Load())/float64(b.N),
		"split-write-tx-ns/op",
	)
}

// benchmarkSalvageManagerOpenSplit measures detached snapshot reads and manager
// reconstruction separately for a fixed number of durable keys.
func benchmarkSalvageManagerOpenSplit(b *testing.B, numKeys int) {
	b.StopTimer()
	fixture := newSalvageBenchmarkFixture(b)
	var lndWallet Interface = fixture.wallet
	for i := 0; i < numKeys; i++ {
		_, _, err := lndWallet.NextExternalKey(
			salvageBenchmarkScope, salvageBenchmarkAccount,
		)
		if err != nil {
			b.Fatalf("preallocate external key %d: %v", i, err)
		}
	}
	fixture.close(b)

	conn, err := storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: fixture.dbPath,
	})
	if err != nil {
		b.Fatalf("reopen SQLite fixture: %v", err)
	}
	fixture.conn = conn
	store := dbsqlite.NewNamedStore(conn, salvageBenchmarkWalletName)

	var (
		snapshotElapsed    time.Duration
		reconstructElapsed time.Duration
	)
	b.ReportAllocs()
	b.ResetTimer()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		var snapshot *waddrmgr.ManagerSnapshot
		start := time.Now()
		err := store.View(
			b.Context(), func(tx walletstore.ReadTx) error {
				var err error
				snapshot, err = waddrmgr.ReadManagerSnapshot(tx.Addr())
				return err
			}, func() {
				snapshot = nil
			},
		)
		snapshotElapsed += time.Since(start)
		if err != nil {
			b.Fatalf("read manager snapshot: %v", err)
		}

		start = time.Now()
		manager, err := waddrmgr.OpenFromSnapshot(
			snapshot, []byte(salvageBenchmarkPubPass),
			&chaincfg.TestNet3Params,
		)
		reconstructElapsed += time.Since(start)
		if err != nil {
			b.Fatalf("reconstruct manager: %v", err)
		}
		manager.Close()
	}
	b.StopTimer()

	b.ReportMetric(
		float64(snapshotElapsed.Nanoseconds())/float64(b.N),
		"snapshot-read-ns/op",
	)
	b.ReportMetric(
		float64(reconstructElapsed.Nanoseconds())/float64(b.N),
		"reconstruct-ns/op",
	)
}

// benchmarkSalvageSequentialExternalKey measures durable external public-key
// allocation through the backend-neutral wallet interface.
func benchmarkSalvageSequentialExternalKey(b *testing.B) {
	b.StopTimer()
	fixture := newSalvageBenchmarkFixture(b)
	var lndWallet Interface = fixture.wallet

	var (
		lastKey   *btcec.PublicKey
		lastIndex uint32
		err       error
	)
	b.ReportAllocs()
	b.ResetTimer()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		lastKey, lastIndex, err = lndWallet.NextExternalKey(
			salvageBenchmarkScope, salvageBenchmarkAccount,
		)
		if err != nil {
			b.Fatalf("allocate external key: %v", err)
		}
	}
	b.StopTimer()

	if lastKey == nil {
		b.Fatal("external allocation returned a nil public key")
	}
	if lastIndex != uint32(b.N-1) {
		b.Fatalf("last external index: got %d, want %d", lastIndex, b.N-1)
	}
}

// benchmarkSalvageConcurrentExternalKey measures contended durable key
// allocation and validates all returned indexes after timed work.
func benchmarkSalvageConcurrentExternalKey(b *testing.B) {
	b.StopTimer()
	fixture := newSalvageBenchmarkFixture(b)
	var lndWallet Interface = fixture.wallet

	results := make([]salvageBenchmarkKeyResult, b.N)
	var resultIndex atomic.Uint64

	b.ReportAllocs()
	b.ResetTimer()
	b.StartTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			key, index, err := lndWallet.NextExternalKey(
				salvageBenchmarkScope, salvageBenchmarkAccount,
			)
			slot := resultIndex.Add(1) - 1
			result := salvageBenchmarkKeyResult{
				index: index,
				err:   err,
			}
			if err == nil && key != nil {
				copy(result.publicKey[:], key.SerializeCompressed())
			}
			results[slot] = result
		}
	})
	b.StopTimer()

	if resultIndex.Load() != uint64(b.N) {
		b.Fatalf("parallel result count: got %d, want %d",
			resultIndex.Load(), b.N)
	}
	indexes := make(map[uint32]struct{}, b.N)
	publicKeys := make(map[[33]byte]struct{}, b.N)
	for i, result := range results {
		if result.err != nil {
			b.Fatalf("parallel allocation %d: %v", i, result.err)
		}
		if result.publicKey == [33]byte{} {
			b.Fatalf("parallel allocation %d returned a nil key", i)
		}
		if _, ok := indexes[result.index]; ok {
			b.Fatalf("duplicate external index %d", result.index)
		}
		indexes[result.index] = struct{}{}
		if _, ok := publicKeys[result.publicKey]; ok {
			b.Fatalf("duplicate external public key at result %d", i)
		}
		publicKeys[result.publicKey] = struct{}{}
	}
	for i := 0; i < b.N; i++ {
		if _, ok := indexes[uint32(i)]; !ok {
			b.Fatalf("missing external index %d", i)
		}
	}
}

// benchmarkSalvagePublicDerivation measures arbitrary public derivation for a
// fixed existing lnd account and path.
func benchmarkSalvagePublicDerivation(b *testing.B) {
	b.StopTimer()
	fixture := newSalvageBenchmarkFixture(b)
	var lndWallet Interface = fixture.wallet

	var (
		publicKey *btcec.PublicKey
		err       error
	)
	b.ReportAllocs()
	b.ResetTimer()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		publicKey, err = lndWallet.DeriveManagedPubKey(
			salvageBenchmarkScope, salvageBenchmarkPath,
		)
		if err != nil {
			b.Fatalf("derive managed public key: %v", err)
		}
	}
	b.StopTimer()

	if publicKey == nil {
		b.Fatal("public derivation returned a nil key")
	}
}

// benchmarkSalvagePrivateDerivation measures private derivation for the fixed
// existing lnd account and path.
func benchmarkSalvagePrivateDerivation(b *testing.B) {
	b.StopTimer()
	fixture := newSalvageBenchmarkFixture(b)
	var lndWallet Interface = fixture.wallet

	var (
		privateKey *btcec.PrivateKey
		err        error
	)
	b.ReportAllocs()
	b.ResetTimer()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		privateKey, err = lndWallet.DeriveFromKeyPath(
			salvageBenchmarkScope, salvageBenchmarkPath,
		)
		if err != nil {
			b.Fatalf("derive private key: %v", err)
		}
	}
	b.StopTimer()

	if privateKey == nil {
		b.Fatal("private derivation returned a nil key")
	}
}

// benchmarkSalvageSigning measures fixed-path private derivation followed by
// deterministic ECDSA signing.
func benchmarkSalvageSigning(b *testing.B) {
	b.StopTimer()
	fixture := newSalvageBenchmarkFixture(b)
	var lndWallet Interface = fixture.wallet
	hash := sha256.Sum256([]byte("sqlite route benchmark"))

	var (
		privateKey *btcec.PrivateKey
		signature  *ecdsa.Signature
		err        error
	)
	b.ReportAllocs()
	b.ResetTimer()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		privateKey, err = lndWallet.DeriveFromKeyPath(
			salvageBenchmarkScope, salvageBenchmarkPath,
		)
		if err != nil {
			b.Fatalf("derive signing key: %v", err)
		}
		signature = ecdsa.Sign(privateKey, hash[:])
	}
	b.StopTimer()

	if signature == nil || !signature.Verify(hash[:], privateKey.PubKey()) {
		b.Fatal("private derivation produced an invalid signature")
	}
}

// benchmarkSalvageRestartOpen measures connection and wallet open after a
// fixed number of durable allocations. Preallocation and shutdown are untimed.
func benchmarkSalvageRestartOpen(b *testing.B, numKeys int) {
	b.StopTimer()
	fixture := newSalvageBenchmarkFixture(b)
	var lndWallet Interface = fixture.wallet
	for i := 0; i < numKeys; i++ {
		_, _, err := lndWallet.NextExternalKey(
			salvageBenchmarkScope, salvageBenchmarkAccount,
		)
		if err != nil {
			b.Fatalf("preallocate external key %d: %v", i, err)
		}
	}
	fixture.close(b)

	info, err := os.Stat(fixture.dbPath)
	if err != nil {
		b.Fatalf("stat SQLite fixture: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	var (
		openElapsed time.Duration
		viewElapsed time.Duration
	)
	for i := 0; i < b.N; i++ {
		start := time.Now()
		b.StartTimer()
		lndWallet = fixture.openExisting(b)
		b.StopTimer()
		openElapsed += time.Since(start)
		viewElapsed += fixture.openViewElapsed

		if lndWallet.Database() != nil {
			b.Fatal("Store-backed wallet exposed a walletdb database")
		}
		fixture.close(b)
	}
	b.ReportMetric(float64(info.Size()), "bytes/file")
	b.ReportMetric(
		float64(openElapsed.Nanoseconds())/float64(b.N),
		"open-ns/op",
	)
	b.ReportMetric(
		float64(viewElapsed.Nanoseconds())/float64(b.N),
		"store-view-ns/op",
	)
}

// benchmarkSalvageControllerSync adds real-btcd full-block rows matching the
// role benchmark hierarchy. This candidate has no compact-filter controller.
func benchmarkSalvageControllerSync(b *testing.B) {
	for _, numBlocks := range []uint32{10, 100} {
		name := fmt.Sprintf("ControllerSync/Blocks-%d", numBlocks)
		b.Run(name, func(b *testing.B) {
			b.Run("FullBlocks", func(b *testing.B) {
				if os.Getenv("BTCWALLET_REAL_BTCD") != "1" {
					b.Skip("set BTCWALLET_REAL_BTCD=1 to run btcd")
				}

				benchmarkSalvageRealBTCDSync(b, numBlocks)
			})
		})
	}
}

// benchmarkSalvageRealBTCDSync times only synchronization from genesis to a
// pre-mined real-btcd tip, using a fresh SQLite wallet for every iteration.
func benchmarkSalvageRealBTCDSync(b *testing.B, numBlocks uint32) {
	b.StopTimer()
	params := &chaincfg.RegressionNetParams
	miner, err := rpctest.New(params, nil, nil, "")
	if err != nil {
		b.Fatalf("create btcd harness: %v", err)
	}
	if err := miner.SetUp(false, 0); err != nil {
		_ = miner.TearDown()
		b.Fatalf("start btcd harness: %v", err)
	}
	defer func() {
		if err := miner.TearDown(); err != nil {
			b.Errorf("tear down btcd harness: %v", err)
		}
	}()

	if _, err := miner.Client.Generate(numBlocks); err != nil {
		b.Fatalf("mine %d empty blocks: %v", numBlocks, err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fixture := newSalvageBenchmarkFixtureForParams(b, params)
		rpcConfig := miner.RPCConfig()
		client, err := chain.NewRPCClientWithConfig(&chain.RPCClientConfig{
			Conn:              &rpcConfig,
			Chain:             params,
			ReconnectAttempts: 3,
		})
		if err != nil {
			b.Fatalf("create btcd RPC client: %v", err)
		}
		if err := client.Start(b.Context()); err != nil {
			b.Fatalf("start btcd RPC client: %v", err)
		}

		b.StartTimer()
		fixture.wallet.SynchronizeRPC(client)
		deadline := time.Now().Add(30 * time.Second)
		for !fixture.wallet.ChainSynced() ||
			fixture.wallet.SyncedTo().Height != int32(numBlocks) {

			if time.Now().After(deadline) {
				b.StopTimer()
				b.Fatalf("wallet did not sync to height %d", numBlocks)
			}
			time.Sleep(time.Millisecond)
		}
		b.StopTimer()

		fixture.close(b)
	}
}

// newSalvageBenchmarkFixtureForParams creates a deterministic Store wallet for
// the real-btcd benchmark without allocating keys before synchronization.
func newSalvageBenchmarkFixtureForParams(b *testing.B,
	params *chaincfg.Params) *salvageBenchmarkFixture {

	b.Helper()
	dbPath := filepath.Join(b.TempDir(), "wallet.sqlite")
	conn, err := storesqlite.Open(context.Background(), storesqlite.Config{
		DBPath: dbPath,
	})
	if err != nil {
		b.Fatalf("open sync SQLite fixture: %v", err)
	}
	if err := storesqlite.ApplyMigrations(conn); err != nil {
		_ = conn.Close()
		b.Fatalf("apply sync SQLite migrations: %v", err)
	}

	store := dbsqlite.NewNamedStore(conn, salvageBenchmarkWalletName)
	loader, err := NewLoaderWithStore(params, 0, store)
	if err != nil {
		_ = conn.Close()
		b.Fatalf("create sync Store loader: %v", err)
	}
	wallet, err := loader.CreateNewWallet(
		[]byte(salvageBenchmarkPubPass),
		[]byte(salvageBenchmarkPrivPass), salvageBenchmarkSeed[:],
		params.GenesisBlock.Header.Timestamp,
	)
	if err != nil {
		_ = conn.Close()
		b.Fatalf("create sync SQLite wallet: %v", err)
	}

	fixture := &salvageBenchmarkFixture{
		dbPath: dbPath,
		conn:   conn,
		loader: loader,
		wallet: wallet,
	}
	b.Cleanup(func() {
		fixture.close(b)
	})

	return fixture
}
