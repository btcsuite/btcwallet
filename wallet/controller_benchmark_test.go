// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/chain/port"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

const (
	// benchBlocksToSync is the number of blocks to generate and sync during
	// the benchmark.
	benchBlocksToSync = 1000

	// benchTxsPerBlock is the total number of transactions per block
	// (hits + noise).
	benchTxsPerBlock = 100

	// testRecoveryWindow is the address lookahead window used during
	// benchmarks. A larger window ensures that the wallet can discover
	// addresses even if there are gaps in the address chain, which is essential
	// for realistic synchronization benchmarks.
	testRecoveryWindow = 100
)

// BenchmarkSyncEmpty benchmarks the wallet synchronization performance against
// empty blocks and an empty wallet by comparing the legacy SynchronizeRPC with
// the new Controller.Start API across different block depths.
func BenchmarkSyncEmpty(b *testing.B) {
	scenarios := []struct {
		blocks int
	}{
		{10},
		{100},
		{1000},
	}

	for _, s := range scenarios {
		name := fmt.Sprintf("Blocks-%d", s.blocks)
		b.Run(name, func(b *testing.B) {
			// Initialize a common miner for all sub-benchmarks in this
			// scenario.
			miner := setupChain(b, s.blocks)

			b.Run("Legacy", func(b *testing.B) {
				runLegacySync(b, miner)
			})

			b.Run("NewWithFullBlock", func(b *testing.B) {
				runNewSync(b, miner, SyncMethodFullBlocks)
			})

			b.Run("NewWithCFilter", func(b *testing.B) {
				runNewSync(b, miner, SyncMethodCFilters)
			})
		})
	}
}

// BenchmarkSyncData benchmarks the wallet synchronization performance against
// blocks with data and a populated wallet. It compares Legacy vs New APIs
// across different wallet sizes (number of accounts/addresses).
func BenchmarkSyncData(b *testing.B) {
	scenarios := []struct {
		addrs    int
		numUTXOs int
	}{
		// Case 1: Sparse Discovery Stress Test.
		// 100 total addresses, but only 1 UTXO sent to the 100th address
		// (index 99). The hit is delivered at block 500.
		// Density: 1 hit per 1000 blocks (0.1%).
		// Intent: Tests how the wallet handles a nearly empty history where
		// it must scan far into the chain and its lookahead window to find
		// a single isolated transaction.
		{addrs: 100, numUTXOs: 1},

		// Case 2: Periodic Discovery Stress Test.
		// 100 total addresses, with 10 UTXOs sent to every 10th address
		// (index 9, 19, ... 99). Hits are delivered every 100 blocks.
		// Density: 1 hit per 100 blocks (1%).
		// Intent: Tests incremental discovery and sequential rescan logic
		// as the wallet regularly finds hits and must decide whether to
		// expand its search window.
		{addrs: 100, numUTXOs: 10},

		// Case 3: Dense Sync Throughput Test.
		// 100 total addresses, with 100 UTXOs sent to every address.
		// Hits are delivered every 10 blocks.
		// Density: 1 hit per 10 blocks (10%).
		// Intent: Tests the raw throughput of the transaction indexing and
		// block processing logic when relevant data appears frequently.
		{addrs: 100, numUTXOs: 100},
	}

	for _, s := range scenarios {
		density := float64(s.numUTXOs) / float64(benchBlocksToSync)
		name := fmt.Sprintf("UTXODensity-%.3f", density)

		b.Run(name, func(b *testing.B) {
			seed, err := hdkeychain.GenerateSeed(hdkeychain.MinSeedBytes)
			require.NoError(b, err)

			// Setup common miner and populate it with wallet-destined data.
			// Always use 1 account.
			miner := setupChainWithWalletData(
				b, seed, s.addrs, s.numUTXOs,
			)

			b.ResetTimer()

			b.Run("Legacy", func(b *testing.B) {
				runLegacySyncData(b, miner, seed, s.numUTXOs)
			})

			b.Run("NewWithFullBlock", func(b *testing.B) {
				runNewSyncData(
					b, miner, seed, SyncMethodFullBlocks, s.numUTXOs,
				)
			})

			b.Run("NewWithCFilter", func(b *testing.B) {
				runNewSyncData(
					b, miner, seed, SyncMethodCFilters, s.numUTXOs,
				)
			})
		})
	}
}

// startProfiling begins CPU profiling if the profileName is not empty. It
// returns a cleanup function that must be called to stop profiling.
func startProfiling(tb testing.TB) func() {
	tb.Helper()

	// We use the test name to generate a unique profile filename for each
	// benchmark case. Slashes are replaced with underscores to ensure a
	// valid filename.
	name := strings.ReplaceAll(tb.Name(), "/", "_") + ".prof"

	f, err := os.Create(name)
	require.NoError(tb, err)

	err = pprof.StartCPUProfile(f)
	require.NoError(tb, err)

	return func() {
		pprof.StopCPUProfile()
		require.NoError(tb, f.Close())
	}
}

// runLegacySync executes the legacy synchronization benchmark loop.
func runLegacySync(b *testing.B, miner *rpctest.Harness) {
	b.Helper()

	for b.Loop() {
		b.StopTimer()

		// Setup a fresh legacy wallet for each iteration.
		seed, err := hdkeychain.GenerateSeed(hdkeychain.MinSeedBytes)
		require.NoError(b, err)
		w := setupLegacyWallet(b, seed)

		// Connect a fresh chain client.
		chainClient := setupChainClient(b, miner)

		stopProfile := startProfiling(b)

		b.StartTimer()

		// Start legacy sync process.
		w.StartDeprecated()
		w.SynchronizeRPC(chainClient)

		// Poll until the wallet reports it is synced.
		for !w.ChainSynced() {
			time.Sleep(5 * time.Millisecond)
		}

		stopProfile()
	}
}

// runLegacySyncData executes the legacy synchronization benchmark loop
// with data.
func runLegacySyncData(b *testing.B, miner *rpctest.Harness, seed []byte,
	expectedUTXOs int) {

	b.Helper()

	for b.Loop() {
		// Stop the timer to exclude expensive setup operations (like
		// creating the wallet database and accounts) from the measured
		// sync time.
		b.StopTimer()

		// Setup a fresh legacy wallet.
		w := setupLegacyWallet(b, seed)

		// Connect a fresh chain client (Bitcoind).
		chainClient := setupChainClient(b, miner)

		stopProfile := startProfiling(b)

		// Start the timer for the actual synchronization phase.
		b.StartTimer()

		// Start legacy sync process.
		w.StartDeprecated()

		w.SynchronizeRPC(chainClient)

		// Poll until the wallet reports it is synced.
		for !w.ChainSynced() {
			time.Sleep(100 * time.Millisecond)
		}

		// Stop the timer to exclude verification.
		b.StopTimer()

		stopProfile()

		// Verify UTXO count using high-level method.
		assertUTXOCountDeprecated(b, w, expectedUTXOs)

		// Restart timer for loop accounting.
		b.StartTimer()
	}
}

// runNewSync executes the modern Controller synchronization benchmark loop.
func runNewSync(b *testing.B, miner *rpctest.Harness, method SyncMethod) {
	b.Helper()

	for b.Loop() {
		b.StopTimer()

		// Connect a fresh chain client.
		chainClient := setupChainClient(b, miner)

		// Configure for the specified sync mode.
		cfg := defaultWalletConfig(b)
		cfg.Chain = chainClient
		cfg.SyncMethod = method

		// Setup a fresh modern wallet.
		seed, err := hdkeychain.GenerateSeed(hdkeychain.MinSeedBytes)
		require.NoError(b, err)
		w := setupNewWallet(b, seed, cfg)

		stopProfile := startProfiling(b)

		b.StartTimer()

		// Start modern controller and syncing.
		err = w.Start(b.Context())
		require.NoError(b, err)

		// Poll until the controller reports it is synced.
		//
		// NOTE: We use w.Info() here to poll for the synced status. This is a
		// heavier operation than the legacy mutex-protected boolean read,
		// making the observed performance gains even more significant as they
		// include this additional status-check overhead.
		for {
			info, err := w.Info(b.Context())
			require.NoError(b, err)

			if info.Synced {
				break
			}

			time.Sleep(5 * time.Millisecond)
		}

		stopProfile()
	}
}

// runNewSyncData executes the modern Controller synchronization benchmark loop
// with data.
func runNewSyncData(b *testing.B, miner *rpctest.Harness, seed []byte,
	method SyncMethod, expectedUTXOs int) {

	b.Helper()

	for b.Loop() {
		// Stop the timer to exclude expensive setup operations (like
		// creating the wallet database and accounts) from the measured
		// sync time.
		b.StopTimer()

		chainClient := setupChainClient(b, miner)
		cfg := defaultWalletConfig(b)
		cfg.Chain = chainClient
		cfg.SyncMethod = method

		w := setupNewWallet(b, seed, cfg)

		stopProfile := startProfiling(b)

		// Start the timer for the actual synchronization phase.
		b.StartTimer()

		// Start modern controller and syncing.
		err := w.Start(b.Context())
		require.NoError(b, err)

		// Poll until the controller reports it is synced.
		for {
			info, err := w.Info(b.Context())
			require.NoError(b, err)

			if info.Synced {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}

		// Stop the timer to exclude verification.
		b.StopTimer()

		stopProfile()

		// Verify UTXO count using high-level method.
		assertUTXOCount(b, w, expectedUTXOs)

		// Restart timer for loop accounting.
		b.StartTimer()
	}
}

// setupLegacyWallet initializes a legacy wallet for benchmarking. It
// automatically registers resource cleanup.
func setupLegacyWallet(tb testing.TB, seed []byte) *Wallet {
	tb.Helper()

	// Initialize temporary database directory and standard test credentials.
	dir := tb.TempDir()
	pubPass := []byte("public")
	privPass := []byte("private")

	// Create the wallet using the legacy Loader.
	loader := NewLoader(
		&chaincfg.RegressionNetParams, dir, true, 10*time.Second,
		testRecoveryWindow,
		WithWalletSyncRetryInterval(10*time.Millisecond),
	)

	// Use an old birthday to ensure the wallet rescans past blocks.
	birthday := time.Now().Add(-48 * time.Hour)
	w, err := loader.CreateNewWallet(pubPass, privPass, seed, birthday)
	require.NoError(tb, err)

	// Register cleanup function to ensure all legacy background processes are
	// stopped and the database is correctly closed after the benchmark subtest.
	tb.Cleanup(func() {
		w.StopDeprecated()
		w.WaitForShutdown()

		if val := w.Database(); val != nil {
			require.NoError(tb, val.Close())
		}
	})

	return w
}

// setupNewWallet initializes a modern wallet using the Manager API. It accepts
// a Config which should at least have the Chain client populated. It
// automatically registers resource cleanup.
func setupNewWallet(tb testing.TB, seed []byte, cfg Config) *Wallet {
	tb.Helper()

	privPass := []byte("private")
	params := CreateWalletParams{
		Mode:              ModeImportSeed,
		Seed:              seed,
		PrivatePassphrase: privPass,
		PubPassphrase:     cfg.PubPassphrase,
		Birthday:          time.Now().Add(-48 * time.Hour),
	}

	// Create the wallet using the new Manager API. This returns a loaded
	// but unstarted wallet instance.
	manager := NewManager()
	w, err := manager.Create(cfg, params)
	require.NoError(tb, err)

	// Register cleanup function to handle the Controller shutdown and close
	// the database handle after the benchmark subtest.
	tb.Cleanup(func() {
		_ = w.Stop(tb.Context())
		require.NoError(tb, w.closeRuntimeStore())
	})

	return w
}

// setupChain prepares a btcd node and generates the required blocks.
func setupChain(tb testing.TB, blocks int) *rpctest.Harness {
	tb.Helper()

	args := []string{
		"--txindex",
		"--minrelaytxfee=0.00000001", // 1 sat/kb
	}
	miner, err := rpctest.New(&chaincfg.RegressionNetParams, nil, args, "")
	require.NoError(tb, err)
	require.NoError(tb, miner.SetUp(true, uint32(blocks)))

	// Generate the requested number of empty blocks.
	if blocks > 0 {
		_, err := miner.Client.Generate(uint32(blocks))
		require.NoError(tb, err)
	}

	tb.Cleanup(func() {
		require.NoError(tb, miner.TearDown())
	})

	return miner
}

// setupChainWithWalletData prepares a miner and populates the blockchain with
// transactions destined for a wallet derived from the provided seed. This
// establishes a realistic environment for benchmarking synchronization.
func setupChainWithWalletData(tb testing.TB, seed []byte,
	addrsPerAccount, numUTXOs int) *rpctest.Harness {

	tb.Helper()

	// Initialize common miner.
	miner := setupChain(tb, 0)

	// 1. Setup a template wallet to extract addresses for the chain.
	cfg := defaultWalletConfig(tb)
	cfg.Chain = setupChainClient(tb, miner)

	templateW := setupNewWallet(tb, seed, cfg)

	err := templateW.Start(tb.Context())
	require.NoError(tb, err)

	// Unlock template wallet to derive addresses.
	err = templateW.Unlock(tb.Context(), UnlockRequest{
		Passphrase: []byte("private"),
	})
	require.NoError(tb, err)

	// Manually derive addresses for the template wallet.
	var targetAddrs []address.Address

	// Calculate chunk for selecting target addresses.
	// Total addresses = addrsPerAccount (since 1 account).
	// We want to pick 'numUTXOs' targets.
	// Stride = Total / numUTXOs.
	chunk := addrsPerAccount / numUTXOs

	accountName := waddrmgr.DefaultAccountName
	for i := range addrsPerAccount {
		addr, err := templateW.NewAddress(tb.Context(),
			accountName, waddrmgr.WitnessPubKey, false)
		require.NoError(tb, err)

		// Select target addresses based on the calculated chunk.
		// For example, if we have 100 addresses and need 10 UTXOs, we pick
		// every 10th address (index 9, 19, ... 99). This ensures the wallet
		// must scan through gaps to find all hits, stressing the recovery
		// and discovery logic.
		targetIdx := (len(targetAddrs)+1)*chunk - 1
		if i == targetIdx {
			targetAddrs = append(targetAddrs, addr)
		}
	}

	// Close the template wallet now that we are done with it. This releases
	// the database lock and resources.
	_ = templateW.Stop(tb.Context())
	require.NoError(tb, templateW.closeRuntimeStore())

	// Ensure we selected the correct number of targets.
	require.Len(tb, targetAddrs, numUTXOs,
		"failed to select target addresses")

	// Pre-mine 200 blocks to ensure the miner has a sufficient balance of
	// mature coinbase outputs. In Bitcoin, coinbase outputs cannot be spent
	// until they have reached a depth of 100 blocks (maturity). Pre-mining 200
	// blocks ensures that the miner can immediately begin sending transactions
	// to the wallet during the setup phase.
	_, err = miner.Client.Generate(200)
	require.NoError(tb, err)

	// 2. Setup the chain based on the scenario (numUTXOs).
	switch numUTXOs {
	case 1:
		setupChainCase1(tb, miner, targetAddrs)

	case 10:
		setupChainCase2(tb, miner, targetAddrs)

	case 100:
		setupChainCase3(tb, miner, targetAddrs)

	default:
		tb.Fatalf("Unsupported numUTXOs: %d", numUTXOs)
	}

	return miner
}

// setupChainCase1 mines 1000 blocks and sends exactly 1 UTXO to the wallet at
// the 500th block. This scenario tests how the wallet handles a sparse history
// and whether it can correctly recover from a birthday that predates a single,
// isolated transaction.
func setupChainCase1(tb testing.TB, miner *rpctest.Harness,
	targetAddrs []address.Address) {

	tb.Helper()
	require.Len(tb, targetAddrs, 1)

	var err error

	// Iterate through 1000 blocks. We want the wallet to find its single UTXO
	// midway through the scan.
	for i := range benchBlocksToSync {
		// Send the single UTXO to the wallet at block 500.
		if i == 500 {
			var pkScript []byte

			pkScript, err = txscript.PayToAddrScript(targetAddrs[0])
			require.NoError(tb, err)

			_, err = miner.SendOutputs([]*wire.TxOut{
				{Value: 1000, PkScript: pkScript},
			}, 1)
			require.NoError(tb, err)
		}

		// Fill the block with 100 noise transactions to simulate a realistic
		// mainnet-like environment where the wallet must filter through
		// many irrelevant transactions.
		noiseCount := benchTxsPerBlock
		if i == 500 {
			noiseCount--
		}

		generateNonWalletTxns(tb, miner, noiseCount)

		// Mine the block.
		_, err = miner.Client.Generate(1)
		require.NoError(tb, err)
	}
}

// setupChainCase2 mines 1000 blocks and sends 1 UTXO to the wallet every 100
// blocks, for a total of 10 UTXOs. This scenario tests the wallet's ability
// to handle incremental discovery and sequential rescans as it finds hits
// distributed regularly across the chain.
func setupChainCase2(tb testing.TB, miner *rpctest.Harness,
	targetAddrs []address.Address) {

	tb.Helper()
	require.Len(tb, targetAddrs, 10)

	var err error

	targetIdx := 0
	for i := range benchBlocksToSync {
		// Determine if this block is a hit (every 100th block). This creates
		// a periodic matching pattern that triggers incremental discovery
		// as the wallet reaches the end of its lookahead window.
		isHit := (i+1)%100 == 0

		if isHit {
			// Pop the next target address and generate a script that pays
			// to it.
			var pkScript []byte

			pkScript, err = txscript.PayToAddrScript(targetAddrs[targetIdx])
			require.NoError(tb, err)

			targetIdx++

			// Send the wallet payment.
			_, err = miner.SendOutputs([]*wire.TxOut{
				{Value: 1000, PkScript: pkScript},
			}, 1)
			require.NoError(tb, err)
		}

		// Add noise transactions to fill the block to 100 total outputs. This
		// ensures the wallet must filter through a realistic amount of
		// irrelevant data in every block.
		noiseCount := benchTxsPerBlock
		if isHit {
			noiseCount--
		}

		generateNonWalletTxns(tb, miner, noiseCount)

		// Mine the block.
		_, err = miner.Client.Generate(1)
		require.NoError(tb, err)
	}
}

// setupChainCase3 mines 1000 blocks and sends 1 UTXO to the wallet every 10
// blocks, for a total of 100 UTXOs. This is a "dense" scenario that
// stresses the wallet's block processing and transaction indexing performance
// when relevant data appears frequently.
func setupChainCase3(tb testing.TB, miner *rpctest.Harness,
	targetAddrs []address.Address) {

	tb.Helper()
	require.Len(tb, targetAddrs, 100)

	var err error

	targetIdx := 0
	for i := range benchBlocksToSync {
		// Determine if this block is a hit (every 10th block).
		isHit := (i+1)%10 == 0

		if isHit {
			// Pop the next target address and generate a script that pays
			// to it.
			var pkScript []byte

			pkScript, err = txscript.PayToAddrScript(targetAddrs[targetIdx])
			require.NoError(tb, err)

			targetIdx++

			// Send the wallet payment.
			_, err = miner.SendOutputs([]*wire.TxOut{
				{Value: 1000, PkScript: pkScript},
			}, 1)
			require.NoError(tb, err)
		}

		// Add noise transactions to reach the 100 txs/block target. This
		// maintains a constant transaction density across all scenarios.
		noiseCount := benchTxsPerBlock
		if isHit {
			noiseCount--
		}

		generateNonWalletTxns(tb, miner, noiseCount)

		// Mine the block.
		_, err = miner.Client.Generate(1)
		require.NoError(tb, err)
	}
}

// generateNonWalletTxns creates 'count' random transactions.
func generateNonWalletTxns(tb testing.TB, miner *rpctest.Harness, count int) {
	tb.Helper()

	outputs := make([]*wire.TxOut, 0, count)
	for range count {
		mAddr, err := miner.NewAddress()
		require.NoError(tb, err)
		pkScript, err := txscript.PayToAddrScript(mAddr)
		require.NoError(tb, err)

		outputs = append(outputs, &wire.TxOut{Value: 1000, PkScript: pkScript})
	}

	_, err := miner.SendOutputs(outputs, 1)
	require.NoError(tb, err)
}

// setupChainClient initializes and starts a new bitcoind client connection to
// the provided chain backend. It automatically registers resource cleanup.
func setupChainClient(tb testing.TB, miner *rpctest.Harness) chain.Interface {
	tb.Helper()

	// Start a bitcoind instance and connect it to miner.
	tempBitcoindDir := tb.TempDir()

	zmqBlockPort := port.NextAvailablePort()
	zmqTxPort := port.NextAvailablePort()

	zmqBlockHost := fmt.Sprintf("tcp://127.0.0.1:%d", zmqBlockPort)
	zmqTxHost := fmt.Sprintf("tcp://127.0.0.1:%d", zmqTxPort)

	rpcPort := port.NextAvailablePort()
	p2pPort := port.NextAvailablePort()
	minerAddr := miner.P2PAddress()

	ctx, cancel := context.WithCancel(context.Background())
	tb.Cleanup(cancel)

	bitcoind := exec.CommandContext(
		ctx,
		"bitcoind",
		"-datadir="+tempBitcoindDir,
		"-regtest",
		"-connect="+minerAddr,
		"-txindex",
		"-rpcauth=weks:469e9bb14ab2360f8e226efed5ca6f"+
			"d$507c670e800a95284294edb5773b05544b"+
			"220110063096c221be9933c82d38e1",
		fmt.Sprintf("-rpcport=%d", rpcPort),
		fmt.Sprintf("-port=%d", p2pPort),
		"-disablewallet",
		"-zmqpubrawblock="+zmqBlockHost,
		"-zmqpubrawtx="+zmqTxHost,
		"-blockfilterindex=1",
	)
	require.NoError(tb, bitcoind.Start())

	tb.Cleanup(func() {
		_ = bitcoind.Process.Kill()
		_ = bitcoind.Wait()
	})

	// Wait for the bitcoind instance to start up.
	time.Sleep(time.Second)

	host := fmt.Sprintf("127.0.0.1:%d", rpcPort)
	cfg := &chain.BitcoindConfig{
		ChainParams: &chaincfg.RegressionNetParams,
		Host:        host,
		User:        "weks",
		Pass:        "weks",
		ZMQConfig: &chain.ZMQConfig{
			ZMQBlockHost:           zmqBlockHost,
			ZMQTxHost:              zmqTxHost,
			ZMQReadDeadline:        5 * time.Second,
			MempoolPollingInterval: time.Millisecond * 100,
		},
	}

	chainConn, err := chain.NewBitcoindConn(cfg)
	require.NoError(tb, err)
	require.NoError(tb, chainConn.Start())

	tb.Cleanup(func() {
		chainConn.Stop()
	})

	// Create a bitcoind client.
	btcClient, err := chainConn.NewBitcoindClient()
	require.NoError(tb, err)
	require.NoError(tb, btcClient.Start(tb.Context()))

	tb.Cleanup(func() {
		btcClient.Stop()
	})

	// Wait for bitcoind to sync with the miner.
	// We want to ensure it has synced at least to the miner's tip.
	require.Eventually(tb, func() bool {
		_, height, err := btcClient.GetBestBlock()
		if err != nil {
			return false
		}

		_, minerHeight, _ := miner.Client.GetBestBlock()

		return height >= minerHeight
	}, 30*time.Second, 100*time.Millisecond)

	return btcClient
}

// defaultWalletConfig returns a Config with standard benchmark settings.
func defaultWalletConfig(tb testing.TB) Config {
	tb.Helper()

	return Config{
		DB: DBConfig{
			// Pin the kvdb backend: these benchmarks exercise the
			// legacy kvdb runtime store, while the default backend
			// is now SQLite.
			Backend: DBBackendKVDB,
			KVDB: KVDBConfig{
				DBPath:         filepath.Join(tb.TempDir(), "wallet.db"),
				NoFreelistSync: true,
				Timeout:        10 * time.Second,
			},
		},
		ChainParams:             &chaincfg.RegressionNetParams,
		Name:                    "bench-wallet",
		PubPassphrase:           []byte("public"),
		WalletSyncRetryInterval: 10 * time.Millisecond,
		RecoveryWindow:          testRecoveryWindow,
	}
}

// assertUTXOCount verifies the number of unspent outputs in a modern wallet.
func assertUTXOCount(b *testing.B, w *Wallet, expected int) {
	b.Helper()

	require.Eventually(b, func() bool {
		utxos, err := w.ListUnspent(b.Context(), UtxoQuery{
			MinConfs: 0,
			MaxConfs: 99999,
		})
		require.NoError(b, err)

		return len(utxos) == expected
	}, 20*time.Second, 100*time.Millisecond, "new wallet utxo count mismatch")
}

// assertUTXOCountDeprecated verifies the number of unspent outputs in a legacy
// wallet.
func assertUTXOCountDeprecated(b *testing.B, w *Wallet, expected int) {
	b.Helper()

	require.Eventually(b, func() bool {
		utxos, err := w.ListUnspentDeprecated(0, 999999, "")
		require.NoError(b, err)

		return len(utxos) == expected
	}, 20*time.Second, 100*time.Millisecond,
		"legacy wallet utxo count mismatch")
}
