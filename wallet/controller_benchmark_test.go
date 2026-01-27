// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wallet

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/stretchr/testify/require"
)

// testRecoveryWindow is the address lookahead window used during benchmarks.
// A larger window ensures that the wallet can discover addresses even if there
// are gaps in the address chain, which is essential for realistic
// synchronization benchmarks.
const testRecoveryWindow = 100

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

		b.StartTimer()

		// Start legacy sync process.
		w.StartDeprecated()
		w.SynchronizeRPC(chainClient)

		// Poll until the wallet reports it is synced.
		for !w.ChainSynced() {
			time.Sleep(5 * time.Millisecond)
		}
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
		cfg := Config{
			Chain:      chainClient,
			SyncMethod: method,
		}

		// Setup a fresh modern wallet.
		seed, err := hdkeychain.GenerateSeed(hdkeychain.MinSeedBytes)
		require.NoError(b, err)
		w := setupNewWallet(b, seed, cfg)

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

	// Unconditionally initialize mandatory fields for the benchmark setup.
	if cfg.DB == nil {
		dir := tb.TempDir()
		dbPath := filepath.Join(dir, "wallet.db")
		db, err := walletdb.Create("bdb", dbPath, true, 10*time.Second, false)
		require.NoError(tb, err)
		cfg.DB = db
	}

	cfg.ChainParams = &chaincfg.RegressionNetParams
	cfg.Name = "new-bench-wallet"
	cfg.PubPassphrase = []byte("public")
	cfg.WalletSyncRetryInterval = 10 * time.Millisecond
	cfg.RecoveryWindow = testRecoveryWindow

	privPass := []byte("private")
	params := CreateWalletParams{
		Mode:              ModeGenSeed,
		Seed:              seed,
		PrivatePassphrase: privPass,
		PubPassphrase:     cfg.PubPassphrase,
		Birthday:          time.Now().Add(-48 * time.Hour),
	}

	// Override params if seed is provided (for SyncData).
	if seed != nil {
		params.Mode = ModeImportSeed
		params.Seed = seed
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
		require.NoError(tb, w.cfg.DB.Close())
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

// setupChainClient initializes and starts a new RPC client connection to the
// provided chain backend. It automatically registers resource cleanup.
func setupChainClient(tb testing.TB, miner *rpctest.Harness) chain.Interface {
	tb.Helper()

	rpcConf := miner.RPCConfig()
	cfg := &chain.RPCClientConfig{
		ReconnectAttempts: 1,
		Chain:             &chaincfg.RegressionNetParams,
		Conn: &rpcclient.ConnConfig{
			Host:         rpcConf.Host,
			User:         rpcConf.User,
			Pass:         rpcConf.Pass,
			Certificates: rpcConf.Certificates,
			DisableTLS:   false,
			Endpoint:     "ws",
		},
	}
	c, err := chain.NewRPCClientWithConfig(cfg)
	require.NoError(tb, err)

	err = c.Start(tb.Context())
	require.NoError(tb, err)

	// Ensure the client is fully synced to the miner's tip.
	require.Eventually(tb, func() bool {
		_, height, err := c.GetBestBlock()
		require.NoError(tb, err)

		_, bestHeight, err := miner.Client.GetBestBlock()
		require.NoError(tb, err)

		return height == bestHeight
	}, 5*time.Second, 50*time.Millisecond, "chain client failed to sync")

	// Register cleanup to ensure the connection is closed after the benchmark
	// subtest.
	tb.Cleanup(c.Stop)

	return c
}
