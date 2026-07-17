// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build test_chain_btcd

// Package sqlwallet's btcd recovery integration test (Stage 3 Phase 3c, the
// Gate-2 recovery vertical). It drives the Phase 3b Syncer against a real btcd
// regtest node through a live chain.RPCClient — the exact production chain
// backend — rather than the deterministic mock used by recovery_test.go, so it
// proves the ChainSource abstraction and the scan/commit contract hold against
// real blocks, real compact-filter FilterBlocks, and a real reorg.
//
// It is gated behind the test_chain_btcd build tag (matching the repo's
// test_db_postgres itest-tag convention) so the default unit-test run neither
// compiles it nor spawns a btcd process. Run it with:
//
//	GOWORK=off go test -tags test_chain_btcd ./wallet/internal/sqlwallet/
//
// rpctest compiles the module's pinned btcd (v0.26.0) on demand, so the node
// under test matches the chain.RPCClient it is driven through.
package sqlwallet

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/integration/rpctest"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

const (
	// numMatureOutputs is the number of mature coinbase outputs the btcd
	// miner is set up with, one per funding transaction the tests spend, plus
	// headroom. Each funding transaction locks a distinct mature output, so
	// consecutive sends never depend on an unconfirmed change output.
	numMatureOutputs = 5

	// itestRecoveryWindow is the address-derivation lookahead the recovery
	// scans use. It is deliberately small so a funded index beyond it is only
	// reached by progressive horizon widening, exercising the gap-limit path.
	itestRecoveryWindow uint32 = 3

	// itestBatchSize is the number of blocks committed per scan batch. It is
	// smaller than the mined chain height so the recovery spans several
	// batches, most of them empty of wallet funds.
	itestBatchSize uint32 = 50

	// itestFeeRate is the sat/byte fee rate the miner funds outputs at.
	itestFeeRate btcutil.Amount = 10
)

// regtestParams is the network the btcd itest wallet and miner both run on. A
// regtest wallet's genesis block equals the btcd node's genesis, so the syncer
// reconciles against the same chain the wallet was created for.
var regtestParams = &chaincfg.RegressionNetParams

// newBtcdMiner starts a btcd regtest node with a pre-mined chain carrying
// numMatureOutputs mature coinbase outputs, registers its teardown, and returns
// the harness. rpctest compiles the module's btcd on first use.
func newBtcdMiner(t *testing.T) *rpctest.Harness {
	t.Helper()

	// A short trickle interval propagates transactions to the node's mempool
	// promptly so a following Generate confirms them.
	args := []string{"--trickleinterval=" + (10 * time.Millisecond).String()}
	miner, err := rpctest.New(regtestParams, nil, args, "")
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, miner.TearDown())
	})

	require.NoError(t, miner.SetUp(true, numMatureOutputs))

	return miner
}

// newBtcdChainSource connects a live chain.RPCClient to the miner's RPC
// interface and returns it as the recovery scan's ChainSource. It drains the
// client's notification channel in the background (the chain.Interface contract
// requires the channel be read) with a shutdown path bound to the client's
// Stop, and registers the client's teardown.
func newBtcdChainSource(t *testing.T, miner *rpctest.Harness) *chain.RPCClient {
	t.Helper()

	rpcCfg := miner.RPCConfig()
	client, err := chain.NewRPCClient(
		regtestParams, rpcCfg.Host, rpcCfg.User, rpcCfg.Pass,
		rpcCfg.Certificates, false, 5,
	)
	require.NoError(t, err)
	require.NoError(t, client.Start(context.Background()))

	t.Cleanup(func() {
		client.Stop()
		client.WaitForShutdown()
	})

	// Drain notifications so the client's handler goroutine is never wedged
	// delivering the connect notification. The range exits when Stop closes
	// the channel, so the goroutine has a clean shutdown path.
	go func() {
		for range client.Notifications() {
		}
	}()

	return client
}

// createBtcdWallet creates a fresh SQL wallet over a new SQLite file in dir,
// using the fixed lifecycle seed but regtest params, so its derivations match
// regtestExternalAddrs and its genesis matches the btcd node.
func createBtcdWallet(t *testing.T, dir string) (*SQLLoader, *SQLWallet) {
	t.Helper()

	loader, err := NewSQLLoader(SQLConfig{
		DBPath: filepath.Join(dir, "wallet.db"),
		Params: regtestParams,
		Scrypt: &waddrmgr.FastScryptOptions,
	})
	require.NoError(t, err)

	wallet, err := loader.CreateWallet(context.Background(), CreateParams{
		Name:           lifecycleWalletName,
		RootKey:        regtestRootKey(t),
		PubPassphrase:  lifecyclePubPass,
		PrivPassphrase: lifecyclePrivPass,
		Scopes:         []waddrmgr.KeyScope{lifecycleScope},
	}, nil)
	require.NoError(t, err)

	return loader, wallet
}

// regtestRootKey returns the deterministic wallet root key for regtest. Child
// derivation is network-independent, so the addresses share the underlying
// public-key hashes with the mainnet lifecycle tests; only the encoding differs.
func regtestRootKey(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()

	root, err := hdkeychain.NewMaster(lifecycleSeed, regtestParams)
	require.NoError(t, err)

	return root
}

// regtestExternalAddrs derives the wallet's first count external addresses from
// the deterministic seed under regtest params, so a test knows the exact scripts
// to fund, sharing no state with the wallet.
func regtestExternalAddrs(t *testing.T, count uint32) []waddrmgr.DerivedAddress {
	t.Helper()

	root := regtestRootKey(t)
	acctKey := deriveExpectedAccountKey(t, root, lifecycleScope)
	defer acctKey.Zero()

	derived, _, err := waddrmgr.DeriveChainedAddresses(
		acctKey, waddrmgr.ExternalBranch, waddrmgr.WitnessPubKey,
		regtestParams, 0, count,
	)
	require.NoError(t, err)

	return derived
}

// fundAddr sends value satoshis to addr from the miner's wallet and confirms it
// in a freshly mined block, so the address is funded on the best chain.
func fundAddr(t *testing.T, miner *rpctest.Harness, addr address.Address,
	value int64) {

	t.Helper()

	script, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	_, err = miner.SendOutputs(
		[]*wire.TxOut{{Value: value, PkScript: script}}, itestFeeRate,
	)
	require.NoError(t, err)

	mineBlocks(t, miner, 1)
}

// mineBlocks mines n blocks on the miner and returns nothing; it is used to
// confirm funding transactions and to extend the chain.
func mineBlocks(t *testing.T, miner *rpctest.Harness, n uint32) {
	t.Helper()

	_, err := miner.Client.Generate(n)
	require.NoError(t, err)
}

// newBtcdSyncer builds a recovery syncer over the given chain source with the
// itest recovery window and batch size.
func newBtcdSyncer(t *testing.T, wallet *SQLWallet,
	chainSrc ChainSource) *Syncer {

	t.Helper()

	syncer, err := wallet.NewSyncer(SyncerConfig{
		Chain:          chainSrc,
		RecoveryWindow: itestRecoveryWindow,
		BatchSize:      itestBatchSize,
	})
	require.NoError(t, err)

	return syncer
}

// TestBtcdRecoversPrefundedSeed is the Gate-2 recovery vertical over real btcd:
// a seed pre-funded at external indexes 0, 2, and 5 (index 5 beyond the initial
// lookahead window) recovers all of its funds over SQLite by scanning a real
// regtest chain through a live chain.RPCClient, with the balance, unspent set,
// synced tip, branch index, and discovered addresses all correct.
func TestBtcdRecoversPrefundedSeed(t *testing.T) {
	ctx := context.Background()
	miner := newBtcdMiner(t)
	chainSrc := newBtcdChainSource(t, miner)

	_, wallet := createBtcdWallet(t, t.TempDir())
	defer func() { require.NoError(t, wallet.Close()) }()

	// Fund external indexes 0, 2, and 5 in ascending blocks. With a recovery
	// window of 3, index 5 is beyond the initial horizon and is only reached
	// because each on-chain find widens the lookahead.
	addrs := regtestExternalAddrs(t, 8)
	fundAddr(t, miner, addrs[0].Address, 100_000)
	fundAddr(t, miner, addrs[2].Address, 30_000)
	fundAddr(t, miner, addrs[5].Address, 20_000)

	_, best, err := chainSrc.GetBestBlock()
	require.NoError(t, err)

	syncer := newBtcdSyncer(t, wallet, chainSrc)
	require.NoError(t, syncer.Recover(ctx))

	// All funds recovered over SQLite from the real chain.
	require.Equal(t, int64(150_000), durableBalance(t, wallet, best))
	require.Len(t, durableUnspent(t, wallet), 3)

	// The synced tip advanced to the chain tip.
	require.Equal(t, best, durableTip(t, wallet).Height)
	bestHash, err := chainSrc.GetBlockHash(int64(best))
	require.NoError(t, err)
	require.Equal(t, *bestHash, durableTip(t, wallet).Hash)

	// The branch advanced to one past the highest found index (5), the
	// last-unused index, and every address up to it was persisted.
	require.Equal(t, uint32(6), externalIndex(t, wallet))
	persisted := durableAddresses(
		t, wallet, lifecycleScope, waddrmgr.DefaultAccountNum,
	)
	indexes := make(map[uint32]struct{})
	for _, addr := range persisted {
		require.NotNil(t, addr.Index)
		indexes[*addr.Index] = struct{}{}
	}
	for i := uint32(0); i <= 5; i++ {
		require.Contains(t, indexes, i)
	}
}

// TestBtcdRecoveryRestartResume proves the recovered state survives a restart
// over real btcd: after recovering, the wallet is closed and reopened, its
// synced tip is reconstructed from durable state, and a re-Recover with no new
// blocks is a clean no-op that rescans nothing and leaves the balance, tip, and
// branch index unchanged.
func TestBtcdRecoveryRestartResume(t *testing.T) {
	ctx := context.Background()
	miner := newBtcdMiner(t)
	chainSrc := newBtcdChainSource(t, miner)

	loader, wallet := createBtcdWallet(t, t.TempDir())

	addrs := regtestExternalAddrs(t, 6)
	fundAddr(t, miner, addrs[0].Address, 120_000)
	fundAddr(t, miner, addrs[2].Address, 40_000)

	_, best, err := chainSrc.GetBestBlock()
	require.NoError(t, err)

	syncer := newBtcdSyncer(t, wallet, chainSrc)
	require.NoError(t, syncer.Recover(ctx))

	balanceBefore := durableBalance(t, wallet, best)
	require.Equal(t, int64(160_000), balanceBefore)
	require.Equal(t, uint32(3), externalIndex(t, wallet))

	tipBefore := durableTip(t, wallet)
	countBefore := len(durableAddresses(
		t, wallet, lifecycleScope, waddrmgr.DefaultAccountNum,
	))
	require.NoError(t, wallet.Close())

	// Reopen the wallet: the synced tip is reconstructed from durable state
	// before any further operation.
	reopened, err := loader.OpenWallet(ctx, OpenParams{
		Name:          lifecycleWalletName,
		PubPassphrase: lifecyclePubPass,
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, reopened.Close()) }()

	require.Equal(t, tipBefore, durableTip(t, reopened))

	// Recover again with no new blocks: it resumes from the durable tip, so
	// nothing is scanned, re-derived, or re-committed.
	resumed := newBtcdSyncer(t, reopened, chainSrc)
	require.NoError(t, resumed.Recover(ctx))

	require.Equal(t, balanceBefore, durableBalance(t, reopened, best))
	require.Equal(t, tipBefore, durableTip(t, reopened))
	require.Equal(t, uint32(3), externalIndex(t, reopened))
	require.Empty(t, resumed.synced)
	require.Equal(t, countBefore, len(durableAddresses(
		t, reopened, lifecycleScope, waddrmgr.DefaultAccountNum,
	)))
}

// TestBtcdRecoveryReorg proves the syncer reconciles a real btcd reorg without
// advancing from a stale tip. After recovering to a tip whose highest block is
// empty of wallet funds, that block is invalidated on btcd and a longer
// competing branch is mined that funds two new indexes. A re-Recover on the same
// syncer detects the fork against the real chain, rewinds to the fork point
// through CommitWalletRewind, and re-discovers the funds on the new branch,
// including funds a stale-tip advance would have skipped.
//
// The reorg is exercised within a single syncer session, whose in-memory chain
// stands in for the durable per-wallet recent-block retention Phase 3a
// deferred; reorg detection across a fresh restart needs that durable retention,
// documented in DECISIONS.md.
func TestBtcdRecoveryReorg(t *testing.T) {
	ctx := context.Background()
	miner := newBtcdMiner(t)
	chainSrc := newBtcdChainSource(t, miner)

	_, wallet := createBtcdWallet(t, t.TempDir())
	defer func() { require.NoError(t, wallet.Close()) }()

	// Fund external index 0, then mine an empty block that becomes the wallet
	// tip. The empty block holds no wallet funds, so orphaning it later loses
	// nothing and isolates the reconciliation behavior.
	addrs := regtestExternalAddrs(t, 8)
	fundAddr(t, miner, addrs[0].Address, 100_000)
	mineBlocks(t, miner, 1)

	_, forkTip, err := chainSrc.GetBestBlock()
	require.NoError(t, err)

	syncer := newBtcdSyncer(t, wallet, chainSrc)
	require.NoError(t, syncer.Recover(ctx))
	require.Equal(t, int64(100_000), durableBalance(t, wallet, forkTip))
	require.Equal(t, forkTip, durableTip(t, wallet).Height)

	// Invalidate the empty tip block on btcd, reorging the node back to the
	// block that funds index 0.
	staleHash, err := chainSrc.GetBlockHash(int64(forkTip))
	require.NoError(t, err)
	require.NoError(t, miner.Client.InvalidateBlock(staleHash))

	// Mine a longer competing branch that funds indexes 2 and 3, so the new
	// best height exceeds the wallet's stale tip.
	fundAddr(t, miner, addrs[2].Address, 30_000)
	fundAddr(t, miner, addrs[3].Address, 20_000)

	_, newBest, err := chainSrc.GetBestBlock()
	require.NoError(t, err)
	require.Greater(t, newBest, forkTip)

	// Recover again on the same syncer: it reconciles the fork and re-scans the
	// competing branch. Without reconciliation it would advance from the stale
	// tip and miss the reorg branch's funds.
	require.NoError(t, syncer.Recover(ctx))

	// The synced tip is on the new branch, and all funds — the pre-fork index 0
	// plus the re-discovered index 2 and index 3 — are present.
	newBestHash, err := chainSrc.GetBlockHash(int64(newBest))
	require.NoError(t, err)
	tip := durableTip(t, wallet)
	require.Equal(t, newBest, tip.Height)
	require.Equal(t, *newBestHash, tip.Hash)

	require.Equal(t, int64(150_000), durableBalance(t, wallet, newBest))
	require.Len(t, durableUnspent(t, wallet), 3)
}

// A live btcd RPC client satisfies the recovery scan's chain source directly,
// guarding the abstraction against drift from chain.Interface.
var _ ChainSource = (*chain.RPCClient)(nil)
