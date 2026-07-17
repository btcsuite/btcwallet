// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sqlwallet

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	dbsqlite "github.com/btcsuite/btcwallet/wallet/internal/db/sqlite"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// mockChain is a deterministic in-memory chain source for the recovery tests.
// It stores a best chain of blocks with their full transactions and reuses the
// production chain.BlockFilterer so its filter semantics match a real backend.
// A reorg truncates the best chain and lets the test append a competing branch.
type mockChain struct {
	params *chaincfg.Params
	hashes []chainhash.Hash
	blocks map[chainhash.Hash]*wire.MsgBlock
	heads  map[chainhash.Hash]wire.BlockHeader
	nonce  uint32
}

// newMockChain builds a mock chain seeded with the network genesis at height
// zero, matching the block a freshly created wallet is synced to.
func newMockChain() *mockChain {
	genesis := *lifecycleParams.GenesisHash

	return &mockChain{
		params: lifecycleParams,
		hashes: []chainhash.Hash{genesis},
		blocks: make(map[chainhash.Hash]*wire.MsgBlock),
		heads:  make(map[chainhash.Hash]wire.BlockHeader),
	}
}

// addBlock appends a block carrying the given transactions to the best chain
// and returns its reference. A monotonically increasing nonce guarantees every
// block, including a reorg replacement at a reused height, has a unique hash.
func (m *mockChain) addBlock(txns ...*wire.MsgTx) walletstore.BlockRef {
	m.nonce++
	height := int32(len(m.hashes))
	prev := m.hashes[height-1]

	header := wire.BlockHeader{
		Version:   1,
		PrevBlock: prev,
		Timestamp: time.Unix(1_600_000_000, 0).Add(
			time.Duration(height) * 10 * time.Minute,
		),
		Bits:  0x1d00ffff,
		Nonce: m.nonce,
	}

	block := &wire.MsgBlock{Header: header, Transactions: txns}
	hash := header.BlockHash()

	m.hashes = append(m.hashes, hash)
	m.blocks[hash] = block
	m.heads[hash] = header

	return walletstore.BlockRef{
		Height:    height,
		Hash:      hash,
		Timestamp: header.Timestamp,
	}
}

// reorg truncates the best chain to the fork height, so the caller can append a
// competing branch above it. Detached blocks remain resolvable by hash.
func (m *mockChain) reorg(forkHeight int32) {
	m.hashes = m.hashes[:forkHeight+1]
}

// GetBestBlock returns the best block's hash and height.
func (m *mockChain) GetBestBlock() (*chainhash.Hash, int32, error) {
	height := int32(len(m.hashes) - 1)
	hash := m.hashes[height]

	return &hash, height, nil
}

// GetBlockHash returns the best-chain block hash at the given height.
func (m *mockChain) GetBlockHash(height int64) (*chainhash.Hash, error) {
	if height < 0 || int(height) >= len(m.hashes) {
		return nil, fmt.Errorf("mock: no block at height %d", height)
	}
	hash := m.hashes[height]

	return &hash, nil
}

// GetBlockHeader returns the header of the block identified by hash.
func (m *mockChain) GetBlockHeader(hash *chainhash.Hash) (*wire.BlockHeader,
	error) {

	header, ok := m.heads[*hash]
	if !ok {
		return nil, fmt.Errorf("mock: no header for %v", hash)
	}

	return &header, nil
}

// GetBlock returns the full block identified by hash.
func (m *mockChain) GetBlock(hash *chainhash.Hash) (*wire.MsgBlock, error) {
	block, ok := m.blocks[*hash]
	if !ok {
		return nil, fmt.Errorf("mock: no block %v", hash)
	}

	return block, nil
}

// FilterBlocks scans the requested block range with the production block
// filterer and returns the first block containing a match, mirroring a real
// chain backend's FilterBlocks contract.
func (m *mockChain) FilterBlocks(req *chain.FilterBlocksRequest) (
	*chain.FilterBlocksResponse, error) {

	for i, meta := range req.Blocks {
		block, ok := m.blocks[meta.Hash]
		if !ok {
			return nil, fmt.Errorf("mock: no block %v", meta.Hash)
		}

		filterer := chain.NewBlockFilterer(m.params, req)
		if !filterer.FilterBlock(block) {
			continue
		}

		return &chain.FilterBlocksResponse{
			BatchIndex:         uint32(i),
			BlockMeta:          meta,
			FoundExternalAddrs: filterer.FoundExternal,
			FoundInternalAddrs: filterer.FoundInternal,
			FoundOutPoints:     filterer.FoundOutPoints,
			RelevantTxns:       filterer.RelevantTxns,
		}, nil
	}

	return nil, nil
}

// A mock chain satisfies the recovery scan's chain-source contract.
var _ ChainSource = (*mockChain)(nil)

// externalAddrs derives the wallet's first count external addresses directly
// from the deterministic test seed, so a test knows the exact scripts to fund
// and the identities to assert against, sharing no state with the wallet.
func externalAddrs(t *testing.T, count uint32) []waddrmgr.DerivedAddress {
	t.Helper()

	root := lifecycleRootKey(t)
	acctKey := deriveExpectedAccountKey(t, root, lifecycleScope)
	defer acctKey.Zero()

	derived, _, err := waddrmgr.DeriveChainedAddresses(
		acctKey, waddrmgr.ExternalBranch, waddrmgr.WitnessPubKey,
		lifecycleParams, 0, count,
	)
	require.NoError(t, err)

	return derived
}

// payTo builds a non-coinbase transaction paying value to addr, with a unique
// input outpoint keyed by salt so distinct funding transactions have distinct
// hashes.
func payTo(t *testing.T, addr address.Address, value int64,
	salt byte) *wire.MsgTx {

	t.Helper()

	script, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	msg := wire.NewMsgTx(2)
	msg.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash: chainhash.Hash{salt}, Index: 0,
		},
	})
	msg.AddTxOut(&wire.TxOut{Value: value, PkScript: script})

	return msg
}

// newRecoverySyncer builds a syncer over the mock chain with a small recovery
// window and batch size so the tests exercise horizon extension and batching.
func newRecoverySyncer(t *testing.T, wallet *SQLWallet, chainSrc ChainSource,
	window, batchSize uint32) *Syncer {

	t.Helper()

	syncer, err := wallet.NewSyncer(SyncerConfig{
		Chain:          chainSrc,
		RecoveryWindow: window,
		BatchSize:      batchSize,
	})
	require.NoError(t, err)

	return syncer
}

// durableTip reads the wallet's durable synced tip through the runtime store,
// bypassing every in-memory cache.
func durableTip(t *testing.T, wallet *SQLWallet) walletstore.BlockRef {
	t.Helper()

	tip, err := wallet.runtimeStore.CurrentSyncedTip(context.Background())
	require.NoError(t, err)

	return tip
}

// externalIndex reads the wallet's durable external branch next index.
func externalIndex(t *testing.T, wallet *SQLWallet) uint32 {
	t.Helper()

	index, err := wallet.runtimeStore.CurrentBranchIndex(
		context.Background(), lifecycleScope, waddrmgr.DefaultAccountNum,
		waddrmgr.ExternalBranch,
	)
	require.NoError(t, err)

	return index
}

// durableBalance reads the wallet's spendable balance at a sync height directly
// from its SQL connection.
func durableBalance(t *testing.T, wallet *SQLWallet, syncHeight int32) int64 {
	t.Helper()

	store := dbsqlite.NewStore(wallet.conn, wallet.walletID)

	var balance btcutil.Amount
	err := store.View(context.Background(), func(tx walletstore.ReadTx) error {
		var err error

		balance, err = tx.Tx().Balance(0, syncHeight)

		return err
	}, func() {})
	require.NoError(t, err)

	return int64(balance)
}

// durableUnspent reads the wallet's unspent outputs directly from its SQL
// connection.
func durableUnspent(t *testing.T, wallet *SQLWallet) []wtxmgr.Credit {
	t.Helper()

	store := dbsqlite.NewStore(wallet.conn, wallet.walletID)

	var unspent []wtxmgr.Credit
	err := store.View(context.Background(), func(tx walletstore.ReadTx) error {
		var err error

		unspent, err = tx.Tx().UnspentOutputs()

		return err
	}, func() {})
	require.NoError(t, err)

	return unspent
}

// relevantTxEvents counts the relevant-transaction events a scan produced, the
// notifications the wallet would deliver for discovered transactions.
func relevantTxEvents(events []walletstore.Event) int {
	var count int
	for _, event := range events {
		if event.Kind == walletstore.RelevantTxKind {
			count++
		}
	}

	return count
}

// TestSyncerRecoversPrefundedSeed proves the Phase 3 recovery exit gate: a seed
// pre-funded at external indexes 0, 2, and 5 (the last beyond the initial
// lookahead window) recovers all of its funds over SQLite through the semantic
// runtime store, with the balance, unspent set, discovered addresses, and
// branch index all correct.
func TestSyncerRecoversPrefundedSeed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	loader, _ := newLoader(t)
	wallet := createLifecycleWallet(t, loader)
	defer func() { require.NoError(t, wallet.Close()) }()

	// Fund external indexes 0, 2, and 5 across ascending blocks. With a
	// recovery window of 3, index 5 is beyond the initial horizon and is only
	// reached because each find widens the lookahead.
	addrs := externalAddrs(t, 8)
	mock := newMockChain()
	mock.addBlock(payTo(t, addrs[0].Address, 100_000, 0x01))
	mock.addBlock(payTo(t, addrs[2].Address, 30_000, 0x02))
	mock.addBlock(payTo(t, addrs[5].Address, 20_000, 0x03))

	_, best, err := mock.GetBestBlock()
	require.NoError(t, err)

	syncer := newRecoverySyncer(t, wallet, mock, 3, 10)
	require.NoError(t, syncer.Recover(ctx))

	// All funds recovered.
	require.Equal(t, int64(150_000), durableBalance(t, wallet, best))
	require.Len(t, durableUnspent(t, wallet), 3)

	// The synced tip advanced to the chain tip.
	require.Equal(t, best, durableTip(t, wallet).Height)

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

// TestSyncerGapLimitAndRestartResume proves the gap-limit and last-unused
// behavior stays correct across a restart: after recovering, the next address
// is the index past the last found, and reopening the wallet and recovering
// again resumes from the durable tip without rescanning from genesis, leaving
// the address set, branch index, and balance unchanged.
func TestSyncerGapLimitAndRestartResume(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	loader, _ := newLoader(t)
	wallet := createLifecycleWallet(t, loader)

	// Fund external indexes 0 and 2, so the last found index is 2.
	addrs := externalAddrs(t, 6)
	mock := newMockChain()
	mock.addBlock(payTo(t, addrs[0].Address, 100_000, 0x01))
	mock.addBlock(payTo(t, addrs[2].Address, 50_000, 0x02))

	_, best, err := mock.GetBestBlock()
	require.NoError(t, err)

	syncer := newRecoverySyncer(t, wallet, mock, 3, 10)
	require.NoError(t, syncer.Recover(ctx))

	balanceBefore := durableBalance(t, wallet, best)
	require.Equal(t, int64(150_000), balanceBefore)
	require.Equal(t, uint32(3), externalIndex(t, wallet))

	countBefore := len(durableAddresses(
		t, wallet, lifecycleScope, waddrmgr.DefaultAccountNum,
	))
	tipBefore := durableTip(t, wallet)

	// The next derived address is the last-unused index (3, past the last
	// found), proving gap-limit accounting.
	require.NoError(t, wallet.Unlock(ctx, lifecyclePrivPass))
	next, err := wallet.NextAddress(
		ctx, lifecycleScope, waddrmgr.DefaultAccountNum,
		waddrmgr.ExternalBranch,
	)
	require.NoError(t, err)
	require.Equal(t, uint32(3), next.Index)
	require.NoError(t, wallet.Close())

	// Reopen the wallet: the synced tip is reconstructed from durable state.
	reopened, err := loader.OpenWallet(ctx, OpenParams{
		Name:          lifecycleWalletName,
		PubPassphrase: lifecyclePubPass,
	})
	require.NoError(t, err)
	defer func() { require.NoError(t, reopened.Close()) }()

	require.Equal(t, tipBefore, durableTip(t, reopened))

	// Recovering again resumes from the durable tip: with no new blocks it
	// scans nothing, so nothing is re-derived or re-persisted.
	resumed := newRecoverySyncer(t, reopened, mock, 3, 10)
	require.NoError(t, resumed.Recover(ctx))

	require.Equal(t, balanceBefore, durableBalance(t, reopened, best))
	require.Equal(t, tipBefore, durableTip(t, reopened))

	// The next index reflects the address derived before the restart (4), and
	// no batch was committed by the resumed scan.
	require.Equal(t, uint32(4), externalIndex(t, reopened))
	require.Empty(t, resumed.synced)

	// The address set grew only by the one address derived before restart, not
	// by a rescan from genesis.
	countAfter := len(durableAddresses(
		t, reopened, lifecycleScope, waddrmgr.DefaultAccountNum,
	))
	require.Equal(t, countBefore+1, countAfter)
}

// TestSyncerForcedRetryIdempotent proves a scan-batch commit forced to retry
// (through the SQL callback-retry failpoint) advances durable state exactly
// once and emits each relevant-transaction event once, so a retried batch never
// double-counts a credit or duplicates a notification.
func TestSyncerForcedRetryIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	loader, _ := newLoader(t)
	wallet := createLifecycleWallet(t, loader)
	defer func() { require.NoError(t, wallet.Close()) }()

	addrs := externalAddrs(t, 4)
	mock := newMockChain()
	mock.addBlock(payTo(t, addrs[0].Address, 70_000, 0x01))

	_, best, err := mock.GetBestBlock()
	require.NoError(t, err)

	// Force the first transaction attempt of every scan commit to retry, and
	// count the attempts to confirm the retry actually fired.
	var attempts int
	retryCtx := walletstore.WithFailpoints(ctx, &walletstore.Failpoints{
		ForceTxRetries: 1,
		OnTxAttempt:    func(int) { attempts++ },
	})

	syncer := newRecoverySyncer(t, wallet, mock, 3, 10)
	require.NoError(t, syncer.Recover(retryCtx))

	// The commit body ran twice but durable state advanced once.
	require.Equal(t, 2, attempts)
	require.Equal(t, int64(70_000), durableBalance(t, wallet, best))
	require.Len(t, durableUnspent(t, wallet), 1)
	require.Equal(t, uint32(1), externalIndex(t, wallet))

	// The relevant-transaction event was materialized exactly once despite the
	// retry.
	require.Equal(t, 1, relevantTxEvents(syncer.events))
}

// TestSyncerConcurrentDerivationConflict proves a concurrent address allocation
// during a scan is a clean typed conflict, not corruption: the batch's
// branch-index compare-and-swap fails, the syncer re-reads durable state and
// recomputes, and the recovery still completes with the funds recorded and no
// duplicate address row.
func TestSyncerConcurrentDerivationConflict(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	loader, _ := newLoader(t)
	wallet := createLifecycleWallet(t, loader)
	defer func() { require.NoError(t, wallet.Close()) }()

	addrs := externalAddrs(t, 4)
	mock := newMockChain()
	mock.addBlock(payTo(t, addrs[0].Address, 90_000, 0x01))

	_, best, err := mock.GetBestBlock()
	require.NoError(t, err)

	syncer := newRecoverySyncer(t, wallet, mock, 3, 10)

	// Between the first batch's preparation and its commit, allocate external
	// index 0 through the normal derivation path, advancing the durable branch
	// index out from under the prepared batch exactly once. The hook fires once
	// per commit attempt, so counting its calls proves the conflict forced a
	// recompute.
	var (
		once     sync.Once
		attempts int
	)
	syncer.beforeScanCommit = func() {
		attempts++
		once.Do(func() {
			_, err := wallet.NextAddress(
				ctx, lifecycleScope,
				waddrmgr.DefaultAccountNum,
				waddrmgr.ExternalBranch,
			)
			require.NoError(t, err)
		})
	}

	require.NoError(t, syncer.Recover(ctx))

	// The first commit hit the branch-index conflict and the batch was
	// re-prepared, so at least two attempts ran.
	require.GreaterOrEqual(t, attempts, 2)

	// The funds were recorded despite the conflict, and the branch index
	// reflects the single allocation (by the concurrent derivation), with no
	// duplicate row for index 0.
	require.Equal(t, int64(90_000), durableBalance(t, wallet, best))
	require.Len(t, durableUnspent(t, wallet), 1)
	require.Equal(t, uint32(1), externalIndex(t, wallet))

	persisted := durableAddresses(
		t, wallet, lifecycleScope, waddrmgr.DefaultAccountNum,
	)
	var atZero int
	for _, addr := range persisted {
		if addr.Index != nil && *addr.Index == 0 {
			atZero++
		}
	}
	require.Equal(t, 1, atZero, "index 0 must have exactly one address row")
}

// TestSyncerReorgReconciles proves a reorg does not advance the wallet from a
// stale tip: the syncer detects that its synced tip is no longer on the chain,
// rewinds to the fork point through CommitWalletRewind, and the forward scan
// re-discovers the funds on the competing branch, including funds in the reorg
// block that a stale-tip advance would have skipped.
func TestSyncerReorgReconciles(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	loader, _ := newLoader(t)
	wallet := createLifecycleWallet(t, loader)
	defer func() { require.NoError(t, wallet.Close()) }()

	// Original chain: block 1 funds external index 0; block 2 is empty.
	addrs := externalAddrs(t, 8)
	mock := newMockChain()
	mock.addBlock(payTo(t, addrs[0].Address, 100_000, 0x01))
	mock.addBlock()

	_, best, err := mock.GetBestBlock()
	require.NoError(t, err)
	require.Equal(t, int32(2), best)

	syncer := newRecoverySyncer(t, wallet, mock, 5, 10)
	require.NoError(t, syncer.Recover(ctx))
	require.Equal(t, int64(100_000), durableBalance(t, wallet, best))
	require.Equal(t, int32(2), durableTip(t, wallet).Height)

	// Reorg the chain from the fork at height 1: a competing block 2 funds
	// external index 2, and a new block 3 funds external index 3. The original
	// block 2 (which the wallet synced) is orphaned.
	mock.reorg(1)
	mock.addBlock(payTo(t, addrs[2].Address, 30_000, 0x04))
	mock.addBlock(payTo(t, addrs[3].Address, 20_000, 0x05))

	_, newBest, err := mock.GetBestBlock()
	require.NoError(t, err)
	require.Equal(t, int32(3), newBest)

	// Recover again on the same syncer: it reconciles the fork and re-scans the
	// competing branch. Without reconciliation it would advance from the stale
	// block 2 and miss the reorg block's funds.
	require.NoError(t, syncer.Recover(ctx))

	// The synced tip is on the new branch, and all funds (the pre-fork index 0
	// plus the re-discovered index 2 and index 3) are present.
	newTipHash, err := mock.GetBlockHash(int64(newBest))
	require.NoError(t, err)
	tip := durableTip(t, wallet)
	require.Equal(t, newBest, tip.Height)
	require.Equal(t, *newTipHash, tip.Hash)

	require.Equal(t, int64(150_000), durableBalance(t, wallet, newBest))
	require.Len(t, durableUnspent(t, wallet), 3)
}

// TestSyncerCatchUp proves the catch-up path advances the synced tip to the
// chain tip one contiguous block at a time through the wallet-tip advance
// operation, for a wallet that only needs to track new blocks.
func TestSyncerCatchUp(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	loader, _ := newLoader(t)
	wallet := createLifecycleWallet(t, loader)
	defer func() { require.NoError(t, wallet.Close()) }()

	mock := newMockChain()
	mock.addBlock()
	mock.addBlock()
	mock.addBlock()

	_, best, err := mock.GetBestBlock()
	require.NoError(t, err)

	syncer := newRecoverySyncer(t, wallet, mock, 3, 10)
	require.NoError(t, syncer.CatchUp(ctx))

	tip := durableTip(t, wallet)
	require.Equal(t, best, tip.Height)

	bestHash, err := mock.GetBlockHash(int64(best))
	require.NoError(t, err)
	require.Equal(t, *bestHash, tip.Hash)
}
