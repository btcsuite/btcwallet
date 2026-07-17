// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sqlwallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/runtime"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

const (
	// defaultRecoveryWindow is the address-derivation lookahead a recovery
	// scan maintains ahead of the last found index on each branch when the
	// caller requests none.
	defaultRecoveryWindow uint32 = 250

	// defaultScanBatchSize is the number of blocks a recovery scan commits in
	// one batch when the caller requests none.
	defaultScanBatchSize uint32 = 2000

	// maxScanAttempts bounds how many times a single batch is re-prepared and
	// re-committed after an optimistic-concurrency conflict (a stale base tip
	// or branch index). A conflict re-reads durable state and recomputes the
	// batch outside any transaction, so a small bound is enough in practice.
	maxScanAttempts = 16
)

// ChainSource is the minimal chain backend a recovery scan reads. Every method
// matches the corresponding method of chain.Interface, so a production wallet
// passes its live chain client and a test passes a deterministic mock. It is
// deliberately read-only: the scan performs all chain I/O, address derivation,
// and script parsing through it outside the write transaction, then commits the
// prepared batch through the semantic runtime store.
type ChainSource interface {
	// GetBestBlock returns the hash and height of the chain's best block.
	GetBestBlock() (*chainhash.Hash, int32, error)

	// GetBlock returns the full block identified by hash.
	GetBlock(hash *chainhash.Hash) (*wire.MsgBlock, error)

	// GetBlockHash returns the hash of the block at the given height on the
	// current best chain.
	GetBlockHash(height int64) (*chainhash.Hash, error)

	// GetBlockHeader returns the header of the block identified by hash.
	GetBlockHeader(hash *chainhash.Hash) (*wire.BlockHeader, error)

	// FilterBlocks scans a range of blocks for outputs paying watched
	// addresses and inputs spending watched outpoints, returning the first
	// block in the range with a match so the caller can widen its horizons
	// before continuing.
	FilterBlocks(req *chain.FilterBlocksRequest) (
		*chain.FilterBlocksResponse, error)
}

// A live chain client satisfies the recovery scan's chain-source contract.
var _ ChainSource = (chain.Interface)(nil)

// SyncerConfig configures a recovery scan over a chain source.
type SyncerConfig struct {
	// Chain is the chain backend the scan reads. It is required.
	Chain ChainSource

	// RecoveryWindow is the address-derivation lookahead maintained ahead of
	// the last found index on each branch. Zero uses defaultRecoveryWindow.
	RecoveryWindow uint32

	// BatchSize is the number of blocks committed per scan batch. Zero uses
	// defaultScanBatchSize.
	BatchSize uint32

	// BirthdayHeight is the earliest height a scan filters. Blocks below it
	// hold no wallet funds by definition and are skipped. Zero scans from the
	// wallet's synced tip.
	BirthdayHeight int32
}

// Syncer drives the recovery scan and minimal chain reconciliation for one SQL
// wallet. It follows the Stage 3 Cache And Commit Protocol: it reads a durable
// snapshot, derives lookahead addresses and filters the chain outside any write
// transaction, assembles a deterministic scan batch, and commits it through the
// semantic runtime coordinator, publishing caches only after the durable commit
// agrees. On a stale base tip or branch index it re-reads durable state and
// recomputes the batch rather than replaying chain I/O inside a transaction.
type Syncer struct {
	wallet *SQLWallet
	chain  ChainSource

	window    uint32
	batchSize uint32
	birthday  int32

	// trackers maps an account branch to its horizon and gap-limit recovery
	// state. It spans the whole recovery so the last-unfound index carries
	// across batches. It is rebuilt per Recover call.
	trackers map[runtime.BranchKey]*branchScan

	// acctKeys are the account extended keys the trackers derive from, held so
	// they can be zeroed when a recovery completes.
	acctKeys []*hdkeychain.ExtendedKey

	// watchedOutPoints accumulates wallet-owned outpoints discovered during a
	// scan, so a later block spending one is detected. It is rebuilt per
	// Recover call.
	watchedOutPoints map[wire.OutPoint]address.Address

	// synced is the in-memory chain of blocks this session advanced through,
	// newest last. It stands in for the durable recent-block retention that
	// Phase 3a deferred, and is walked to locate a reorg fork point.
	synced []walletstore.BlockRef

	// events accumulates the post-commit events every committed batch
	// produced, in commit order, so a caller (or a test) can confirm each
	// event is delivered exactly once even under a forced transaction retry.
	events []walletstore.Event

	// beforeScanCommit is a test seam invoked in scanBatch after a batch is
	// prepared and before it is committed, used to interpose a concurrent
	// mutation. It is nil in production.
	beforeScanCommit func()
}

// NewSyncer constructs a recovery scan driver for the wallet over a chain
// source.
func (w *SQLWallet) NewSyncer(cfg SyncerConfig) (*Syncer, error) {
	if cfg.Chain == nil {
		return nil, errors.New("sqlwallet: a chain source is required")
	}

	window := cfg.RecoveryWindow
	if window == 0 {
		window = defaultRecoveryWindow
	}

	batchSize := cfg.BatchSize
	if batchSize == 0 {
		batchSize = defaultScanBatchSize
	}

	return &Syncer{
		wallet:           w,
		chain:            cfg.Chain,
		window:           window,
		batchSize:        batchSize,
		birthday:         cfg.BirthdayHeight,
		watchedOutPoints: make(map[wire.OutPoint]address.Address),
	}, nil
}

// Recover rescans the chain from the wallet's synced tip for used addresses and
// the funds they received, recovering a pre-funded seed over the semantic
// runtime store. It first reconciles any fork against the chain source, then
// scans forward in bounded batches, extending each branch's address horizon and
// committing the discovered addresses, transactions, credits, usage marks, and
// tip advance atomically. It resumes from the durable synced tip, so a restart
// never rescans from genesis.
func (s *Syncer) Recover(ctx context.Context) error {
	if err := s.buildTrackers(); err != nil {
		return err
	}
	defer s.zeroKeys()

	// Reconcile any fork against the chain source before scanning forward, so
	// a scan never advances from a stale tip.
	if err := s.reconcile(ctx); err != nil {
		return err
	}

	_, best, err := s.chain.GetBestBlock()
	if err != nil {
		return fmt.Errorf("sqlwallet: get best block: %w", err)
	}

	// Scan forward in bounded batches, re-reading the durable tip each batch
	// so the batch's base always equals the current synced block.
	for {
		tip, err := s.currentTip(ctx)
		if err != nil {
			return err
		}

		start := tip.Height + 1
		if start < s.birthday {
			start = s.birthday
		}

		if start > best {
			return nil
		}

		end := start + int32(s.batchSize) - 1
		if end > best {
			end = best
		}

		blocks, err := s.fetchBlockMetas(start, end)
		if err != nil {
			return err
		}

		if err := s.scanBatch(ctx, blocks); err != nil {
			return err
		}
	}
}

// CatchUp advances the wallet's synced tip to the chain's best block without
// filtering, one contiguous block at a time, for a wallet already synced past
// its recovery window that only needs to track new blocks. It fetches each
// header outside the write transaction and reuses the wallet-tip advance
// operation, which enforces a single-block contiguous advance. A stale tip
// (a concurrent advance) is retried from the fresh durable tip.
func (s *Syncer) CatchUp(ctx context.Context) error {
	_, best, err := s.chain.GetBestBlock()
	if err != nil {
		return fmt.Errorf("sqlwallet: get best block: %w", err)
	}

	for {
		tip, err := s.currentTip(ctx)
		if err != nil {
			return err
		}

		if tip.Height >= best {
			return nil
		}

		height := tip.Height + 1
		newTip, err := s.blockRef(height)
		if err != nil {
			return err
		}

		opID, err := randomOperationID()
		if err != nil {
			return err
		}

		_, err = s.wallet.coordinator.AdvanceTip(ctx, newTip, opID)
		switch {
		case errors.Is(err, walletstore.ErrStaleTip):
			// A concurrent advance moved the tip; re-read and retry.
			continue

		case err != nil:
			return fmt.Errorf("sqlwallet: catch up tip: %w", err)
		}

		s.synced = append(s.synced, newTip)
	}
}

// reconcile detects whether the wallet's synced tip is still on the chain
// source's best chain and, if not, rewinds to the fork point through
// CommitWalletRewind before the forward scan resumes. Fork discovery happens
// outside the write transaction; the rewind is one guarded compare-and-swap.
func (s *Syncer) reconcile(ctx context.Context) error {
	tip, err := s.currentTip(ctx)
	if err != nil {
		return err
	}

	// Nothing recorded above genesis can be forked away.
	if tip.Height == 0 {
		return nil
	}

	chainHash, err := s.chain.GetBlockHash(int64(tip.Height))
	if err != nil {
		return fmt.Errorf("sqlwallet: get block hash: %w", err)
	}

	// The synced tip is still on the best chain; no reconciliation needed.
	if *chainHash == tip.Hash {
		return nil
	}

	fork, err := s.findFork(tip)
	if err != nil {
		return err
	}

	opID, err := randomOperationID()
	if err != nil {
		return err
	}

	_, err = s.wallet.coordinator.CommitRewind(
		ctx, walletstore.CommitWalletRewindRequest{
			ExpectedTip: tip,
			TargetBlock: fork,
			OperationID: opID,
		},
	)
	if err != nil {
		return fmt.Errorf("sqlwallet: rewind to %d: %w", fork.Height, err)
	}

	s.truncateSynced(fork.Height)

	return nil
}

// findFork locates the deepest block the wallet and the chain source still
// agree on, walking back through the in-memory session chain. When the session
// chain does not reach the fork (for example a reorg detected on a fresh
// restart, before durable recent-block retention exists), it falls back to the
// wallet's genesis block, which forces a full re-scan.
func (s *Syncer) findFork(tip walletstore.BlockRef) (walletstore.BlockRef,
	error) {

	for i := len(s.synced) - 1; i >= 0; i-- {
		block := s.synced[i]
		if block.Height >= tip.Height {
			continue
		}

		chainHash, err := s.chain.GetBlockHash(int64(block.Height))
		if err != nil {
			return walletstore.BlockRef{}, fmt.Errorf(
				"sqlwallet: get block hash: %w", err)
		}

		if *chainHash == block.Hash {
			return block, nil
		}
	}

	return s.genesisRef(), nil
}

// buildTrackers rebuilds the per-branch recovery state for the wallet's scopes
// and default account under the wallet mutex, snapshotting each account key so
// derivation runs outside the mutex afterward. Only the default account is
// recovered, matching the legacy recovery scope.
func (s *Syncer) buildTrackers() error {
	s.wallet.mu.Lock()
	defer s.wallet.mu.Unlock()

	s.trackers = make(map[runtime.BranchKey]*branchScan)
	s.acctKeys = nil
	s.watchedOutPoints = make(map[wire.OutPoint]address.Address)
	s.events = nil

	account := uint32(waddrmgr.DefaultAccountNum)
	for scope, cache := range s.wallet.scopes {
		state, ok := cache.accounts[account]
		if !ok {
			continue
		}

		acctKey, err := s.wallet.keyring.AccountKey(state)
		if err != nil {
			return fmt.Errorf("sqlwallet: account key: %w", err)
		}
		s.acctKeys = append(s.acctKeys, acctKey)

		branches := []uint32{
			waddrmgr.ExternalBranch, waddrmgr.InternalBranch,
		}
		for _, branch := range branches {
			addrType, err := branchAddrType(
				cache.schema, state.AddrSchema, branch,
			)
			if err != nil {
				return err
			}

			key := runtime.BranchKey{
				Scope:   scope,
				Account: account,
				Branch:  branch,
			}
			s.trackers[key] = &branchScan{
				key:      key,
				addrType: addrType,
				acctKey:  acctKey,
				params:   s.wallet.params,
				window:   s.window,
				derived:  make(map[uint32]waddrmgr.DerivedAddress),
				found:    make(map[uint32]struct{}),
			}
		}
	}

	return nil
}

// zeroKeys zeroes the account extended keys the trackers derived from.
func (s *Syncer) zeroKeys() {
	for _, key := range s.acctKeys {
		key.Zero()
	}
	s.acctKeys = nil
}

// currentTip reads the wallet's durable synced tip through the semantic runtime
// store, so a batch's base and the reconciliation always see committed state.
func (s *Syncer) currentTip(ctx context.Context) (walletstore.BlockRef, error) {
	tip, err := s.wallet.runtimeStore.CurrentSyncedTip(ctx)
	if err != nil {
		return walletstore.BlockRef{}, fmt.Errorf(
			"sqlwallet: read synced tip: %w", err)
	}

	return tip, nil
}

// fetchBlockMetas reads the block metadata for the inclusive height range from
// the chain source, outside any write transaction.
func (s *Syncer) fetchBlockMetas(start, end int32) ([]wtxmgr.BlockMeta, error) {
	blocks := make([]wtxmgr.BlockMeta, 0, end-start+1)
	for height := start; height <= end; height++ {
		ref, err := s.blockRef(height)
		if err != nil {
			return nil, err
		}

		blocks = append(blocks, wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Hash: ref.Hash, Height: ref.Height},
			Time:  ref.Timestamp,
		})
	}

	return blocks, nil
}

// blockRef reads the block reference at a height from the chain source.
func (s *Syncer) blockRef(height int32) (walletstore.BlockRef, error) {
	hash, err := s.chain.GetBlockHash(int64(height))
	if err != nil {
		return walletstore.BlockRef{}, fmt.Errorf(
			"sqlwallet: get block hash %d: %w", height, err)
	}

	header, err := s.chain.GetBlockHeader(hash)
	if err != nil {
		return walletstore.BlockRef{}, fmt.Errorf(
			"sqlwallet: get block header %d: %w", height, err)
	}

	return walletstore.BlockRef{
		Height:    height,
		Hash:      *hash,
		Timestamp: header.Timestamp,
	}, nil
}

// genesisRef returns the wallet's genesis block reference, the safe rewind
// floor.
func (s *Syncer) genesisRef() walletstore.BlockRef {
	return walletstore.BlockRef{
		Height:    0,
		Hash:      *s.wallet.params.GenesisHash,
		Timestamp: s.wallet.params.GenesisBlock.Header.Timestamp,
	}
}

// truncateSynced drops in-memory session blocks above the given height after a
// rewind, so a subsequent reconciliation does not treat detached blocks as part
// of the wallet's chain.
func (s *Syncer) truncateSynced(height int32) {
	kept := s.synced[:0]
	for _, block := range s.synced {
		if block.Height <= height {
			kept = append(kept, block)
		}
	}
	s.synced = kept
}
