// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sqlwallet

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/chain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/runtime"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

// branchScan is the horizon and gap-limit recovery state for one account
// branch. It mirrors the legacy wallet's per-branch recovery state: it derives
// a lookahead of addresses ahead of the last found index, records which indexes
// were found on chain, and reports how far the durable branch index should
// advance. Derivation uses only child public keys, so it works for a locked or
// watch-only account.
type branchScan struct {
	// key identifies the account branch this state tracks.
	key runtime.BranchKey

	// addrType is the address type derived for this branch.
	addrType waddrmgr.AddressType

	// acctKey is the account extended key the branch derives from. It is owned
	// by the syncer and zeroed when the recovery completes.
	acctKey *hdkeychain.ExtendedKey

	// params is the chain the addresses are derived for.
	params *chaincfg.Params

	// window is the lookahead maintained ahead of the last found index.
	window uint32

	// horizon is the next index past every address derived so far, the
	// exclusive upper bound of the watched set.
	horizon uint32

	// nextUnfound is one past the highest index found on chain, so it is the
	// branch's next durable index after the scan. It is zero until an address
	// is found.
	nextUnfound uint32

	// derived maps a child index to its derived address, retained so the
	// filter watch-set and the discovered-address rows share one derivation.
	derived map[uint32]waddrmgr.DerivedAddress

	// found is the set of indexes found on chain, so a used mark is emitted for
	// each. Indexes below a prior batch's commit boundary are already marked
	// used durably; re-marking is idempotent.
	found map[uint32]struct{}
}

// expand derives enough addresses to maintain the recovery window ahead of the
// last found index. It skips invalid children exactly as the address manager
// does, so the derived horizon can advance past the requested count.
func (b *branchScan) expand() error {
	target := b.nextUnfound + b.window
	for b.horizon < target {
		need := target - b.horizon

		derived, next, err := waddrmgr.DeriveChainedAddresses(
			b.acctKey, b.key.Branch, b.addrType, b.params, b.horizon,
			need,
		)
		if err != nil {
			return fmt.Errorf("sqlwallet: derive lookahead: %w", err)
		}

		for _, d := range derived {
			b.derived[d.Index] = d
		}

		// Guard against a non-advancing derivation so the loop always
		// terminates.
		if next <= b.horizon {
			break
		}
		b.horizon = next
	}

	return nil
}

// reportFound records that the address at index was found on chain, advancing
// the last-unfound boundary so the next horizon expansion widens the lookahead.
func (b *branchScan) reportFound(index uint32) {
	b.found[index] = struct{}{}
	if index+1 > b.nextUnfound {
		b.nextUnfound = index + 1
	}
}

// scanBatch prepares and commits one block batch, retrying on an optimistic
// concurrency conflict. Each attempt re-reads the durable synced tip, re-runs
// the chain filter and derivation outside any write transaction, and commits
// the whole batch atomically. A stale base tip or branch index re-reads durable
// state and recomputes the batch rather than replaying chain I/O inside a
// transaction, following the Stage 3 recovery contract.
func (s *Syncer) scanBatch(ctx context.Context,
	blocks []wtxmgr.BlockMeta) error {

	for attempt := 0; attempt < maxScanAttempts; attempt++ {
		base, err := s.currentTip(ctx)
		if err != nil {
			return err
		}

		opID, err := randomOperationID()
		if err != nil {
			return err
		}

		req, err := s.prepareBatch(ctx, base, blocks, opID)
		if err != nil {
			return err
		}

		// A test seam to interpose a concurrent mutation between a prepared
		// batch and its commit.
		if s.beforeScanCommit != nil {
			s.beforeScanCommit()
		}

		result, err := s.wallet.coordinator.CommitScan(ctx, req)
		switch {
		// A concurrent advance or address allocation moved the durable state
		// the batch was prepared against; re-read it and recompute.
		case errors.Is(err, walletstore.ErrStaleTip),
			errors.Is(err, walletstore.ErrStaleAccountIndex):

			continue

		case err != nil:
			return fmt.Errorf("sqlwallet: commit scan batch: %w", err)
		}

		// Record the batch's blocks in the session chain so a later
		// reconciliation can locate a reorg fork point, and retain the
		// committed events for delivery. The commit materialized them once, so
		// a forced transaction retry never duplicates them.
		for _, blk := range blocks {
			s.synced = append(s.synced, blockRefFromMeta(blk))
		}
		s.events = append(s.events, result.Events...)

		return nil
	}

	return fmt.Errorf("sqlwallet: scan batch abandoned after %d conflicts",
		maxScanAttempts)
}

// prepareBatch runs the chain filter over the block range and assembles a
// deterministic scan batch, all outside the write transaction. It iterates the
// filter the way legacy recovery does: expand every branch horizon, filter the
// remaining blocks, record the addresses and transactions found in the first
// matching block, then repeat from just after that block until the range is
// exhausted.
func (s *Syncer) prepareBatch(ctx context.Context, base walletstore.BlockRef,
	blocks []wtxmgr.BlockMeta, opID []byte) (
	walletstore.CommitScanResultsRequest, error) {

	var txns []walletstore.ScanTransaction

	remaining := blocks
	for len(remaining) > 0 {
		// Ensure every branch has a full lookahead before filtering.
		for _, tracker := range s.trackers {
			if err := tracker.expand(); err != nil {
				return walletstore.CommitScanResultsRequest{}, err
			}
		}

		resp, err := s.chain.FilterBlocks(s.filterRequest(remaining))
		if err != nil {
			return walletstore.CommitScanResultsRequest{}, fmt.Errorf(
				"sqlwallet: filter blocks: %w", err)
		}

		// No further matches in the remaining range.
		if resp == nil {
			break
		}

		s.recordFound(resp)

		owned := s.ownedAddrs()
		for _, msg := range resp.RelevantTxns {
			scanTx, err := s.buildScanTx(msg, &resp.BlockMeta, owned)
			if err != nil {
				return walletstore.CommitScanResultsRequest{}, err
			}
			txns = append(txns, scanTx)
		}

		// Continue from just after the matched block.
		next := int(resp.BatchIndex) + 1
		if next >= len(remaining) {
			break
		}
		remaining = remaining[next:]
	}

	return s.assembleRequest(ctx, base, blocks, txns, opID)
}

// filterRequest builds the chain filter request for the block range from the
// current derived watch-set and the outpoints found so far.
func (s *Syncer) filterRequest(
	blocks []wtxmgr.BlockMeta) *chain.FilterBlocksRequest {

	req := &chain.FilterBlocksRequest{
		Blocks:           blocks,
		ExternalAddrs:    make(map[waddrmgr.ScopedIndex]address.Address),
		InternalAddrs:    make(map[waddrmgr.ScopedIndex]address.Address),
		WatchedOutPoints: s.watchedOutPoints,
	}

	for key, tracker := range s.trackers {
		for index, derived := range tracker.derived {
			scopedIndex := waddrmgr.ScopedIndex{
				Scope: key.Scope,
				Index: index,
			}

			switch key.Branch {
			case waddrmgr.ExternalBranch:
				req.ExternalAddrs[scopedIndex] = derived.Address

			case waddrmgr.InternalBranch:
				req.InternalAddrs[scopedIndex] = derived.Address
			}
		}
	}

	return req
}

// recordFound folds a filter response into the recovery state: it reports every
// found external and internal index and adds every found outpoint to the
// watched set so a later block spending one is detected.
func (s *Syncer) recordFound(resp *chain.FilterBlocksResponse) {
	account := uint32(waddrmgr.DefaultAccountNum)

	for scope, indexes := range resp.FoundExternalAddrs {
		key := runtime.BranchKey{
			Scope: scope, Account: account,
			Branch: waddrmgr.ExternalBranch,
		}
		if tracker, ok := s.trackers[key]; ok {
			for index := range indexes {
				tracker.reportFound(index)
			}
		}
	}

	for scope, indexes := range resp.FoundInternalAddrs {
		key := runtime.BranchKey{
			Scope: scope, Account: account,
			Branch: waddrmgr.InternalBranch,
		}
		if tracker, ok := s.trackers[key]; ok {
			for index := range indexes {
				tracker.reportFound(index)
			}
		}
	}

	for outPoint, addr := range resp.FoundOutPoints {
		s.watchedOutPoints[outPoint] = addr
	}
}

// ownedAddrs builds a lookup from an encoded address to whether it is an
// internal (change) address, over every derived address, so a relevant
// transaction's wallet-owned outputs and their change flag are identified the
// same way the legacy addRelevantTx does.
func (s *Syncer) ownedAddrs() map[string]bool {
	owned := make(map[string]bool)
	for key, tracker := range s.trackers {
		internal := key.Branch == waddrmgr.InternalBranch
		for _, derived := range tracker.derived {
			owned[derived.Address.EncodeAddress()] = internal
		}
	}

	return owned
}

// buildScanTx builds one prepared scan transaction from a relevant chain
// transaction, recording a credit for each output paying a wallet-owned
// address, with the change flag set for an internal-branch address.
func (s *Syncer) buildScanTx(msg *wire.MsgTx, block *wtxmgr.BlockMeta,
	owned map[string]bool) (walletstore.ScanTransaction, error) {

	record, err := wtxmgr.NewTxRecordFromMsgTx(msg, block.Time)
	if err != nil {
		return walletstore.ScanTransaction{}, fmt.Errorf(
			"sqlwallet: build tx record: %w", err)
	}

	var credits []walletstore.ScanCredit
	for i, out := range msg.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			out.PkScript, s.wallet.params,
		)
		if err != nil {
			// Non-standard outputs cannot pay a wallet address.
			continue
		}

		for _, addr := range addrs {
			change, ok := owned[addr.EncodeAddress()]
			if !ok {
				continue
			}

			//nolint:gosec // A transaction output index fits a uint32.
			credits = append(credits, walletstore.ScanCredit{
				Index:  uint32(i),
				Change: change,
			})

			break
		}
	}

	return walletstore.ScanTransaction{
		Record:  record,
		Block:   block,
		Credits: credits,
	}, nil
}

// assembleRequest builds the scan-batch commit request from the recovery state:
// the discovered-address rows to persist, each branch's horizon advance, the
// sticky usage marks, the batch blocks, and the new tip. The durable branch
// index is read fresh per branch, so the horizon compare-and-swap is guarded on
// the current durable value and a concurrent allocation is a clean conflict.
func (s *Syncer) assembleRequest(ctx context.Context, base walletstore.BlockRef,
	blocks []wtxmgr.BlockMeta, txns []walletstore.ScanTransaction,
	opID []byte) (walletstore.CommitScanResultsRequest, error) {

	var (
		addresses []walletstore.PreparedAddress
		horizons  []walletstore.BranchHorizon
		used      []walletstore.AddressUse
	)

	for key, tracker := range s.trackers {
		if len(tracker.found) == 0 {
			continue
		}

		durableIndex, err := s.wallet.runtimeStore.CurrentBranchIndex(
			ctx, key.Scope, key.Account, key.Branch,
		)
		if err != nil {
			return walletstore.CommitScanResultsRequest{}, fmt.Errorf(
				"sqlwallet: read branch index: %w", err)
		}

		// nextUnfound is one past the highest found index, the branch's new
		// durable next index. Persist and advance only the range above the
		// current durable index; anything below is already durable.
		if tracker.nextUnfound > durableIndex {
			maxFound := tracker.nextUnfound - 1
			for index := durableIndex; index <= maxFound; index++ {
				derived, ok := tracker.derived[index]
				if !ok {
					continue
				}
				addresses = append(
					addresses, preparedAddress(key, derived),
				)
			}

			horizons = append(horizons, walletstore.BranchHorizon{
				Scope:         key.Scope,
				Account:       key.Account,
				Branch:        key.Branch,
				ExpectedIndex: durableIndex,
				FinalIndex:    tracker.nextUnfound,
			})
		}

		// Mark every found address used. The row exists (persisted here or in
		// a prior batch) and the mark is sticky, so re-marking is idempotent.
		for index := range tracker.found {
			derived, ok := tracker.derived[index]
			if !ok {
				continue
			}
			used = append(used, walletstore.AddressUse{
				Scope:     key.Scope,
				AddressID: derived.AddressID,
			})
		}
	}

	blockRefs := make([]walletstore.BlockRef, len(blocks))
	for i, blk := range blocks {
		blockRefs[i] = blockRefFromMeta(blk)
	}

	return walletstore.CommitScanResultsRequest{
		ExpectedTip:   base,
		NewTip:        blockRefFromMeta(blocks[len(blocks)-1]),
		Blocks:        blockRefs,
		Horizons:      horizons,
		Addresses:     addresses,
		Transactions:  txns,
		UsedAddresses: used,
		OperationID:   opID,
	}, nil
}

// preparedAddress turns a derived address into the prepared row a scan batch
// inserts, mirroring runtime.ChainedAddressPreparer so the recovery scan and
// live derivation persist identical rows.
func preparedAddress(key runtime.BranchKey,
	derived waddrmgr.DerivedAddress) walletstore.PreparedAddress {

	hash := sha256.Sum256(derived.AddressID)
	branch := derived.Branch
	index := derived.Index

	return walletstore.PreparedAddress{
		AddressID: derived.AddressID,
		State: waddrmgr.AddressState{
			Scope:      key.Scope,
			Hash:       hash[:],
			Account:    key.Account,
			Type:       waddrmgr.AddressChain,
			AddedAt:    time.Now(),
			SyncStatus: waddrmgr.AddressSyncFull,
			Branch:     &branch,
			Index:      &index,
		},
	}
}

// blockRefFromMeta projects a block metadata into the neutral block reference
// the runtime store exchanges.
func blockRefFromMeta(block wtxmgr.BlockMeta) walletstore.BlockRef {
	return walletstore.BlockRef{
		Height:    block.Height,
		Hash:      block.Hash,
		Timestamp: block.Time,
	}
}
