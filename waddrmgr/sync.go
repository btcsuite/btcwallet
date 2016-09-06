// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr

import (
	"sync"

	"github.com/jadeblaquiere/ctcd/chaincfg/chainhash"
	"github.com/jadeblaquiere/ctcwallet/walletdb"
)

const (
	// maxRecentHashes is the maximum number of hashes to keep in history
	// for the purposes of rollbacks.
	maxRecentHashes = 20
)

// BlockStamp defines a block (by height and a unique hash) and is
// used to mark a point in the blockchain that an address manager element is
// synced to.
type BlockStamp struct {
	Height int32
	Hash   chainhash.Hash
}

// syncState houses the sync state of the manager.  It consists of the recently
// seen blocks as height, as well as the start and current sync block stamps.
type syncState struct {
	// startBlock is the first block that can be safely used to start a
	// rescan.  It is either the block the manager was created with, or
	// the earliest block provided with imported addresses or scripts.
	startBlock BlockStamp

	// syncedTo is the current block the addresses in the manager are known
	// to be synced against.
	syncedTo BlockStamp

	// recentHeight is the most recently seen sync height.
	recentHeight int32

	// recentHashes is a list of the last several seen block hashes.
	recentHashes []chainhash.Hash
}

// iter returns a BlockIterator that can be used to iterate over the recently
// seen blocks in the sync state.
func (s *syncState) iter(mtx *sync.RWMutex) *BlockIterator {
	if s.recentHeight == -1 || len(s.recentHashes) == 0 {
		return nil
	}
	return &BlockIterator{
		mtx:      mtx,
		height:   s.recentHeight,
		index:    len(s.recentHashes) - 1,
		syncInfo: s,
	}
}

// newSyncState returns a new sync state with the provided parameters.
func newSyncState(startBlock, syncedTo *BlockStamp, recentHeight int32,
	recentHashes []chainhash.Hash) *syncState {

	return &syncState{
		startBlock:   *startBlock,
		syncedTo:     *syncedTo,
		recentHeight: recentHeight,
		recentHashes: recentHashes,
	}
}

// BlockIterator allows for the forwards and backwards iteration of recently
// seen blocks.
type BlockIterator struct {
	mtx      *sync.RWMutex
	height   int32
	index    int
	syncInfo *syncState
}

// Next returns the next recently seen block or false if there is not one.
func (it *BlockIterator) Next() bool {
	it.mtx.RLock()
	defer it.mtx.RUnlock()

	if it.index+1 >= len(it.syncInfo.recentHashes) {
		return false
	}
	it.index++
	return true
}

// Prev returns the previous recently seen block or false if there is not one.
func (it *BlockIterator) Prev() bool {
	it.mtx.RLock()
	defer it.mtx.RUnlock()

	if it.index-1 < 0 {
		return false
	}
	it.index--
	return true
}

// BlockStamp returns the block stamp associated with the recently seen block
// the iterator is currently pointing to.
func (it *BlockIterator) BlockStamp() BlockStamp {
	it.mtx.RLock()
	defer it.mtx.RUnlock()

	return BlockStamp{
		Height: it.syncInfo.recentHeight -
			int32(len(it.syncInfo.recentHashes)-1-it.index),
		Hash: it.syncInfo.recentHashes[it.index],
	}
}

// NewIterateRecentBlocks returns an iterator for recently-seen blocks.
// The iterator starts at the most recently-added block, and Prev should
// be used to access earlier blocks.
//
// NOTE: Ideally this should not really be a part of the address manager as it
// is intended for syncing purposes.   It is being exposed here for now to go
// with the other syncing code.  Ultimately, all syncing code should probably
// go into its own package and share the data store.
func (m *Manager) NewIterateRecentBlocks() *BlockIterator {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return m.syncState.iter(&m.mtx)
}

// SetSyncedTo marks the address manager to be in sync with the recently-seen
// block described by the blockstamp.  When the provided blockstamp is nil,
// the oldest blockstamp of the block the manager was created at and of all
// imported addresses will be used.  This effectively allows the manager to be
// marked as unsynced back to the oldest known point any of the addresses have
// appeared in the block chain.
func (m *Manager) SetSyncedTo(bs *BlockStamp) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Update the recent history.
	//
	// NOTE: The values in the memory sync state aren't directly modified
	// here in case the forthcoming db update fails.  The memory sync state
	// is updated with these values as needed after the db updates.
	recentHeight := m.syncState.recentHeight
	recentHashes := m.syncState.recentHashes
	if bs == nil {
		// Use the stored start blockstamp and reset recent hashes and
		// height when the provided blockstamp is nil.
		bs = &m.syncState.startBlock
		recentHeight = m.syncState.startBlock.Height
		recentHashes = nil

	} else if bs.Height < recentHeight {
		// When the new block stamp height is prior to the most recently
		// seen height, a rollback is being performed.  Thus, when the
		// previous block stamp is already saved, remove anything after
		// it.  Otherwise, the rollback must be too far in history, so
		// clear the recent hashes and set the recent height to the
		// current block stamp height.
		numHashes := len(recentHashes)
		idx := numHashes - 1 - int(recentHeight-bs.Height)
		if idx >= 0 && idx < numHashes && recentHashes[idx] == bs.Hash {
			// subslice out the removed hashes.
			recentHeight = bs.Height
			recentHashes = recentHashes[:idx]
		} else {
			recentHeight = bs.Height
			recentHashes = nil
		}

	} else if bs.Height != recentHeight+1 {
		// At this point the new block stamp height is after the most
		// recently seen block stamp, so it should be the next height in
		// sequence.  When this is not the case, the recent history is
		// no longer valid, so clear the recent hashes and set the
		// recent height to the current block stamp height.
		recentHeight = bs.Height
		recentHashes = nil
	} else {
		// The only case left is when the new block stamp height is the
		// next height in sequence after the most recently seen block
		// stamp, so update it accordingly.
		recentHeight = bs.Height
	}

	// Enforce maximum number of recent hashes.
	if len(recentHashes) == maxRecentHashes {
		// Shift everything down one position and add the new hash in
		// the last position.
		copy(recentHashes, recentHashes[1:])
		recentHashes[maxRecentHashes-1] = bs.Hash
	} else {
		recentHashes = append(recentHashes, bs.Hash)
	}

	// Update the database.
	err := m.namespace.Update(func(tx walletdb.Tx) error {
		err := putSyncedTo(tx, bs)
		if err != nil {
			return err
		}

		return putRecentBlocks(tx, recentHeight, recentHashes)
	})
	if err != nil {
		return err
	}

	// Update memory now that the database is updated.
	m.syncState.syncedTo = *bs
	m.syncState.recentHashes = recentHashes
	m.syncState.recentHeight = recentHeight
	return nil
}

// SyncedTo returns details about the block height and hash that the address
// manager is synced through at the very least.  The intention is that callers
// can use this information for intelligently initiating rescans to sync back to
// the best chain from the last known good block.
func (m *Manager) SyncedTo() BlockStamp {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	return m.syncState.syncedTo
}
