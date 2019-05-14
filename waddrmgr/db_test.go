package waddrmgr

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/walletdb"
)

// TestStoreMaxReorgDepth ensures that we can only store up to MaxReorgDepth
// blocks at any given time.
func TestStoreMaxReorgDepth(t *testing.T) {
	t.Parallel()

	teardown, db, _ := setupManager(t)
	defer teardown()

	// We'll start the test by simulating a synced chain where we start from
	// 1000 and end at 109999.
	const (
		startHeight = 1000
		numBlocks   = MaxReorgDepth - 1
	)

	blocks := make([]*BlockStamp, 0, numBlocks)
	for i := int32(startHeight); i <= startHeight+numBlocks; i++ {
		var hash chainhash.Hash
		binary.BigEndian.PutUint32(hash[:], uint32(i))
		blocks = append(blocks, &BlockStamp{
			Hash:   hash,
			Height: i,
		})
	}

	// We'll write all of the blocks to the database.
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		for _, block := range blocks {
			if err := PutSyncedTo(ns, block); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// We should be able to retrieve them all as we have MaxReorgDepth
	// blocks.
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		syncedTo, err := fetchSyncedTo(ns)
		if err != nil {
			return err
		}
		lastBlock := blocks[len(blocks)-1]
		if syncedTo.Height != lastBlock.Height {
			return fmt.Errorf("expected synced to block height "+
				"%v, got %v", lastBlock.Height, syncedTo.Height)
		}
		if syncedTo.Hash != lastBlock.Hash {
			return fmt.Errorf("expected synced to block hash %v, "+
				"got %v", lastBlock.Hash, syncedTo.Hash)
		}

		firstBlock := blocks[0]
		hash, err := fetchBlockHash(ns, firstBlock.Height)
		if err != nil {
			return err
		}
		if *hash != firstBlock.Hash {
			return fmt.Errorf("expected hash %v for height %v, "+
				"got %v", firstBlock.Hash, firstBlock.Height,
				hash)
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Then, we'll create a new block which we'll use to extend the chain.
	lastBlock := blocks[len(blocks)-1]
	newBlockHeight := lastBlock.Height + 1
	var newBlockHash chainhash.Hash
	binary.BigEndian.PutUint32(newBlockHash[:], uint32(newBlockHeight))
	newBlock := &BlockStamp{Height: newBlockHeight, Hash: newBlockHash}

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		return PutSyncedTo(ns, newBlock)
	})
	if err != nil {
		t.Fatal(err)
	}

	// Extending the chain would cause us to exceed our MaxReorgDepth blocks
	// stored, so we should see the first block we ever added to now be
	// removed.
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		syncedTo, err := fetchSyncedTo(ns)
		if err != nil {
			return err
		}
		if syncedTo.Height != newBlock.Height {
			return fmt.Errorf("expected synced to block height "+
				"%v, got %v", newBlock.Height, syncedTo.Height)
		}
		if syncedTo.Hash != newBlock.Hash {
			return fmt.Errorf("expected synced to block hash %v, "+
				"got %v", newBlock.Hash, syncedTo.Hash)
		}

		firstBlock := blocks[0]
		_, err = fetchBlockHash(ns, firstBlock.Height)
		if !IsError(err, ErrBlockNotFound) {
			return fmt.Errorf("expected ErrBlockNotFound, got %v",
				err)
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
