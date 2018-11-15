package waddrmgr

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/walletdb"
)

// applyMigration is a helper function that allows us to assert the state of the
// top-level bucket before and after a migration. This can be used to ensure
// the correctness of migrations.
func applyMigration(t *testing.T, beforeMigration, afterMigration,
	migration func(walletdb.ReadWriteBucket) error, shouldFail bool) {

	t.Helper()

	// We'll start by setting up our address manager backed by a database.
	teardown, db, _ := setupManager(t)
	defer teardown()

	// First, we'll run the beforeMigration closure, which contains the
	// database modifications/assertions needed before proceeding with the
	// migration.
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errors.New("top-level namespace does not exist")
		}
		return beforeMigration(ns)
	})
	if err != nil {
		t.Fatalf("unable to run beforeMigration func: %v", err)
	}

	// Then, we'll run the migration itself and fail if it does not match
	// its expected result.
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errors.New("top-level namespace does not exist")
		}
		return migration(ns)
	})
	if err != nil && !shouldFail {
		t.Fatalf("unable to perform migration: %v", err)
	} else if err == nil && shouldFail {
		t.Fatal("expected migration to fail, but did not")
	}

	// Finally, we'll run the afterMigration closure, which contains the
	// assertions needed in order to guarantee than the migration was
	// successful.
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if ns == nil {
			return errors.New("top-level namespace does not exist")
		}
		return afterMigration(ns)
	})
	if err != nil {
		t.Fatalf("unable to run afterMigration func: %v", err)
	}
}

// TestMigrationPupulateBirthdayBlock ensures that the migration to populate the
// wallet's birthday block works as intended.
func TestMigrationPopulateBirthdayBlock(t *testing.T) {
	t.Parallel()

	var expectedHeight int32
	beforeMigration := func(ns walletdb.ReadWriteBucket) error {
		// To test this migration, we'll start by writing to disk 10
		// random blocks.
		block := &BlockStamp{}
		for i := int32(1); i <= 10; i++ {
			block.Height = i
			blockHash := bytes.Repeat([]byte(string(i)), 32)
			copy(block.Hash[:], blockHash)
			if err := putSyncedTo(ns, block); err != nil {
				return err
			}
		}

		// With the blocks inserted, we'll assume that the birthday
		// block corresponds to the 7th block (out of 11) in the chain.
		// To do this, we'll need to set our birthday timestamp to the
		// estimated timestamp of a block that's 6 blocks after genesis.
		genesisTimestamp := chaincfg.MainNetParams.GenesisBlock.Header.Timestamp
		delta := time.Hour
		expectedHeight = int32(delta.Seconds() / 600)
		birthday := genesisTimestamp.Add(delta)
		if err := putBirthday(ns, birthday); err != nil {
			return err
		}

		// Finally, since the migration has not yet started, we should
		// not be able to find the birthday block within the database.
		_, err := fetchBirthdayBlock(ns)
		if !IsError(err, ErrBirthdayBlockNotSet) {
			return fmt.Errorf("expected ErrBirthdayBlockNotSet, "+
				"got %v", err)
		}

		return nil
	}

	// After the migration has completed, we should see that the birthday
	// block now exists and is set to the correct expected height.
	afterMigration := func(ns walletdb.ReadWriteBucket) error {
		birthdayBlock, err := fetchBirthdayBlock(ns)
		if err != nil {
			return err
		}

		if birthdayBlock.Height != expectedHeight {
			return fmt.Errorf("expected birthday block with "+
				"height %d, got %d", expectedHeight,
				birthdayBlock.Height)
		}

		return nil
	}

	// We can now apply the migration and expect it not to fail.
	applyMigration(
		t, beforeMigration, afterMigration, populateBirthdayBlock,
		false,
	)
}

// TestMigrationPopulateBirthdayBlockEstimateTooFar ensures that the migration
// can properly detect a height estimate which the chain from our point of view
// has not yet reached.
func TestMigrationPopulateBirthdayBlockEstimateTooFar(t *testing.T) {
	t.Parallel()

	const numBlocks = 1000
	chainParams := chaincfg.MainNetParams

	var expectedHeight int32
	beforeMigration := func(ns walletdb.ReadWriteBucket) error {
		// To test this migration, we'll start by writing to disk 999
		// random blocks to simulate a synced chain with height 1000.
		block := &BlockStamp{}
		for i := int32(1); i < numBlocks; i++ {
			block.Height = i
			blockHash := bytes.Repeat([]byte(string(i)), 32)
			copy(block.Hash[:], blockHash)
			if err := putSyncedTo(ns, block); err != nil {
				return err
			}
		}

		// With the blocks inserted, we'll assume that the birthday
		// block corresponds to the 900th block in the chain. To do
		// this, we'd need to set our birthday timestamp to the
		// estimated timestamp of a block that's 899 blocks after
		// genesis. However, this will not work if the average block
		// time is not 10 mins, which can throw off the height estimate
		// with a height longer than the chain in the event of test
		// networks (testnet, regtest, etc. and not fully synced
		// wallets). Instead the migration should be able to handle this
		// by subtracting a days worth of blocks until finding a block
		// that it is aware of.
		//
		// We'll have the migration assume that our birthday is at block
		// 1001 in the chain. Since this block doesn't exist from the
		// database's point of view, a days worth of blocks will be
		// subtracted from the estimate, which should give us a valid
		// block height.
		genesisTimestamp := chainParams.GenesisBlock.Header.Timestamp
		delta := numBlocks * 10 * time.Minute
		expectedHeight = numBlocks - 144

		birthday := genesisTimestamp.Add(delta)
		if err := putBirthday(ns, birthday); err != nil {
			return err
		}

		// Finally, since the migration has not yet started, we should
		// not be able to find the birthday block within the database.
		_, err := fetchBirthdayBlock(ns)
		if !IsError(err, ErrBirthdayBlockNotSet) {
			return fmt.Errorf("expected ErrBirthdayBlockNotSet, "+
				"got %v", err)
		}

		return nil
	}

	// After the migration has completed, we should see that the birthday
	// block now exists and is set to the correct expected height.
	afterMigration := func(ns walletdb.ReadWriteBucket) error {
		birthdayBlock, err := fetchBirthdayBlock(ns)
		if err != nil {
			return err
		}

		if birthdayBlock.Height != expectedHeight {
			return fmt.Errorf("expected birthday block height %d, "+
				"got %d", expectedHeight, birthdayBlock.Height)
		}

		return nil
	}

	// We can now apply the migration and expect it not to fail.
	applyMigration(
		t, beforeMigration, afterMigration, populateBirthdayBlock,
		false,
	)
}
