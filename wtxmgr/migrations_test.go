package wtxmgr

import (
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcwallet/walletdb"
)

// applyMigration is a helper function that allows us to assert the state of the
// top-level bucket before and after a migration. This can be used to ensure
// the correctness of migrations.
func applyMigration(t *testing.T,
	beforeMigration, afterMigration func(walletdb.ReadWriteBucket, *Store) error,
	migration func(walletdb.ReadWriteBucket) error, shouldFail bool) {

	t.Helper()

	// We'll start by setting up our transaction store backed by a database.
	store, db, teardown, err := testStore()
	if err != nil {
		t.Fatalf("unable to create test store: %v", err)
	}
	defer teardown()

	// First, we'll run the beforeMigration closure, which contains the
	// database modifications/assertions needed before proceeding with the
	// migration.
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(namespaceKey)
		if ns == nil {
			return errors.New("top-level namespace does not exist")
		}
		return beforeMigration(ns, store)
	})
	if err != nil {
		t.Fatalf("unable to run beforeMigration func: %v", err)
	}

	// Then, we'll run the migration itself and fail if it does not match
	// its expected result.
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(namespaceKey)
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
		ns := tx.ReadWriteBucket(namespaceKey)
		if ns == nil {
			return errors.New("top-level namespace does not exist")
		}
		return afterMigration(ns, store)
	})
	if err != nil {
		t.Fatalf("unable to run afterMigration func: %v", err)
	}
}

// TestMigrationDropTransactionHistory ensures that a transaction store is reset
// to a clean state after dropping its transaction history.
func TestMigrationDropTransactionHistory(t *testing.T) {
	t.Parallel()

	// checkTransactions is a helper function that will assert the correct
	// state of the transaction store based on whether the migration has
	// completed or not.
	checkTransactions := func(ns walletdb.ReadWriteBucket, s *Store,
		afterMigration bool) error {

		// We should see one confirmed unspent output before the
		// migration, and none after.
		utxos, err := s.UnspentOutputs(ns)
		if err != nil {
			return err
		}
		if len(utxos) == 0 && !afterMigration {
			return errors.New("expected to find 1 utxo, found none")
		}
		if len(utxos) > 0 && afterMigration {
			return fmt.Errorf("expected to find 0 utxos, found %d",
				len(utxos))
		}

		// We should see one unconfirmed transaction before the
		// migration, and none after.
		unconfirmedTxs, err := s.UnminedTxs(ns)
		if err != nil {
			return err
		}
		if len(unconfirmedTxs) == 0 && !afterMigration {
			return errors.New("expected to find 1 unconfirmed " +
				"transaction, found none")
		}
		if len(unconfirmedTxs) > 0 && afterMigration {
			return fmt.Errorf("expected to find 0 unconfirmed "+
				"transactions, found %d", len(unconfirmedTxs))
		}

		// We should have a non-zero balance before the migration, and
		// zero after.
		minedBalance, err := fetchMinedBalance(ns)
		if err != nil {
			return err
		}
		if minedBalance == 0 && !afterMigration {
			return errors.New("expected non-zero balance before " +
				"migration")
		}
		if minedBalance > 0 && afterMigration {
			return fmt.Errorf("expected zero balance after "+
				"migration, got %d", minedBalance)
		}

		return nil
	}

	beforeMigration := func(ns walletdb.ReadWriteBucket, s *Store) error {
		// We'll start by adding two transactions to the store: a
		// confirmed transaction and an unconfirmed transaction one.
		// The confirmed transaction will spend from a coinbase output,
		// while the unconfirmed will spend an output from the confirmed
		// transaction.
		cb := newCoinBase(1e8)
		cbRec, err := NewTxRecordFromMsgTx(cb, timeNow())
		if err != nil {
			return err
		}

		b := &BlockMeta{Block: Block{Height: 100}}
		confirmedSpend := spendOutput(&cbRec.Hash, 0, 5e7, 4e7)
		confirmedSpendRec, err := NewTxRecordFromMsgTx(
			confirmedSpend, timeNow(),
		)
		if err := s.InsertTx(ns, confirmedSpendRec, b); err != nil {
			return err
		}
		err = s.AddCredit(ns, confirmedSpendRec, b, 1, true)
		if err != nil {
			return err
		}

		unconfimedSpend := spendOutput(
			&confirmedSpendRec.Hash, 0, 5e6, 5e6,
		)
		unconfirmedSpendRec, err := NewTxRecordFromMsgTx(
			unconfimedSpend, timeNow(),
		)
		if err != nil {
			return err
		}
		if err := s.InsertTx(ns, unconfirmedSpendRec, nil); err != nil {
			return err
		}
		err = s.AddCredit(ns, unconfirmedSpendRec, nil, 1, true)
		if err != nil {
			return err
		}

		// Ensure these transactions exist within the store.
		return checkTransactions(ns, s, false)
	}

	afterMigration := func(ns walletdb.ReadWriteBucket, s *Store) error {
		// Assuming the migration was successful, we should see that the
		// store no longer has the transaction history prior to the
		// migration.
		return checkTransactions(ns, s, true)
	}

	// We can now apply the migration and expect it not to fail.
	applyMigration(
		t, beforeMigration, afterMigration, dropTransactionHistory,
		false,
	)
}
