/*
 * Copyright (c) 2014 Conformal Systems LLC <info@conformal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package waddrmgr

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/walletdb"
)

var (
	// seed is the master seed used throughout the tests.
	seed = []byte{
		0x2a, 0x64, 0xdf, 0x08, 0x5e, 0xef, 0xed, 0xd8, 0xbf,
		0xdb, 0xb3, 0x31, 0x76, 0xb5, 0xba, 0x2e, 0x62, 0xe8,
		0xbe, 0x8b, 0x56, 0xc8, 0x83, 0x77, 0x95, 0x59, 0x8b,
		0xb6, 0xc4, 0x40, 0xc0, 0x64,
	}

	pubPassphrase  = []byte("_DJr{fL4H0O}*-0\n:V1izc)(6BomK")
	privPassphrase = []byte("81lUHXnOMZ@?XXd7O9xyDIWIbXX-lj")

	// fastScrypt are parameters used throughout the tests to speed up the
	// scrypt operations.
	fastScrypt = &Options{
		ScryptN: 16,
		ScryptR: 8,
		ScryptP: 1,
	}
	waddrmgrNamespaceKey = []byte("waddrmgrNamespace")
)

// createDbNamespace creates a new wallet database at the provided path and
// returns it along with the address manager namespace.
func createDbNamespace(dbPath string) (walletdb.DB, walletdb.Namespace, error) {
	db, err := walletdb.Create("bdb", dbPath)
	if err != nil {
		return nil, nil, err
	}

	namespace, err := db.Namespace(waddrmgrNamespaceKey)
	if err != nil {
		db.Close()
		return nil, nil, err
	}

	return db, namespace, nil
}

// testVersion tests that the manager is at the expected version
func testVersion(t *testing.T, namespace walletdb.Namespace, wantVersion uint32) {
	var gotVersion uint32
	err := namespace.View(func(tx walletdb.Tx) error {
		var err error
		gotVersion, err = fetchManagerVersion(tx)
		return err
	})
	if err != nil {
		t.Errorf("version: unexpected error: %v", err)
	}
	if gotVersion != wantVersion {
		t.Errorf("Upgrade Manager "+
			"version mismatch -- got %d, "+
			"want %d", gotVersion, wantVersion)
	}
}

// testUpgradeToVersion2 tests that applying version 2 upgrade works as expected
func testUpgradeToVersion2(t *testing.T, namespace walletdb.Namespace) {
	if err := upgradeToVersion2(namespace); err != nil {
		t.Errorf("Upgrade Manager (version 2): upgrade failed - %v", err)
		return
	}

	err := namespace.View(func(tx walletdb.Tx) error {
		bucket := tx.RootBucket().Bucket(usedAddrBucketName)
		if bucket == nil {
			str := fmt.Sprintf("missing bucket %s", usedAddrBucketName)
			return errors.New(str)
		}
		return nil
	})
	if err != nil {
		t.Errorf("Upgrade Manager (version 2): unexpected err - %v", err)
	}
}

// testUpgradeToVersion3 tests that applying version 3 upgrade works as expected
func testUpgradeToVersion3(t *testing.T, namespace walletdb.Namespace) {
	if err := upgradeToVersion3(namespace, seed, pubPassphrase, privPassphrase); err != nil {
		t.Errorf("Upgrade Manager (version 2): upgrade failed - %v", err)
		return
	}

	err := namespace.View(func(tx walletdb.Tx) error {
		bucket := tx.RootBucket().Bucket(acctNameIdxBucketName)
		if bucket == nil {
			str := fmt.Sprintf("missing bucket %s", acctNameIdxBucketName)
			return errors.New(str)
		}

		bucket = tx.RootBucket().Bucket(acctIDIdxBucketName)
		if bucket == nil {
			str := fmt.Sprintf("missing bucket %s", acctIDIdxBucketName)
			return errors.New(str)
		}

		bucket = tx.RootBucket().Bucket(metaBucketName)
		if bucket == nil {
			str := fmt.Sprintf("missing bucket %s", metaBucketName)
			return errors.New(str)
		}

		gotCTPubKeyEnc, gotCTPrivKeyEnc, err := fetchCoinTypeKeys(tx)
		if err != nil {
			return err
		}

		if gotCTPubKeyEnc == nil {
			t.Errorf("Upgrade Manager " +
				"missing encrypted cointype public key")
		}

		if gotCTPrivKeyEnc == nil {
			t.Errorf("Upgrade Manager " +
				"missing encrypted cointype private key")
		}

		gotDefaultAccountName, err := fetchAccountName(tx, DefaultAccountNum)
		if err != nil {
			return err
		}
		if gotDefaultAccountName != DefaultAccountName {
			t.Errorf("Upgrade Manager "+
				"default account name mismatch"+
				"got %v, want %v", gotDefaultAccountName, DefaultAccountName)
		}

		gotImportedAccountName, err := fetchAccountName(tx, ImportedAddrAccount)
		if err != nil {
			return err
		}
		if gotImportedAccountName != ImportedAddrAccountName {
			t.Errorf("Upgrade Manager "+
				"imported account name mismatch"+
				"got %v, want %v", gotImportedAccountName, ImportedAddrAccountName)
		}

		gotLastAccount, err := fetchLastAccount(tx)
		if err != nil {
			return err
		}
		if gotLastAccount != DefaultAccountNum {
			t.Errorf("Upgrade Manager "+
				"last account mismatch"+
				"got %d, want %d", gotLastAccount, DefaultAccountNum)
		}

		gotAccount, err := fetchAccountByName(tx, "")
		if err != nil {
			return err
		}
		if gotAccount != DefaultAccountNum {
			t.Errorf("Upgrade Manager "+
				"default account alias mismatch"+
				"got %d, want %d", gotAccount, DefaultAccountNum)
		}
		return nil
	})
	if err != nil {
		t.Errorf("Upgrade Manager (version 3): unexpected error - %v", err)
	}
}

// TestUpgrade tests that the upgrades apply to the initial database version as
// expected.
func TestUpgrade(t *testing.T) {
	upMgrName := "upmgrtest.bin"
	db, namespace, err := createDbNamespace(upMgrName)
	if err != nil {
		t.Errorf("createDbNamespace: unexpected error: %v", err)
		return
	}
	defer db.Close()
	defer os.Remove(upMgrName)

	// Disable automatic upgrades so we can test each one individually
	autoUpgradeManager := upgradeManager
	upgradeManager = func(namespace walletdb.Namespace, seed, pubPassPhrase,
		privPassPhrase []byte, config *Options) error {
		return nil
	}

	// Create a new manager.
	_, err = Create(namespace, seed, pubPassphrase,
		privPassphrase, &chaincfg.MainNetParams, fastScrypt)
	if err != nil {
		t.Errorf("Create: unexpected error: %v", err)
		return
	}

	// Test that manager is the initial version
	testVersion(t, namespace, 1)

	// Apply and test each upgrade
	testUpgradeToVersion2(t, namespace)
	testUpgradeToVersion3(t, namespace)

	// After all upgrades, test that manager is the latest version
	testVersion(t, namespace, latestMgrVersion)

	// Restore auto upgradeManager for other tests
	upgradeManager = autoUpgradeManager
	return
}
