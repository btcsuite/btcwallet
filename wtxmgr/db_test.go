// Copyright (c) 2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wtxmgr

import (
	"bytes"
	"testing"

	"github.com/boltdb/bolt"
	"github.com/decred/dcrwallet/walletdb"
)

func TestCursorDeletions(t *testing.T) {
	t.Skip("Cursor deletion APIs have been removed until bolt issue #620 is resolved")

	db, _, teardown, err := setup()
	defer teardown()
	if err != nil {
		t.Fatal(err)
	}

	err = walletdb.Update(db, func(dbtx walletdb.ReadWriteTx) error {
		txHash := decodeHash("2b29213f06354455c235021e541604607ed738b1bc6217f2fe3ae5bffbfe1218")
		ks := [][]byte{
			canonicalOutPoint(txHash, 0),
			canonicalOutPoint(txHash, 1),
		}
		vs := [][]byte{
			valueUnminedCredit(1e8, false, 0, false, scriptTypeP2PKH, 0, 0, 0),
			valueUnminedCredit(2e8, true, 0, false, scriptTypeP2PKH, 0, 0, 0),
		}

		ns := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)
		for i := range ks {
			err = putRawUnminedCredit(ns, ks[i], vs[i])
			if err != nil {
				return err
			}
		}

		iterations := 0

		// Test the iterator iterates over each.
		it := makeUnminedCreditIterator(ns, txHash)
		for it.next() {
			iterations++
		}
		if iterations != 2 {
			t.Errorf("Expected to iterate over two k/v pairs, but iterated %v time(s)", iterations)
		}

		iterations = 0

		// Test the iterator can be used to delete each.
		it = makeUnminedCreditIterator(ns, txHash)
		for it.next() {
			//err = it.delete()
			if err != nil {
				return err
			}
			iterations++
		}
		if iterations != 2 {
			t.Errorf("Expected to iterate over and delete two k/v pairs, but iterated %v time(s)", iterations)
		}

		it = makeUnminedCreditIterator(ns, txHash)
		for it.next() {
			t.Error("Did not delete every k/v pair from bucket using iterator")
			break
		}

		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestBoltDBCursorDeletion(t *testing.T) {
	t.Skip("Skipping known failing test demonstrating upstream bolt issue #620")

	db, teardown, err := setupBoltDB()
	defer teardown()
	if err != nil {
		t.Fatal(err)
	}

	err = db.Update(func(dbtx *bolt.Tx) error {
		b, err := dbtx.CreateBucket(wtxmgrNamespaceKey)
		if err != nil {
			return err
		}

		txHash := decodeHash("2b29213f06354455c235021e541604607ed738b1bc6217f2fe3ae5bffbfe1218")
		ks := [][]byte{
			canonicalOutPoint(txHash, 0),
			canonicalOutPoint(txHash, 1),
			canonicalOutPoint(txHash, 2),
			canonicalOutPoint(txHash, 3),
		}
		vs := [][]byte{
			valueUnminedCredit(1e8, false, 0, false, scriptTypeP2PKH, 0, 0, 0),
			valueUnminedCredit(2e8, true, 0, false, scriptTypeP2PKH, 0, 0, 0),
			valueUnminedCredit(3e8, true, 0, false, scriptTypeP2PKH, 0, 0, 0),
			valueUnminedCredit(4e8, true, 0, false, scriptTypeP2PKH, 0, 0, 0),
		}

		for i := range ks {
			err = b.Put(ks[i], vs[i])
			if err != nil {
				return err
			}
		}

		iterations := 0

		c := b.Cursor()
		for k, _ := c.Seek(txHash[:]); bytes.HasPrefix(k, txHash[:]); k, _ = c.Next() {
			iterations++
		}

		if iterations != 4 {
			t.Errorf("Expected to iterate over four k/v pairs, but iterated %v time(s)", iterations)
		}

		iterations = 0

		// Test the iterator can be used to delete each.
		c = b.Cursor()
		for k, _ := c.Seek(txHash[:]); bytes.HasPrefix(k, txHash[:]); k, _ = c.Next() {
			err = c.Delete()
			if err != nil {
				return err
			}
			iterations++
		}
		if iterations != 4 {
			t.Errorf("Expected to iterate over and delete four k/v pairs, but iterated %v time(s)", iterations)
		}

		c = b.Cursor()
		for k, v := c.Seek(txHash[:]); bytes.HasPrefix(k, txHash[:]); k, v = c.Next() {
			t.Errorf("bucket still has key %x value %x", k, v)
		}

		return nil
	})
	if err != nil {
		t.Error(err)
	}
}
