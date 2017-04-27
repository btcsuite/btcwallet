// Copyright (c) 2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package votingpool

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/btcsuite/btcwallet/walletdb"
)

func TestPutUsedAddrHash(t *testing.T) {
	tearDown, db, pool := TstCreatePool(t)
	defer tearDown()

	dummyHash := bytes.Repeat([]byte{0x09}, 10)
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, _ := TstRWNamespaces(tx)
		return putUsedAddrHash(ns, pool.ID, 0, 0, 0, dummyHash)
	})
	if err != nil {
		t.Fatal(err)
	}

	var storedHash []byte
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns, _ := TstRNamespaces(tx)
		storedHash = getUsedAddrHash(ns, pool.ID, 0, 0, 0)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedHash, dummyHash) {
		t.Fatalf("Wrong stored hash; got %x, want %x", storedHash, dummyHash)
	}
}

func TestGetMaxUsedIdx(t *testing.T) {
	tearDown, db, pool := TstCreatePool(t)
	defer tearDown()

	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, _ := TstRWNamespaces(tx)
		for i, idx := range []int{0, 7, 9, 3001, 41, 500, 6} {
			dummyHash := bytes.Repeat([]byte{byte(i)}, 10)
			err := putUsedAddrHash(ns, pool.ID, 0, 0, Index(idx), dummyHash)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var maxIdx Index
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns, _ := TstRNamespaces(tx)
		var err error
		maxIdx, err = getMaxUsedIdx(ns, pool.ID, 0, 0)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if maxIdx != Index(3001) {
		t.Fatalf("Wrong max idx; got %d, want %d", maxIdx, Index(3001))
	}
}

func TestWithdrawalSerialization(t *testing.T) {
	tearDown, db, pool := TstCreatePool(t)
	defer tearDown()

	dbtx, err := db.BeginReadWriteTx()
	if err != nil {
		t.Fatal(err)
	}
	defer dbtx.Commit()
	ns, addrmgrNs := TstRWNamespaces(dbtx)

	roundID := uint32(0)
	wi := createAndFulfillWithdrawalRequests(t, dbtx, pool, roundID)

	serialized, err := serializeWithdrawal(wi.requests, wi.startAddress, wi.lastSeriesID,
		wi.changeStart, wi.dustThreshold, wi.status)
	if err != nil {
		t.Fatal(err)
	}

	var wInfo *withdrawalInfo
	TstRunWithManagerUnlocked(t, pool.Manager(), addrmgrNs, func() {
		wInfo, err = deserializeWithdrawal(pool, ns, addrmgrNs, serialized)
		if err != nil {
			t.Fatal(err)
		}
	})

	if !reflect.DeepEqual(wInfo.startAddress, wi.startAddress) {
		t.Fatalf("Wrong startAddr; got %v, want %v", wInfo.startAddress, wi.startAddress)
	}

	if !reflect.DeepEqual(wInfo.changeStart, wi.changeStart) {
		t.Fatalf("Wrong changeStart; got %v, want %v", wInfo.changeStart, wi.changeStart)
	}

	if wInfo.lastSeriesID != wi.lastSeriesID {
		t.Fatalf("Wrong LastSeriesID; got %d, want %d", wInfo.lastSeriesID, wi.lastSeriesID)
	}

	if wInfo.dustThreshold != wi.dustThreshold {
		t.Fatalf("Wrong DustThreshold; got %d, want %d", wInfo.dustThreshold, wi.dustThreshold)
	}

	if !reflect.DeepEqual(wInfo.requests, wi.requests) {
		t.Fatalf("Wrong output requests; got %v, want %v", wInfo.requests, wi.requests)
	}

	TstCheckWithdrawalStatusMatches(t, wInfo.status, wi.status)
}

func TestPutAndGetWithdrawal(t *testing.T) {
	tearDown, db, _ := TstCreatePool(t)
	defer tearDown()

	serialized := bytes.Repeat([]byte{1}, 10)
	poolID := []byte{0x00}
	roundID := uint32(0)
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns, _ := TstRWNamespaces(tx)
		return putWithdrawal(ns, poolID, roundID, serialized)
	})
	if err != nil {
		t.Fatal(err)
	}

	var retrieved []byte
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns, _ := TstRNamespaces(tx)
		retrieved = getWithdrawal(ns, poolID, roundID)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(retrieved, serialized) {
		t.Fatalf("Wrong value retrieved from DB; got %x, want %x", retrieved, serialized)
	}
}
