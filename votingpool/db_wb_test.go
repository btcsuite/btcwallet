// Copyright (c) 2015 The btcsuite developers
// Copyright (c) 2015 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package votingpool

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/decred/dcrwallet/walletdb"
)

func TestPutUsedAddrHash(t *testing.T) {
	tearDown, _, pool := TstCreatePool(t)
	defer tearDown()

	dummyHash := bytes.Repeat([]byte{0x09}, 10)
	err := pool.namespace.Update(
		func(tx walletdb.Tx) error {
			return putUsedAddrHash(tx, pool.ID, 0, 0, 0, dummyHash)
		})
	if err != nil {
		t.Fatal(err)
	}

	var storedHash []byte
	err = pool.namespace.View(
		func(tx walletdb.Tx) error {
			storedHash = getUsedAddrHash(tx, pool.ID, 0, 0, 0)
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
	tearDown, _, pool := TstCreatePool(t)
	defer tearDown()

	var err error
	pool.namespace.Update(
		func(tx walletdb.Tx) error {
			for i, idx := range []int{0, 7, 9, 3001, 41, 500, 6} {
				dummyHash := bytes.Repeat([]byte{byte(i)}, 10)
				err = putUsedAddrHash(tx, pool.ID, 0, 0, Index(idx), dummyHash)
				if err != nil {
					t.Fatal(err)
				}
			}
			return nil
		})

	var maxIdx Index
	pool.namespace.View(
		func(tx walletdb.Tx) error {
			maxIdx, err = getMaxUsedIdx(tx, pool.ID, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			return nil
		})
	if maxIdx != Index(3001) {
		t.Fatalf("Wrong max idx; got %d, want %d", maxIdx, Index(3001))
	}
}

func TestWithdrawalSerialization(t *testing.T) {
	tearDown, _, pool := TstCreatePool(t)
	defer tearDown()

	roundID := uint32(0)
	wi := createAndFulfillWithdrawalRequests(t, pool, roundID)

	serialized, err := serializeWithdrawal(wi.requests, wi.startAddress, wi.lastSeriesID,
		wi.changeStart, wi.dustThreshold, wi.status)
	if err != nil {
		t.Fatal(err)
	}

	var wInfo *withdrawalInfo
	TstRunWithManagerUnlocked(t, pool.Manager(), func() {
		wInfo, err = deserializeWithdrawal(pool, serialized)
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
	tearDown, _, pool := TstCreatePool(t)
	defer tearDown()

	serialized := bytes.Repeat([]byte{1}, 10)
	poolID := []byte{0x00}
	roundID := uint32(0)
	err := pool.namespace.Update(
		func(tx walletdb.Tx) error {
			return putWithdrawal(tx, poolID, roundID, serialized)
		})
	if err != nil {
		t.Fatal(err)
	}

	var retrieved []byte
	err = pool.namespace.View(
		func(tx walletdb.Tx) error {
			retrieved = getWithdrawal(tx, poolID, roundID)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(retrieved, serialized) {
		t.Fatalf("Wrong value retrieved from DB; got %x, want %x", retrieved, serialized)
	}
}
