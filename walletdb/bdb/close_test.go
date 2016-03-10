// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bdb

import (
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/btcsuite/btcwallet/walletdb"
)

func doWithDb(t *testing.T, action func(walletdb.DB, walletdb.Namespace)) {
	dbPath := "closetest.db"
	db, err := walletdb.Create(dbType, dbPath)
	if err != nil {
		t.Fatalf("Failed to create db: %v", err)
	}
	defer os.Remove(dbPath)

	ns, err := db.Namespace([]byte("ns"))
	if err != nil {
		t.Fatalf("Failed to create namespace: %v", err)
	}

	action(db, ns)
}

func TestCloseWithActiveTxs(t *testing.T) {
	closeErrs := make(chan error)
	commitErrs := make(chan error)

	var step int
	var stepMu sync.Mutex
	incrementStep := func() int {
		stepMu.Lock()
		s := step
		step++
		stepMu.Unlock()
		return s
	}
	resetStep := func() {
		stepMu.Lock()
		step = 0
		stepMu.Unlock()
	}
	getStep := func() int {
		stepMu.Lock()
		s := step
		stepMu.Unlock()
		return s
	}

	doWithDb(t, func(db walletdb.DB, ns walletdb.Namespace) {
		writeTx, err := ns.Begin(true)
		if err != nil {
			t.Fatalf("Failed to begin write transaction: %v", err)
		}
		unblockCommit := make(chan struct{})
		go func() {
			err := db.Close()
			if incrementStep() != 1 {
				err = errors.New("Closed db with active write transaction")
			}
			closeErrs <- err
		}()
		go func() {
			<-unblockCommit
			err := writeTx.Commit()
			if incrementStep() != 0 {
				err = errors.New("Closed transaction after database closed")
			}
			commitErrs <- err
		}()
		writeTx.RootBucket().Put([]byte("key"), []byte("val"))
		_ = writeTx.RootBucket().Get([]byte("key"))
		close(unblockCommit)
		for getStep() != 2 {
			select {
			case err := <-closeErrs:
				if err != nil {
					t.Fatal(err)
				}
			case err := <-commitErrs:
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		resetStep()
	})
}

/*
	err = writeTx.Commit()
	if err != nil {
		t.Fatalf("Failed to commit tx: %v", err)
	}
	select {
	case <-closeErrs: // ok
	default:
		t.Fatal("Did not close DB after write tx exited")
	}

	readTx0, err := ns.Begin(false)
	if err != nil {
		t.Fatalf("Failed to begin read transaction: %v", err)
	}
	_ = readTx0.RootBucket().Get([]byte("key"))
	go func() {
		closeErrs <- db.Close()
	}()
	select {
	case <-closeErrs:
		t.Fatal("Closed database with 1 active read transacton")
	default:
	}
	err = readTx0.Commit()
	if err != nil {
		t.Fatalf("Failed to close read transaction 0: %v", err)
	}
*/
