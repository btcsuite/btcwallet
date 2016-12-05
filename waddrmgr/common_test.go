// Copyright (c) 2014 The btcsuite developers
// Copyright (c) 2015 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Test must be updated for API changes.
//+build disabled

package waddrmgr_test

import (
	"encoding/hex"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrwallet/waddrmgr"
	"github.com/decred/dcrwallet/walletdb"
	_ "github.com/decred/dcrwallet/walletdb/bdb"
)

var (
	// seed is the master seed used throughout the tests.
	seed = []byte{
		0xb4, 0x6b, 0xc6, 0x50, 0x2a, 0x30, 0xbe, 0xb9, 0x2f,
		0x0a, 0xeb, 0xc7, 0x76, 0x40, 0x3c, 0x3d, 0xbf, 0x11,
		0xbf, 0xb6, 0x83, 0x05, 0x96, 0x7c, 0x36, 0xda, 0xc9,
		0xef, 0x8d, 0x64, 0x15, 0x67,
	}

	pubPassphrase   = []byte("_DJr{fL4H0O}*-0\n:V1izc)(6BomK")
	privPassphrase  = []byte("81lUHXnOMZ@?XXd7O9xyDIWIbXX-lj")
	pubPassphrase2  = []byte("-0NV4P~VSJBWbunw}%<Z]fuGpbN[ZI")
	privPassphrase2 = []byte("~{<]08%6!-?2s<$(8$8:f(5[4/!/{Y")

	// fastScrypt are parameters used throughout the tests to speed up the
	// scrypt operations.
	fastScrypt = &waddrmgr.ScryptOptions{
		N: 16,
		R: 8,
		P: 1,
	}

	// waddrmgrNamespaceKey is the namespace key for the waddrmgr package.
	waddrmgrNamespaceKey = []byte("waddrmgrNamespace")

	// expectedAddrs is the list of all expected addresses generated from the
	// seed.
	expectedAddrs = []expectedAddr{
		{
			address:     "TsU4c9NBMajGb5eYv8Nf6mW9yaQoQCYcUpR",
			addressHash: hexToBytes("21604e6679b943734c61297c94bc6e347d19722a"),
			internal:    false,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("02065884ce63ee2f66e82f8aa7b8a584bd0cb658a16860ea1c685dc6499b06dad1"),
			privKey:     hexToBytes("31258faa30c4f36b600682cf586db377e327a7f2fdcef39a91e18f5e6e9b8839"),
			privKeyWIF:  "PtWTuWf7uRYgteK8tDtfwNWdhADh9auKtrE8nNUyGdLAprZLYMPCc",
		},
		{
			address:     "TsThths61ijMNmyK5r5uJirYh9x2Dz5mkcb",
			addressHash: hexToBytes("1d756518d95c3736a4316e7ee2b2f88da2d2d4ad"),
			internal:    false,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("03799f30387b2a8c65591368cf7d9d9d5e4245f369a90895c4e2b22e811a18796a"),
			privKey:     hexToBytes("9023cb7b8e9ae0a2cd411a07adeeff7780e9f1906e3de811f25a6a0ea3c404e5"),
			privKeyWIF:  "PtWUdM8TCGSju37965fkkq1GrEuhfiNzu8zcEc8uN65H4ni9JzXTX",
		},
		{
			address:     "TsnjoqZTUMC4n86KrJqTxsSxfcVZLknRhpt",
			addressHash: hexToBytes("ee3c8dbf4bd6f66f7350f4653dd103f7e78cc72f"),
			internal:    false,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("03dd95cca091f9d06e0cfdfccac75f15057a11e350d416efffda9ec17e61e2a925"),
			privKey:     hexToBytes("9c88b9f930f90f958743671a0dd8e9f74a812928d3a2d1d29e30efb63f5b99b4"),
			privKeyWIF:  "PtWUioixEtzc1ErPYykYbJtZSyuWkiXfeppNCuzuK4HFm959M8EQX",
		},
		{
			address:     "TsbKRJEDT4ojPoYqVM6Y9xvfAsTbC4tHYx7",
			addressHash: hexToBytes("70f65f12e52786853d53cdf126c03b61b7421948"),
			internal:    false,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("03c642fc8e9133682787b70f0a11958617353c6d9a850ebd346b1e5769a5273dee"),
			privKey:     hexToBytes("a29362a8d9c45754468bcc106e56fc085e61d13cca95aa68e618e96e7fce4b7d"),
			privKeyWIF:  "PtWUmU3qCju8NeXguuAqnHpVHrQpJMQBWTywkwJeXKkXgg8hSqgXG",
		},
		{
			address:     "TsgpA7siAKgSWa5cdm6PPJ8WjZHuZBzTWw7",
			addressHash: hexToBytes("ad3e648f4a3ffe73816fc2ead468b955514a10c9"),
			internal:    false,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("03bd60247ae5cda41aa6c0da7f36b9c296ae591fccf7bcb6c5207c8968a5ff08a9"),
			privKey:     hexToBytes("4f2ad247fba882d746199af6b32e3f12d1790d6a8ae512720d4dee2db6f7375b"),
			privKeyWIF:  "PtWU8jVXVuntE1Jazn4e3NUofYR1cveo9LZhHpN9frA2hvwnzNn36",
		},
		{
			address:     "TsTQPUbv4Amvbf2W7YpJtz56Fz3kynP6JUB",
			addressHash: hexToBytes("1a25ecba04a7552fc875420738badfe47e6dbf0e"),
			internal:    true,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("038c2816d53e69e4bda46c208070a0dc08a53324b8ab06012b22dd01333650d29b"),
			privKey:     hexToBytes("1fbe840701f9f8b76c3caea7c6830388f3e6004bde25a2f3aafa9803e5c46a94"),
			privKeyWIF:  "PtWTmr8izsePN9u3AUcoDpXz6sSLKUa9H8B6fDF2wX8cyQEXYoKWP",
		},
		{
			address:     "TsauUQn4HJDszuRVHNo6vjsVZphBVDQwwdG",
			addressHash: hexToBytes("6c6efca0cde6bb8c83468a0f454ab3c63758cd63"),
			internal:    true,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("0393c925e9e3e551c67f3c2a24dd0a9d760a6006d194906b8a4f25b7a02cf89fb3"),
			privKey:     hexToBytes("4713f7a949ee00099882e3a78e3962498e794ba8d9fd28587b9bd11a7ea0e9d5"),
			privKeyWIF:  "PtWU5As1RGTx2dCMzN6SVNB8zxi5NeBxLbw6GiKL4ugX11e8qcUG7",
		},
		{
			address:     "TscWhrFeB8NCZG947cDgRQcoisrMMUgfwXu",
			addressHash: hexToBytes("7e10e3c8d0ee50dbd565b775ce2ed419a16c188e"),
			internal:    true,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("03f07840b3a739ffff86c1b9cec4698f6715f2ae3e02bc7c5d769e8a8e367568fe"),
			privKey:     hexToBytes("47f61ab82da5a4e2bdbd15188f69f20ee72fd58b9a64e135e92c05611e83bfe5"),
			privKeyWIF:  "PtWU5ZRiTnRc7fT6nWTDMKjrNjdjHDjZpEeza3ioxhmntzvV6RABc",
		},
		{
			address:     "TsUW8wqqr6dFPcEfxZ6vPdaB3JWKVHCdPFD",
			addressHash: hexToBytes("26346abd270f8155b71581e33e6f4e57cd315709"),
			internal:    true,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("02ed0450cae4b26aa675181c16e90a6192ff5edd25d8a2e91c8503c6d4ded64cef"),
			privKey:     hexToBytes("be77e3d659da10679b6d45ce9aaf2773fb9622b06cf5676f70dfd6fd08ea9415"),
			privKeyWIF:  "PtWUykXcL1g4iscr2iLKW5aFbUtDZxZvQmM4NU6rTz4eJKiKSgcG6",
		},
		{
			address:     "TsfHNz4HQ8BzD4Xp3k6VnLJfSsS3NMr7DJS",
			addressHash: hexToBytes("9c741c8e8faa0fc76e0907127e0145c26ea3b31b"),
			internal:    true,
			compressed:  true,
			imported:    false,
			pubKey:      hexToBytes("0374af6831563bb7470323ca41289e4b5b1b7c754317bf58a9280ac04a5fd702e9"),
			privKey:     hexToBytes("fc970de1af191f844fa5b31d0c9ac8490406051c34c031c25865cab104d5e04b"),
			privKeyWIF:  "PtWVT7LxY4rGwj2826fxgdukkQFT6z6rAAmuhtbqcQVyA9b6qtkyp",
		},
	}

	// expectedExternalAddrs is the list of expected external addresses
	// generated from the seed
	expectedExternalAddrs = expectedAddrs[:5]

	// expectedInternalAddrs is the list of expected internal addresses
	// generated from the seed
	expectedInternalAddrs = expectedAddrs[5:]
)

// checkManagerError ensures the passed error is a ManagerError with an error
// code that matches the passed  error code.
func checkManagerError(t *testing.T, testName string, gotErr error, wantErrCode waddrmgr.ErrorCode) bool {
	merr, ok := gotErr.(waddrmgr.ManagerError)
	if !ok {
		t.Errorf("%s: unexpected error type - got %T, want %T",
			testName, gotErr, waddrmgr.ManagerError{})
		return false
	}
	if merr.ErrorCode != wantErrCode {
		t.Errorf("%s: unexpected error code - got %s (%s), want %s",
			testName, merr.ErrorCode, merr.Description, wantErrCode)
		return false
	}

	return true
}

// hexToBytes is a wrapper around hex.DecodeString that panics if there is an
// error.  It MUST only be used with hard coded values in the tests.
func hexToBytes(origHex string) []byte {
	buf, err := hex.DecodeString(origHex)
	if err != nil {
		panic(err)
	}
	return buf
}

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

// openDbNamespace opens wallet database at the provided path and returns it
// along with the address manager namespace.
func openDbNamespace(dbPath string) (walletdb.DB, walletdb.Namespace, error) {
	db, err := walletdb.Open("bdb", dbPath)
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

// setupManager creates a new address manager and returns a teardown function
// that should be invoked to ensure it is closed and removed upon completion.
func setupManager(t *testing.T) (tearDownFunc func(), mgr *waddrmgr.Manager) {
	t.Parallel()

	// Create a new manager in a temp directory.
	dirName, err := ioutil.TempDir("", "mgrtest")
	if err != nil {
		t.Fatalf("Failed to create db temp dir: %v", err)
	}
	dbPath := filepath.Join(dirName, "mgrtest.db")
	db, namespace, err := createDbNamespace(dbPath)
	if err != nil {
		_ = os.RemoveAll(dirName)
		t.Fatalf("createDbNamespace: unexpected error: %v", err)
	}
	err = waddrmgr.Create(namespace, seed, pubPassphrase,
		privPassphrase, &chaincfg.MainNetParams, fastScrypt, false)
	if err == nil {
		mgr, err = waddrmgr.Open(namespace, pubPassphrase,
			&chaincfg.TestNetParams, nil)
	}

	if err != nil {
		db.Close()
		_ = os.RemoveAll(dirName)
		t.Fatalf("Failed to create Manager: %v", err)
	}
	tearDownFunc = func() {
		mgr.Close()
		db.Close()
		_ = os.RemoveAll(dirName)
	}
	return tearDownFunc, mgr
}
