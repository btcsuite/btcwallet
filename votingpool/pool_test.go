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

package votingpool_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/btcsuite/btcnet"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/conformal/btcwallet/votingpool"
	"github.com/conformal/btcwallet/waddrmgr"
	"github.com/conformal/btcwallet/walletdb"
	_ "github.com/conformal/btcwallet/walletdb/bdb"
)

var fastScrypt = &waddrmgr.Options{
	ScryptN: 16,
	ScryptR: 8,
	ScryptP: 1,
}

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
		t.Errorf("%s: unexpected error code - got %s, want %s",
			testName, merr.ErrorCode, wantErrCode)
		return false
	}

	return true
}

const (
	privKey0 = "xprv9s21ZrQH143K2j9PK4CXkCu8sgxkpUxCF7p1KVwiV5tdnkeYzJXReUkxz5iB2FUzTXC1L15abCDG4RMxSYT5zhm67uvsnLYxuDhZfoFcB6a"
	privKey1 = "xprv9s21ZrQH143K4PtW77ATQAKAGk7KAFFCzxFuAcWduoMEeQhCgWpuYWQvMGZknqdispUbgLZV1YPqFCbpzMJij8tSZ5xPSaZqPbchojeNuq7"
	privKey2 = "xprv9s21ZrQH143K27XboWxXZGU5j7VZ9SqVBnmMQPKTbddiWAhuNzeLynKHaZTAti6N454tVUUcvy6u15DfuW68NCBUxry6ZsHHzqoA8UtzdMn"
	privKey3 = "xprv9s21ZrQH143K2vb4DGQymRejLcZSksBHTYLxB7Stg1c7Lk9JxgEUGZTozwUKxoEWJPoGSdGnJY1TW7LNFQCWrpZjDdEXJeqJuDde6BmdD4P"
	privKey4 = "xprv9s21ZrQH143K4JNmRvWeLc1PggzusKcDYV1y8fAMNDdb9Rm5X1AvGHizxEdhTVR3sc62XvifC6dLAXMuQesX1y6999xnDwQ3aVno8KviU9d"
	privKey5 = "xprv9s21ZrQH143K3dxrqESqeHZ7pSwM6Uq77ssQADSBs7qdFs6dyRWmRcPyLUTQRpgB3EduNhJuWkCGG2LHjuUisw8KKfXJpPqYJ1MSPrZpe1z"
	privKey6 = "xprv9s21ZrQH143K2nE8ENAMNksTTVxPrMxFNWUuwThMy2bcH9LHTtQDXSNq2pTNcbuq36n5A3J9pbXVqnq5LDXvqniFRLN299kW7Svnxsx9tQv"
	privKey7 = "xprv9s21ZrQH143K3p93xF1oFeB6ey5ruUesWjuPxA9Z2R5wf6BLYfGXz7fg7NavWkQ2cx3Vm8w2HV9uKpSprNNHnenGeW9XhYDPSjwS9hyCs33"
	privKey8 = "xprv9s21ZrQH143K3WxnnvPZ8SDGXndASvLTFwMLBVzNCVgs9rzP6rXgW92DLvozdyBm8T9bSQvrFm1jMpTJrRE6w1KY5tshFeDk9Nn3K6V5FYX"

	pubKey0 = "xpub661MyMwAqRbcFDDrR5jY7LqsRioFDwg3cLjc7tML3RRcfYyhXqqgCH5SqMSQdpQ1Xh8EtVwcfm8psD8zXKPcRaCVSY4GCqbb3aMEs27GitE"
	pubKey1 = "xpub661MyMwAqRbcGsxyD8hTmJFtpmwoZhy4NBBVxzvFU8tDXD2ME49A6JjQCYgbpSUpHGP1q4S2S1Pxv2EqTjwfERS5pc9Q2yeLkPFzSgRpjs9"
	pubKey2 = "xpub661MyMwAqRbcEbc4uYVXvQQpH9L3YuZLZ1gxCmj59yAhNy33vXxbXadmRpx5YZEupNSqWRrR7PqU6duS2FiVCGEiugBEa5zuEAjsyLJjKCh"
	pubKey3 = "xpub661MyMwAqRbcFQfXKHwz8ZbTtePwAKu8pmGYyVrWEM96DYUTWDYipMnHrFcemZHn13jcRMfsNU3UWQUudiaE7mhkWCHGFRMavF167DQM4Va"
	pubKey4 = "xpub661MyMwAqRbcGnTEXx3ehjx8EiqQGnL4uhwZw3ZxvZAa2E6E4YVAp63UoVtvm2vMDDF8BdPpcarcf7PWcEKvzHhxzAYw1zG23C2egeh82AR"
	pubKey5 = "xpub661MyMwAqRbcG83KwFyr1RVrNUmqVwYxV6nzxbqoRTNc8fRnWxq1yQiTBifTHhevcEM9ucZ1TqFS7Kv17Gd81cesv6RDrrvYS9SLPjPXhV5"
	pubKey6 = "xpub661MyMwAqRbcFGJbLPhMjtpC1XntFpg6jjQWjr6yXN8b9wfS1RiU5EhJt5L7qoFuidYawc3XJoLjT2PcjVpXryS3hn1WmSPCyvQDNuKsfgM"
	pubKey7 = "xpub661MyMwAqRbcGJDX4GYocn7qCzvMJwNisxpzkYZAakcvXtWV6CanXuz9xdfe5kTptFMJ4hDt2iTiT11zyN14u8R5zLvoZ1gnEVqNLxp1r3v"
	pubKey8 = "xpub661MyMwAqRbcG13FtwvZVaA15pTerP4JdAGvytPykqDr2fKXePqw3wLhCALPAixsE176jFkc2ac9K3tnF4KwaTRKUqFF5apWD6XL9LHCu7E"
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
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func setUp(t *testing.T) (tearDownFunc func(), mgr *waddrmgr.Manager, pool *votingpool.Pool) {
	t.Parallel()

	// Create a new wallet DB and addr manager.
	dir, err := ioutil.TempDir("", "pool_test")
	if err != nil {
		t.Fatalf("Failed to create db dir: %v", err)
	}
	db, err := walletdb.Create("bdb", filepath.Join(dir, "wallet.db"))
	if err != nil {
		t.Fatalf("Failed to create wallet DB: %v", err)
	}
	mgrNamespace, err := db.Namespace([]byte("waddrmgr"))
	if err != nil {
		t.Fatalf("Failed to create addr manager DB namespace: %v", err)
	}
	mgr, err = waddrmgr.Create(mgrNamespace, seed, pubPassphrase, privPassphrase,
		&btcnet.MainNetParams, fastScrypt)
	if err != nil {
		t.Fatalf("Failed to create addr manager: %v", err)
	}

	// Create a walletdb for votingpools.
	vpNamespace, err := db.Namespace([]byte("votingpool"))
	if err != nil {
		t.Fatalf("Failed to create VotingPool DB namespace: %v", err)
	}
	pool, err = votingpool.Create(vpNamespace, mgr, []byte{0x00})
	if err != nil {
		t.Fatalf("Voting Pool creation failed: %v", err)
	}
	tearDownFunc = func() {
		db.Close()
		mgr.Close()
		os.RemoveAll(dir)
	}
	return tearDownFunc, mgr, pool
}

func TestLoadVotingPoolAndDepositScript(t *testing.T) {
	tearDown, manager, pool := setUp(t)
	defer tearDown()
	// setup
	poolID := "test"
	pubKeys := []string{pubKey0, pubKey1, pubKey2}
	err := votingpool.LoadAndCreateSeries(pool.TstNamespace(), manager, 1, poolID, 0, 2, pubKeys)
	if err != nil {
		t.Fatalf("Failed to create voting pool and series: %v", err)
	}

	// execute
	script, err := votingpool.LoadAndGetDepositScript(pool.TstNamespace(), manager, poolID, 0, 0, 0)
	if err != nil {
		t.Fatalf("Failed to get deposit script: %v", err)
	}

	// validate
	strScript := hex.EncodeToString(script)
	want := "5221035e94da75731a2153b20909017f62fcd49474c45f3b46282c0dafa8b40a3a312b2102e983a53dd20b7746dd100dfd2925b777436fc1ab1dd319433798924a5ce143e32102908d52a548ee9ef6b2d0ea67a3781a0381bc3570ad623564451e63757ff9393253ae"
	if want != strScript {
		t.Fatalf("Failed to get the right deposit script. Got %v, want %v",
			strScript, want)
	}
}

func TestLoadVotingPoolAndCreateSeries(t *testing.T) {
	tearDown, manager, pool := setUp(t)
	defer tearDown()

	poolID := "test"

	// first time, the voting pool is created
	pubKeys := []string{pubKey0, pubKey1, pubKey2}
	err := votingpool.LoadAndCreateSeries(pool.TstNamespace(), manager, 1, poolID, 0, 2, pubKeys)
	if err != nil {
		t.Fatalf("Creating voting pool and Creating series failed: %v", err)
	}

	// create another series where the voting pool is loaded this time
	pubKeys = []string{pubKey3, pubKey4, pubKey5}
	err = votingpool.LoadAndCreateSeries(pool.TstNamespace(), manager, 1, poolID, 1, 2, pubKeys)

	if err != nil {
		t.Fatalf("Loading voting pool and Creating series failed: %v", err)
	}
}

func TestLoadVotingPoolAndReplaceSeries(t *testing.T) {
	tearDown, manager, pool := setUp(t)
	defer tearDown()

	// setup
	poolID := "test"
	pubKeys := []string{pubKey0, pubKey1, pubKey2}
	err := votingpool.LoadAndCreateSeries(pool.TstNamespace(), manager, 1, poolID, 0, 2, pubKeys)
	if err != nil {
		t.Fatalf("Failed to create voting pool and series: %v", err)
	}

	pubKeys = []string{pubKey3, pubKey4, pubKey5}
	err = votingpool.LoadAndReplaceSeries(pool.TstNamespace(), manager, 1, poolID, 0, 2, pubKeys)
	if err != nil {
		t.Fatalf("Failed to replace series: %v", err)
	}
}

func TestLoadVotingPoolAndEmpowerSeries(t *testing.T) {
	tearDown, manager, pool := setUp(t)
	defer tearDown()

	// setup
	poolID := "test"
	pubKeys := []string{pubKey0, pubKey1, pubKey2}
	err := votingpool.LoadAndCreateSeries(pool.TstNamespace(), manager, 1, poolID, 0, 2, pubKeys)
	if err != nil {
		t.Fatalf("Creating voting pool and Creating series failed: %v", err)
	}

	// We need to unlock the manager in order to empower a series
	manager.Unlock(privPassphrase)

	err = votingpool.LoadAndEmpowerSeries(pool.TstNamespace(), manager, poolID, 0, privKey0)
	if err != nil {
		t.Fatalf("Load voting pool and Empower series failed: %v", err)
	}
}

func TestDepositScriptAddress(t *testing.T) {
	tearDown, _, pool := setUp(t)
	defer tearDown()

	tests := []struct {
		version uint32
		series  uint32
		reqSigs uint32
		pubKeys []string
		// map of branch:address (we only check the branch index at 0)
		addresses map[uint32]string
	}{
		{
			version: 1,
			series:  0,
			reqSigs: 2,
			pubKeys: []string{pubKey0, pubKey1, pubKey2},
			addresses: map[uint32]string{
				0: "3Hb4xcebcKg4DiETJfwjh8sF4uDw9rqtVC",
				1: "34eVkREKgvvGASZW7hkgE2uNc1yycntMK6",
				2: "3Qt1EaKRD9g9FeL2DGkLLswhK1AKmmXFSe",
				3: "3PbExiaztsSYgh6zeMswC49hLUwhTQ86XG",
			},
		},
	}

	for i, test := range tests {
		if err := pool.CreateSeries(test.version, test.series,
			test.reqSigs, test.pubKeys); err != nil {
			t.Fatalf("Cannot creates series %v", test.series)
		}
		for branch, expectedAddress := range test.addresses {
			addr, err := pool.DepositScriptAddress(test.series, branch, 0)
			if err != nil {
				t.Fatalf("Failed to get DepositScriptAddress #%d: %v", i, err)
			}
			address := addr.EncodeAddress()
			if expectedAddress != address {
				t.Errorf("DepositScript #%d returned the wrong deposit script. Got %v, want %v",
					i, address, expectedAddress)
			}
		}
	}
}

func TestDepositScriptAddressForNonExistentSeries(t *testing.T) {
	tearDown, _, pool := setUp(t)
	defer tearDown()

	if _, err := pool.DepositScriptAddress(0, 0, 0); err == nil {
		t.Fatalf("Expected an error, got none")
	} else {
		rerr := err.(waddrmgr.ManagerError)
		if waddrmgr.ErrSeriesNotExists != rerr.ErrorCode {
			t.Errorf("Got %v, want ErrSeriesNotExists", rerr.ErrorCode)
		}
	}
}

func TestDepositScriptAddressForHardenedPubKey(t *testing.T) {
	tearDown, _, pool := setUp(t)
	defer tearDown()
	if err := pool.CreateSeries(1, 0, 2, []string{pubKey0, pubKey1, pubKey2}); err != nil {
		t.Fatalf("Cannot creates series")
	}

	// Ask for a DepositScriptAddress using an index for a hardened child, which should
	// fail as we use the extended public keys to derive childs.
	_, err := pool.DepositScriptAddress(0, 0, uint32(hdkeychain.HardenedKeyStart+1))

	if err == nil {
		t.Fatalf("Expected an error, got none")
	} else {
		rerr := err.(waddrmgr.ManagerError)
		if waddrmgr.ErrKeyChain != rerr.ErrorCode {
			t.Errorf("Got %v, want ErrKeyChain", rerr.ErrorCode)
		}
	}
}

func TestLoadVotingPool(t *testing.T) {
	tearDown, mgr, pool := setUp(t)
	defer tearDown()

	pool2, err := votingpool.Load(pool.TstNamespace(), mgr, pool.ID)
	if err != nil {
		t.Errorf("Error loading VotingPool: %v", err)
	}
	if !bytes.Equal(pool2.ID, pool.ID) {
		t.Errorf("Voting pool obtained from DB does not match the created one")
	}
}

func TestCreateVotingPool(t *testing.T) {
	tearDown, mgr, pool := setUp(t)
	defer tearDown()

	pool2, err := votingpool.Create(pool.TstNamespace(), mgr, []byte{0x02})
	if err != nil {
		t.Errorf("Error creating VotingPool: %v", err)
	}
	if !bytes.Equal(pool2.ID, []byte{0x02}) {
		t.Errorf("VotingPool ID mismatch: got %v, want %v", pool2.ID, []byte{0x02})
	}
}

func TestCreateVotingPoolWhenAlreadyExists(t *testing.T) {
	tearDown, mgr, pool := setUp(t)
	defer tearDown()

	_, err := votingpool.Create(pool.TstNamespace(), mgr, pool.ID)

	checkManagerError(t, "", err, waddrmgr.ErrVotingPoolAlreadyExists)
}

func TestCreateSeries(t *testing.T) {
	tearDown, _, pool := setUp(t)
	defer tearDown()

	tests := []struct {
		version uint32
		series  uint32
		reqSigs uint32
		pubKeys []string
	}{
		{
			version: 1,
			series:  0,
			reqSigs: 2,
			pubKeys: []string{pubKey0, pubKey1, pubKey2},
		},
		{
			version: 1,
			series:  1,
			reqSigs: 3,
			pubKeys: []string{pubKey0, pubKey1, pubKey2, pubKey3, pubKey4},
		},
		{
			version: 1,
			series:  2,
			reqSigs: 4,
			pubKeys: []string{pubKey0, pubKey1, pubKey2, pubKey3, pubKey4,
				pubKey5, pubKey6},
		},
		{
			version: 1,
			series:  3,
			reqSigs: 5,
			pubKeys: []string{pubKey0, pubKey1, pubKey2, pubKey3, pubKey4,
				pubKey5, pubKey6, pubKey7, pubKey8},
		},
	}

	for testNum, test := range tests {
		err := pool.CreateSeries(test.version, test.series, test.reqSigs, test.pubKeys[:])
		if err != nil {
			t.Fatalf("%d: Cannot create series %d", testNum, test.series)
		}
		exists, err := pool.TstExistsSeries(test.series)
		if err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Errorf("%d: Series %d not in database", testNum, test.series)
		}
	}
}

func TestCreateSeriesWhenAlreadyExists(t *testing.T) {
	tearDown, _, pool := setUp(t)
	defer tearDown()
	pubKeys := []string{pubKey0, pubKey1, pubKey2}
	if err := pool.CreateSeries(1, 0, 1, pubKeys); err != nil {
		t.Fatalf("Cannot create series: %v", err)
	}

	err := pool.CreateSeries(1, 0, 1, pubKeys)

	checkManagerError(t, "", err, waddrmgr.ErrSeriesAlreadyExists)
}

func TestPutSeriesErrors(t *testing.T) {
	tearDown, _, pool := setUp(t)
	defer tearDown()

	tests := []struct {
		version uint32
		reqSigs uint32
		pubKeys []string
		err     waddrmgr.ManagerError
		msg     string
	}{
		{
			pubKeys: []string{pubKey0},
			err:     waddrmgr.ManagerError{ErrorCode: waddrmgr.ErrTooFewPublicKeys},
			msg:     "Should return error when passed too few pubkeys",
		},
		{
			reqSigs: 5,
			pubKeys: []string{pubKey0, pubKey1, pubKey2},
			err:     waddrmgr.ManagerError{ErrorCode: waddrmgr.ErrTooManyReqSignatures},
			msg:     "Should return error when reqSigs > len(pubKeys)",
		},
		{
			pubKeys: []string{pubKey0, pubKey1, pubKey2, pubKey0},
			err:     waddrmgr.ManagerError{ErrorCode: waddrmgr.ErrKeyDuplicate},
			msg:     "Should return error when passed duplicate pubkeys",
		},
		{
			pubKeys: []string{"invalidxpub1", "invalidxpub2", "invalidxpub3"},
			err:     waddrmgr.ManagerError{ErrorCode: waddrmgr.ErrKeyChain},
			msg:     "Should return error when passed invalid pubkey",
		},
		{
			pubKeys: []string{privKey0, privKey1, privKey2},
			err:     waddrmgr.ManagerError{ErrorCode: waddrmgr.ErrKeyIsPrivate},
			msg:     "Should return error when passed private keys",
		},
	}

	for i, test := range tests {
		err := pool.TstPutSeries(test.version, uint32(i), test.reqSigs, test.pubKeys)
		if err == nil {
			str := fmt.Sprintf(test.msg+" pubKeys: %v, reqSigs: %v",
				test.pubKeys, test.reqSigs)
			t.Errorf(str)
		} else {
			retErr := err.(waddrmgr.ManagerError)
			if test.err.ErrorCode != retErr.ErrorCode {
				t.Errorf(
					"Create series #%d - Incorrect error type. Got %s, want %s",
					i, retErr.ErrorCode, test.err.ErrorCode)
			}
		}
	}
}

func TestValidateAndDecryptKeys(t *testing.T) {
	tearDown, manager, pool := setUp(t)
	defer tearDown()

	rawPubKeys, err := encryptKeys([]string{pubKey0, pubKey1}, manager, waddrmgr.CKTPublic)
	if err != nil {
		t.Fatalf("Failed to encrypt public keys: %v", err)
	}

	// We need to unlock the manager in order to encrypt with the
	// private key.
	manager.Unlock(privPassphrase)

	rawPrivKeys, err := encryptKeys([]string{privKey0, ""}, manager, waddrmgr.CKTPrivate)
	if err != nil {
		t.Fatalf("Failed to encrypt private keys: %v", err)
	}

	pubKeys, privKeys, err := votingpool.TstValidateAndDecryptKeys(rawPubKeys, rawPrivKeys, pool)
	if err != nil {
		t.Fatalf("Error when validating/decrypting keys: %v", err)
	}

	if len(pubKeys) != 2 {
		t.Fatalf("Unexpected number of decrypted public keys: got %d, want 2", len(pubKeys))
	}
	if len(privKeys) != 2 {
		t.Fatalf("Unexpected number of decrypted private keys: got %d, want 2", len(privKeys))
	}

	if pubKeys[0].String() != pubKey0 || pubKeys[1].String() != pubKey1 {
		t.Fatalf("Public keys don't match: %v, %v", []string{pubKey0, pubKey1}, pubKeys)
	}

	if privKeys[0].String() != privKey0 || privKeys[1] != nil {
		t.Fatalf("Private keys don't match: %v, %v", []string{privKey0, ""}, privKeys)
	}

	neuteredKey, err := privKeys[0].Neuter()
	if err != nil {
		t.Fatalf("Unable to neuter private key: %v", err)
	}
	if pubKeys[0].String() != neuteredKey.String() {
		t.Errorf("Public key (%v) does not match neutered private key (%v)",
			pubKeys[0].String(), neuteredKey.String())
	}
}

func TestValidateAndDecryptKeysErrors(t *testing.T) {
	tearDown, manager, pool := setUp(t)
	defer tearDown()

	encryptedPubKeys, err := encryptKeys([]string{pubKey0}, manager, waddrmgr.CKTPublic)
	if err != nil {
		t.Fatalf("Failed to encrypt public key: %v", err)
	}

	// We need to unlock the manager in order to encrypt with the
	// private key.
	manager.Unlock(privPassphrase)

	encryptedPrivKeys, err := encryptKeys([]string{privKey1}, manager, waddrmgr.CKTPrivate)
	if err != nil {
		t.Fatalf("Failed to encrypt private key: %v", err)
	}

	tests := []struct {
		rawPubKeys  [][]byte
		rawPrivKeys [][]byte
		err         waddrmgr.ErrorCode
	}{
		{
			// Number of public keys does not match number of private keys.
			rawPubKeys:  [][]byte{[]byte(pubKey0)},
			rawPrivKeys: [][]byte{},
			err:         waddrmgr.ErrKeysPrivatePublicMismatch,
		},
		{
			// Failure to decrypt public key.
			rawPubKeys:  [][]byte{[]byte(pubKey0)},
			rawPrivKeys: [][]byte{[]byte(privKey0)},
			err:         waddrmgr.ErrCrypto,
		},
		{
			// Failure to decrypt private key.
			rawPubKeys:  encryptedPubKeys,
			rawPrivKeys: [][]byte{[]byte(privKey0)},
			err:         waddrmgr.ErrCrypto,
		},
		{
			// One public and one private key, but they don't match.
			rawPubKeys:  encryptedPubKeys,
			rawPrivKeys: encryptedPrivKeys,
			err:         waddrmgr.ErrKeyMismatch,
		},
	}

	for i, test := range tests {
		_, _, err := votingpool.TstValidateAndDecryptKeys(test.rawPubKeys, test.rawPrivKeys, pool)

		checkManagerError(t, fmt.Sprintf("Test #%d", i), err, test.err)
	}
}

func encryptKeys(keys []string, mgr *waddrmgr.Manager, keyType waddrmgr.CryptoKeyType) ([][]byte, error) {
	encryptedKeys := make([][]byte, len(keys))
	var err error
	for i, key := range keys {
		if key == "" {
			encryptedKeys[i] = nil
		} else {
			encryptedKeys[i], err = mgr.Encrypt(keyType, []byte(key))
		}
		if err != nil {
			return nil, err
		}
	}
	return encryptedKeys, nil
}

func TestCannotReplaceEmpoweredSeries(t *testing.T) {
	tearDown, manager, pool := setUp(t)
	defer tearDown()

	var seriesID uint32 = 1

	if err := pool.CreateSeries(1, seriesID, 3, []string{pubKey0, pubKey1, pubKey2, pubKey3}); err != nil {
		t.Fatalf("Failed to create series", err)
	}

	// We need to unlock the manager in order to empower a series.
	manager.Unlock(privPassphrase)

	if err := pool.EmpowerSeries(seriesID, privKey1); err != nil {
		t.Fatalf("Failed to empower series", err)
	}

	if err := pool.ReplaceSeries(1, seriesID, 2, []string{pubKey0, pubKey2, pubKey3}); err == nil {
		t.Errorf("Replaced an empowered series. That should not be possible", err)
	} else {
		gotErr := err.(waddrmgr.ManagerError)
		wantErrCode := waddrmgr.ErrorCode(waddrmgr.ErrSeriesAlreadyEmpowered)
		if wantErrCode != gotErr.ErrorCode {
			t.Errorf("Got %s, want %s", gotErr.ErrorCode, wantErrCode)
		}
	}
}

func TestReplaceNonExistingSeries(t *testing.T) {
	tearDown, _, pool := setUp(t)
	defer tearDown()

	pubKeys := []string{pubKey0, pubKey1, pubKey2}
	if err := pool.ReplaceSeries(1, 1, 3, pubKeys); err == nil {
		t.Errorf("Replaced non-existent series. This should not be possible.")
	} else {
		gotErr := err.(waddrmgr.ManagerError)
		wantErrCode := waddrmgr.ErrorCode(waddrmgr.ErrSeriesNotExists)
		if wantErrCode != gotErr.ErrorCode {
			t.Errorf("Got %s, want %s", gotErr.ErrorCode, wantErrCode)
		}
	}
}

type replaceSeriesTestEntry struct {
	testID      int
	orig        seriesRaw
	replaceWith seriesRaw
}

var replaceSeriesTestData = []replaceSeriesTestEntry{
	{
		testID: 0,
		orig: seriesRaw{
			id:      0,
			version: 1,
			reqSigs: 2,
			pubKeys: votingpool.CanonicalKeyOrder(
				[]string{pubKey0, pubKey1, pubKey2, pubKey4}),
		},
		replaceWith: seriesRaw{
			id:      0,
			version: 1,
			reqSigs: 1,
			pubKeys: votingpool.CanonicalKeyOrder(
				[]string{pubKey3, pubKey4, pubKey5}),
		},
	},
	{
		testID: 1,
		orig: seriesRaw{
			id:      2,
			version: 1,
			reqSigs: 2,
			pubKeys: votingpool.CanonicalKeyOrder(
				[]string{pubKey0, pubKey1, pubKey2}),
		},
		replaceWith: seriesRaw{
			id:      2,
			version: 1,
			reqSigs: 2,
			pubKeys: votingpool.CanonicalKeyOrder(
				[]string{pubKey3, pubKey4, pubKey5, pubKey6}),
		},
	},
	{
		testID: 2,
		orig: seriesRaw{
			id:      4,
			version: 1,
			reqSigs: 8,
			pubKeys: votingpool.CanonicalKeyOrder([]string{pubKey0, pubKey1, pubKey2, pubKey3, pubKey4, pubKey5, pubKey6, pubKey7, pubKey8}),
		},
		replaceWith: seriesRaw{
			id:      4,
			version: 1,
			reqSigs: 7,
			pubKeys: votingpool.CanonicalKeyOrder([]string{pubKey0, pubKey1, pubKey2, pubKey3, pubKey4, pubKey5, pubKey6, pubKey7}),
		},
	},
}

func TestReplaceExistingSeries(t *testing.T) {
	tearDown, _, pool := setUp(t)
	defer tearDown()

	for _, data := range replaceSeriesTestData {
		seriesID := data.orig.id
		testID := data.testID

		if err := pool.CreateSeries(data.orig.version, seriesID, data.orig.reqSigs, data.orig.pubKeys); err != nil {
			t.Fatalf("Test #%d: failed to create series in replace series setup",
				testID, err)
		}

		if err := pool.ReplaceSeries(data.replaceWith.version, seriesID,
			data.replaceWith.reqSigs, data.replaceWith.pubKeys); err != nil {
			t.Errorf("Test #%d: replaceSeries failed", testID, err)
		}

		validateReplaceSeries(t, pool, testID, data.replaceWith)
	}
}

// validateReplaceSeries validate the created series stored in the system
// corresponds to the series we replaced the original with.
func validateReplaceSeries(t *testing.T, pool *votingpool.Pool, testID int, replacedWith seriesRaw) {
	seriesID := replacedWith.id
	series := pool.GetSeries(seriesID)
	if series == nil {
		t.Fatalf("Test #%d Series #%d: series not found", testID, seriesID)
	}

	pubKeys := series.TstGetRawPublicKeys()
	// Check that the public keys match what we expect.
	if !reflect.DeepEqual(replacedWith.pubKeys, pubKeys) {
		t.Errorf("Test #%d, series #%d: pubkeys mismatch. Got %v, want %v",
			testID, seriesID, pubKeys, replacedWith.pubKeys)
	}

	// Check number of required sigs.
	if replacedWith.reqSigs != series.TstGetReqSigs() {
		t.Errorf("Test #%d, series #%d: required signatures mismatch. Got %d, want %d",
			testID, seriesID, series.TstGetReqSigs(), replacedWith.reqSigs)
	}

	// Check that the series is not empowered.
	if series.IsEmpowered() {
		t.Errorf("Test #%d, series #%d: series is empowered but should not be",
			testID, seriesID)
	}
}

func TestEmpowerSeries(t *testing.T) {
	tearDown, manager, pool := setUp(t)
	defer tearDown()

	seriesID := uint32(0)
	err := pool.CreateSeries(1, seriesID, 2, []string{pubKey0, pubKey1, pubKey2})
	if err != nil {
		t.Fatalf("Failed to create series: %v", err)
	}

	tests := []struct {
		seriesID uint32
		key      string
		err      error
	}{
		{
			seriesID: 0,
			key:      privKey0,
		},
		{
			seriesID: 0,
			key:      privKey1,
		},
		{
			seriesID: 1,
			key:      privKey0,
			// invalid series
			err: waddrmgr.ManagerError{ErrorCode: waddrmgr.ErrSeriesNotExists},
		},
		{
			seriesID: 0,
			key:      "NONSENSE",
			// invalid private key
			err: waddrmgr.ManagerError{ErrorCode: waddrmgr.ErrKeyChain},
		},
		{
			seriesID: 0,
			key:      pubKey5,
			// wrong type of key
			err: waddrmgr.ManagerError{ErrorCode: waddrmgr.ErrKeyIsPublic},
		},
		{
			seriesID: 0,
			key:      privKey5,
			// key not corresponding to pub key
			err: waddrmgr.ManagerError{ErrorCode: waddrmgr.ErrKeysPrivatePublicMismatch},
		},
	}

	// We need to unlock the manager in order to empower a series.
	manager.Unlock(privPassphrase)

	for testNum, test := range tests {
		// Add the extended private key to voting pool.
		err := pool.EmpowerSeries(test.seriesID, test.key)
		if test.err != nil {
			if err == nil {
				t.Errorf("EmpowerSeries #%d Expected an error and got none", testNum)
				continue
			}
			if reflect.TypeOf(err) != reflect.TypeOf(test.err) {
				t.Errorf("DepositScript #%d wrong error type. Got: %v <%T>, want: %T",
					testNum, err, err, test.err)
				continue
			}
			rerr := err.(waddrmgr.ManagerError)
			trerr := test.err.(waddrmgr.ManagerError)
			if rerr.ErrorCode != trerr.ErrorCode {
				t.Errorf("DepositScript #%d wrong error code. Got: %v, want: %v",
					testNum, rerr.ErrorCode, trerr.ErrorCode)
				continue
			}
			continue
		}

		if err != nil {
			t.Errorf("EmpowerSeries #%d Unexpected error %v", testNum, err)
			continue
		}
	}

}

func TestGetSeries(t *testing.T) {
	tearDown, _, pool := setUp(t)
	defer tearDown()
	expectedPubKeys := votingpool.CanonicalKeyOrder([]string{pubKey0, pubKey1, pubKey2})
	if err := pool.CreateSeries(1, 0, 2, expectedPubKeys); err != nil {
		t.Fatalf("Failed to create series: %v", err)
	}

	series := pool.GetSeries(0)

	if series == nil {
		t.Fatal("GetSeries() returned nil")
	}
	pubKeys := series.TstGetRawPublicKeys()
	if !reflect.DeepEqual(pubKeys, expectedPubKeys) {
		t.Errorf("Series pubKeys mismatch. Got %v, want %v", pubKeys, expectedPubKeys)
	}
}

type seriesRaw struct {
	id       uint32
	version  uint32
	reqSigs  uint32
	pubKeys  []string
	privKeys []string
}

type testLoadAllSeriesTest struct {
	id     int
	series []seriesRaw
}

var testLoadAllSeriesTests = []testLoadAllSeriesTest{
	{
		id: 1,
		series: []seriesRaw{
			{
				id:      0,
				version: 1,
				reqSigs: 2,
				pubKeys: []string{pubKey0, pubKey1, pubKey2},
			},
			{
				id:       1,
				version:  1,
				reqSigs:  2,
				pubKeys:  []string{pubKey3, pubKey4, pubKey5},
				privKeys: []string{privKey4},
			},
			{
				id:       2,
				version:  1,
				reqSigs:  3,
				pubKeys:  []string{pubKey0, pubKey1, pubKey2, pubKey3, pubKey4},
				privKeys: []string{privKey0, privKey2},
			},
		},
	},
	{
		id: 2,
		series: []seriesRaw{
			{
				id:      0,
				version: 1,
				reqSigs: 2,
				pubKeys: []string{pubKey0, pubKey1, pubKey2},
			},
		},
	},
}

func setUpLoadAllSeries(t *testing.T, namespace walletdb.Namespace, mgr *waddrmgr.Manager,
	test testLoadAllSeriesTest) *votingpool.Pool {
	pool, err := votingpool.Create(namespace, mgr, []byte{byte(test.id + 1)})
	if err != nil {
		t.Fatalf("Voting Pool creation failed: %v", err)
	}

	for _, series := range test.series {
		err := pool.CreateSeries(series.version, series.id,
			series.reqSigs, series.pubKeys)
		if err != nil {
			t.Fatalf("Test #%d Series #%d: failed to create series: %v",
				test.id, series.id, err)
		}

		for _, privKey := range series.privKeys {
			err := pool.EmpowerSeries(series.id, privKey)
			if err != nil {
				t.Fatalf("Test #%d Series #%d: empower with privKey %v failed: %v",
					test.id, series.id, privKey, err)
			}
		}
	}
	return pool
}

func TestLoadAllSeries(t *testing.T) {
	tearDown, manager, pool := setUp(t)
	defer tearDown()

	// We need to unlock the manager in order to empower a series.
	manager.Unlock(privPassphrase)

	for _, test := range testLoadAllSeriesTests {
		pool := setUpLoadAllSeries(t, pool.TstNamespace(), manager, test)
		pool.TstEmptySeriesLookup()
		err := pool.LoadAllSeries()
		if err != nil {
			t.Fatalf("Test #%d: failed to load voting pool: %v", test.id, err)
		}
		for _, seriesData := range test.series {
			validateLoadAllSeries(t, pool, test.id, seriesData)
		}
	}
}

func validateLoadAllSeries(t *testing.T, pool *votingpool.Pool, testID int, seriesData seriesRaw) {
	series := pool.GetSeries(seriesData.id)

	// Check that the series exists.
	if series == nil {
		t.Errorf("Test #%d, series #%d: series not found", testID, seriesData.id)
	}

	// Check that reqSigs is what we inserted.
	if seriesData.reqSigs != series.TstGetReqSigs() {
		t.Errorf("Test #%d, series #%d: required sigs are different. Got %d, want %d",
			testID, seriesData.id, series.TstGetReqSigs(), seriesData.reqSigs)
	}

	// Check that pubkeys and privkeys have the same length.
	publicKeys := series.TstGetRawPublicKeys()
	privateKeys := series.TstGetRawPrivateKeys()
	if len(privateKeys) != len(publicKeys) {
		t.Errorf("Test #%d, series #%d: wrong number of private keys. Got %d, want %d",
			testID, seriesData.id, len(privateKeys), len(publicKeys))
	}

	sortedKeys := votingpool.CanonicalKeyOrder(seriesData.pubKeys)
	if !reflect.DeepEqual(publicKeys, sortedKeys) {
		t.Errorf("Test #%d, series #%d: public keys mismatch. Got %d, want %d",
			testID, seriesData.id, sortedKeys, publicKeys)
	}

	// Check that privkeys are what we inserted (length and content).
	foundPrivKeys := make([]string, 0, len(seriesData.pubKeys))
	for _, privateKey := range privateKeys {
		if privateKey != "" {
			foundPrivKeys = append(foundPrivKeys, privateKey)
		}
	}
	foundPrivKeys = votingpool.CanonicalKeyOrder(foundPrivKeys)
	privKeys := votingpool.CanonicalKeyOrder(seriesData.privKeys)
	if !reflect.DeepEqual(privKeys, foundPrivKeys) {
		t.Errorf("Test #%d, series #%d: private keys mismatch. Got %d, want %d",
			testID, seriesData.id, foundPrivKeys, privKeys)
	}
}

func reverse(inKeys []*hdkeychain.ExtendedKey) []*hdkeychain.ExtendedKey {
	revKeys := make([]*hdkeychain.ExtendedKey, len(inKeys))
	max := len(inKeys)
	for i := range inKeys {
		revKeys[i] = inKeys[max-i-1]
	}
	return revKeys
}

func TestBranchOrderZero(t *testing.T) {
	// test change address branch (0) for 0-10 keys
	for i := 0; i < 10; i++ {
		inKeys := createTestPubKeys(t, i, 0)
		wantKeys := reverse(inKeys)
		resKeys, err := votingpool.TstBranchOrder(inKeys, 0)
		if err != nil {
			t.Fatalf("Error ordering keys: %v", err)
		}

		if len(resKeys) != len(wantKeys) {
			t.Errorf("BranchOrder: wrong no. of keys. Got: %d, want %d",
				len(resKeys), len(inKeys))
			return
		}

		for keyIdx := 0; i < len(inKeys); i++ {
			if resKeys[keyIdx] != wantKeys[keyIdx] {
				fmt.Printf("%p, %p\n", resKeys[i], wantKeys[i])
				t.Errorf("BranchOrder(keys, 0): got %v, want %v",
					resKeys[i], wantKeys[i])
			}
		}
	}
}

func TestBranchOrderNonZero(t *testing.T) {
	maxBranch := 5
	maxTail := 4
	// Test branch reordering for branch no. > 0. We test all branch values
	// within [1, 5] in a slice of up to 9 (maxBranch-1 + branch-pivot +
	// maxTail) keys. Hopefully that covers all combinations and edge-cases.
	// We test the case where branch no. is 0 elsewhere.
	for branch := 1; branch <= maxBranch; branch++ {
		for j := 0; j <= maxTail; j++ {
			first := createTestPubKeys(t, branch-1, 0)
			pivot := createTestPubKeys(t, 1, branch)
			last := createTestPubKeys(t, j, branch+1)

			inKeys := append(append(first, pivot...), last...)
			wantKeys := append(append(pivot, first...), last...)
			resKeys, err := votingpool.TstBranchOrder(inKeys, uint32(branch))
			if err != nil {
				t.Fatalf("Error ordering keys: %v", err)
			}

			if len(resKeys) != len(inKeys) {
				t.Errorf("BranchOrder: wrong no. of keys. Got: %d, want %d",
					len(resKeys), len(inKeys))
			}

			for idx := 0; idx < len(inKeys); idx++ {
				if resKeys[idx] != wantKeys[idx] {
					o, w, g := branchErrorFormat(inKeys, wantKeys, resKeys)
					t.Errorf("Branch: %d\nOrig: %v\nGot: %v\nWant: %v", branch, o, g, w)
				}
			}
		}
	}
}

func TestBranchOrderNilKeys(t *testing.T) {
	_, err := votingpool.TstBranchOrder(nil, 1)

	checkManagerError(t, "", err, waddrmgr.ErrInvalidValue)
}

func TestBranchOrderInvalidBranch(t *testing.T) {
	_, err := votingpool.TstBranchOrder(createTestPubKeys(t, 3, 0), 4)

	checkManagerError(t, "", err, waddrmgr.ErrInvalidBranch)
}

func branchErrorFormat(orig, want, got []*hdkeychain.ExtendedKey) (origOrder, wantOrder, gotOrder []int) {
	origOrder = []int{}
	origMap := make(map[*hdkeychain.ExtendedKey]int)
	for i, key := range orig {
		origMap[key] = i + 1
		origOrder = append(origOrder, i+1)
	}

	wantOrder = []int{}
	for _, key := range want {
		wantOrder = append(wantOrder, origMap[key])
	}

	gotOrder = []int{}
	for _, key := range got {
		gotOrder = append(gotOrder, origMap[key])
	}

	return origOrder, wantOrder, gotOrder
}

func createTestPubKeys(t *testing.T, number, offset int) []*hdkeychain.ExtendedKey {
	xpubRaw := "xpub661MyMwAqRbcFwdnYF5mvCBY54vaLdJf8c5ugJTp5p7PqF9J1USgBx12qYMnZ9yUiswV7smbQ1DSweMqu8wn7Jociz4PWkuJ6EPvoVEgMw7"
	xpubKey, err := hdkeychain.NewKeyFromString(xpubRaw)
	if err != nil {
		t.Fatalf("Failed to generate new key", err)
	}

	keys := make([]*hdkeychain.ExtendedKey, number)
	for i := uint32(0); i < uint32(len(keys)); i++ {
		chPubKey, err := xpubKey.Child(i + uint32(offset))
		if err != nil {
			t.Fatalf("Failed to generate child key", err)
		}
		keys[i] = chPubKey
	}
	return keys
}

func TestReverse(t *testing.T) {
	// Test the utility function that reverses a list of public keys.
	// 11 is arbitrary.
	for numKeys := 0; numKeys < 11; numKeys++ {
		keys := createTestPubKeys(t, numKeys, 0)
		revRevKeys := reverse(reverse(keys))
		if len(keys) != len(revRevKeys) {
			t.Errorf("Reverse(Reverse(x)): the no. pubkeys changed. Got %d, want %d",
				len(revRevKeys), len(keys))
		}

		for i := 0; i < len(keys); i++ {
			if keys[i] != revRevKeys[i] {
				t.Errorf("Reverse(Reverse(x)) != x. Got %v, want %v",
					revRevKeys[i], keys[i])
			}
		}
	}
}

func TestEmpowerSeriesNeuterFailed(t *testing.T) {
	tearDown, _, pool := setUp(t)
	defer tearDown()

	seriesID := uint32(0)
	err := pool.CreateSeries(1, seriesID, 2, []string{pubKey0, pubKey1, pubKey2})
	if err != nil {
		t.Fatalf("Failed to create series: %v", err)
	}

	// A private key with bad version (0xffffffff) will trigger an
	// error in (k *ExtendedKey).Neuter and the associated error path
	// in EmpowerSeries.
	badKey := "wM5uZBNTYmaYGiK8VaGi7zPGbZGLuQgDiR2Zk4nGfbRFLXwHGcMUdVdazRpNHFSR7X7WLmzzbAq8dA1ViN6eWKgKqPye1rJTDQTvBiXvZ7E3nmdx"
	err = pool.EmpowerSeries(seriesID, badKey)

	checkManagerError(t, "", err, waddrmgr.ErrKeyNeuter)
}

func TestDecryptExtendedKeyCannotCreateResultKey(t *testing.T) {
	tearDown, mgr, pool := setUp(t)
	defer tearDown()

	// the plaintext not being base58 encoded triggers the error
	cipherText, err := mgr.Encrypt(waddrmgr.CKTPublic, []byte("not-base58-encoded"))
	if err != nil {
		t.Fatalf("Failed to encrypt plaintext: %v", err)
	}

	if _, err := pool.TstDecryptExtendedKey(waddrmgr.CKTPublic, cipherText); err == nil {
		t.Errorf("Expected function to fail, but it didn't")
	} else {
		gotErr := err.(waddrmgr.ManagerError)
		wantErrCode := waddrmgr.ErrorCode(waddrmgr.ErrKeyChain)
		if gotErr.ErrorCode != wantErrCode {
			t.Errorf("Got %s, want %s", gotErr.ErrorCode, wantErrCode)
		}
	}
}

func TestDecryptExtendedKeyCannotDecrypt(t *testing.T) {
	tearDown, _, pool := setUp(t)
	defer tearDown()

	if _, err := pool.TstDecryptExtendedKey(waddrmgr.CKTPublic, []byte{}); err == nil {
		t.Errorf("Expected function to fail, but it didn't")
	} else {
		gotErr := err.(waddrmgr.ManagerError)
		wantErrCode := waddrmgr.ErrorCode(waddrmgr.ErrCrypto)
		if gotErr.ErrorCode != wantErrCode {
			t.Errorf("Got %s, want %s", gotErr.ErrorCode, wantErrCode)
		}
	}
}

func TestSerializationErrors(t *testing.T) {
	tearDown, mgr, _ := setUp(t)
	defer tearDown()

	tests := []struct {
		version  uint32
		pubKeys  []string
		privKeys []string
		reqSigs  uint32
		err      waddrmgr.ErrorCode
	}{
		{
			version: 2,
			pubKeys: []string{pubKey0, pubKey1, pubKey2},
			err:     waddrmgr.ErrSeriesVersion,
		},
		{
			pubKeys: []string{"NONSENSE"},
			// Not a valid length public key.
			err: waddrmgr.ErrSeriesStorage,
		},
		{
			pubKeys:  []string{pubKey0, pubKey1, pubKey2},
			privKeys: []string{privKey0},
			// The number of public and private keys should be the same.
			err: waddrmgr.ErrSeriesStorage,
		},
		{
			pubKeys:  []string{pubKey0},
			privKeys: []string{"NONSENSE"},
			// Not a valid length private key.
			err: waddrmgr.ErrSeriesStorage,
		},
	}

	// We need to unlock the manager in order to encrypt with the
	// private key.
	mgr.Unlock(privPassphrase)

	active := true
	for testNum, test := range tests {
		encryptedPubs, err := encryptKeys(test.pubKeys, mgr, waddrmgr.CKTPublic)
		if err != nil {
			t.Fatalf("Test #%d - Error encrypting pubkeys: %v", testNum, err)
		}
		encryptedPrivs, err := encryptKeys(test.privKeys, mgr, waddrmgr.CKTPrivate)
		if err != nil {
			t.Fatalf("Test #%d - Error encrypting privkeys: %v", testNum, err)
		}

		_, err = votingpool.SerializeSeries(
			test.version, active, test.reqSigs, encryptedPubs, encryptedPrivs)

		checkManagerError(t, fmt.Sprintf("Test #%d", testNum), err, test.err)
	}
}

func TestSerialization(t *testing.T) {
	tearDown, mgr, _ := setUp(t)
	defer tearDown()

	tests := []struct {
		version  uint32
		active   bool
		pubKeys  []string
		privKeys []string
		reqSigs  uint32
	}{
		{
			version: 1,
			active:  true,
			pubKeys: []string{pubKey0},
			reqSigs: 1,
		},
		{
			version:  0,
			active:   false,
			pubKeys:  []string{pubKey0},
			privKeys: []string{privKey0},
			reqSigs:  1,
		},
		{
			pubKeys:  []string{pubKey0, pubKey1, pubKey2},
			privKeys: []string{privKey0, "", ""},
			reqSigs:  2,
		},
		{
			pubKeys: []string{pubKey0, pubKey1, pubKey2, pubKey3, pubKey4},
			reqSigs: 3,
		},
		{
			pubKeys:  []string{pubKey0, pubKey1, pubKey2, pubKey3, pubKey4, pubKey5, pubKey6},
			privKeys: []string{"", privKey1, "", privKey3, "", "", ""},
			reqSigs:  4,
		},
	}

	// We need to unlock the manager in order to encrypt with the
	// private key.
	mgr.Unlock(privPassphrase)

	for testNum, test := range tests {
		encryptedPubs, err := encryptKeys(test.pubKeys, mgr, waddrmgr.CKTPublic)
		if err != nil {
			t.Fatalf("Test #%d - Error encrypting pubkeys: %v", testNum, err)
		}
		encryptedPrivs, err := encryptKeys(test.privKeys, mgr, waddrmgr.CKTPrivate)
		if err != nil {
			t.Fatalf("Test #%d - Error encrypting privkeys: %v", testNum, err)
		}

		serialized, err := votingpool.SerializeSeries(
			test.version, test.active, test.reqSigs, encryptedPubs, encryptedPrivs)
		if err != nil {
			t.Fatalf("Test #%d - Error in serialization %v", testNum, err)
		}

		row, err := votingpool.DeserializeSeries(serialized)
		if err != nil {
			t.Fatalf("Test #%d - Failed to deserialize %v %v", testNum, serialized, err)
		}

		// TODO: Move all of these checks into one or more separate functions.
		if row.Version != test.version {
			t.Errorf("Serialization #%d - version mismatch: got %d want %d",
				testNum, row.Version, test.version)
		}

		if row.Active != test.active {
			t.Errorf("Serialization #%d - active mismatch: got %d want %d",
				testNum, row.Active, test.active)
		}

		if row.ReqSigs != test.reqSigs {
			t.Errorf("Serialization #%d - row reqSigs off. Got %d, want %d",
				testNum, row.ReqSigs, test.reqSigs)
		}

		if len(row.PubKeysEncrypted) != len(test.pubKeys) {
			t.Errorf("Serialization #%d - Wrong no. of pubkeys. Got %d, want %d",
				testNum, len(row.PubKeysEncrypted), len(test.pubKeys))
		}

		for i, encryptedPub := range encryptedPubs {
			got := string(row.PubKeysEncrypted[i])

			if got != string(encryptedPub) {
				t.Errorf("Serialization #%d - Pubkey deserialization. Got %v, want %v",
					testNum, got, string(encryptedPub))
			}
		}

		if len(row.PrivKeysEncrypted) != len(row.PubKeysEncrypted) {
			t.Errorf("Serialization #%d - no. privkeys (%d) != no. pubkeys (%d)",
				testNum, len(row.PrivKeysEncrypted), len(row.PubKeysEncrypted))
		}

		for i, encryptedPriv := range encryptedPrivs {
			got := string(row.PrivKeysEncrypted[i])

			if got != string(encryptedPriv) {
				t.Errorf("Serialization #%d - Privkey deserialization. Got %v, want %v",
					testNum, got, string(encryptedPriv))
			}
		}
	}
}

func TestDeserializationErrors(t *testing.T) {
	tearDown, _, _ := setUp(t)
	defer tearDown()

	tests := []struct {
		serialized []byte
		err        waddrmgr.ErrorCode
	}{
		{
			serialized: make([]byte, 1000000),
			// Too many bytes (over waddrmgr.seriesMaxSerial).
			err: waddrmgr.ErrSeriesStorage,
		},
		{
			serialized: make([]byte, 10),
			// Not enough bytes (under waddrmgr.seriesMinSerial).
			err: waddrmgr.ErrSeriesStorage,
		},
		{
			serialized: []byte{
				1, 0, 0, 0, // 4 bytes (version)
				0,          // 1 byte (active)
				2, 0, 0, 0, // 4 bytes (reqSigs)
				3, 0, 0, 0, // 4 bytes (nKeys)
			},
			// Here we have the constant data but are missing any public/private keys.
			err: waddrmgr.ErrSeriesStorage,
		},
		{
			serialized: []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			// Unsupported version.
			err: waddrmgr.ErrSeriesVersion,
		},
	}

	for testNum, test := range tests {
		_, err := votingpool.DeserializeSeries(test.serialized)

		checkManagerError(t, fmt.Sprintf("Test #%d", testNum), err, test.err)
	}
}
