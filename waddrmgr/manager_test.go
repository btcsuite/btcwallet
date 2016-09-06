// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr_test

import (
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/jadeblaquiere/ctcd/chaincfg"
	"github.com/jadeblaquiere/ctcd/chaincfg/chainhash"
	"github.com/jadeblaquiere/ctcutil"
	"github.com/jadeblaquiere/ctcwallet/waddrmgr"
	"github.com/jadeblaquiere/ctcwallet/walletdb"
)

// newHash converts the passed big-endian hex string into a chainhash.Hash.
// It only differs from the one available in wire in that it panics on an
// error since it will only (and must only) be called with hard-coded, and
// therefore known good, hashes.
func newHash(hexStr string) *chainhash.Hash {
	hash, err := chainhash.NewHashFromStr(hexStr)
	if err != nil {
		panic(err)
	}
	return hash
}

// testContext is used to store context information about a running test which
// is passed into helper functions.  The useSpends field indicates whether or
// not the spend data should be empty or figure it out based on the specific
// test blocks provided.  This is needed because the first loop where the blocks
// are inserted, the tests are running against the latest block and therefore
// none of the outputs can be spent yet.  However, on subsequent runs, all
// blocks have been inserted and therefore some of the transaction outputs are
// spent.
type testContext struct {
	t            *testing.T
	db           walletdb.DB
	manager      *waddrmgr.Manager
	account      uint32
	create       bool
	unlocked     bool
	watchingOnly bool
}

// addrType is the type of address being tested
type addrType byte

const (
	addrPubKeyHash addrType = iota
	addrScriptHash
)

// expectedAddr is used to house the expected return values from a managed
// address.  Not all fields for used for all managed address types.
type expectedAddr struct {
	address     string
	addressHash []byte
	internal    bool
	compressed  bool
	used        bool
	imported    bool
	pubKey      []byte
	privKey     []byte
	privKeyWIF  string
	script      []byte
}

// testNamePrefix is a helper to return a prefix to show for test errors based
// on the state of the test context.
func testNamePrefix(tc *testContext) string {
	prefix := "Open "
	if tc.create {
		prefix = "Create "
	}

	return prefix + fmt.Sprintf("account #%d", tc.account)
}

// testManagedPubKeyAddress ensures the data returned by all exported functions
// provided by the passed managed p ublic key address matches the corresponding
// fields in the provided expected address.
//
// When the test context indicates the manager is unlocked, the private data
// will also be tested, otherwise, the functions which deal with private data
// are checked to ensure they return the correct error.
func testManagedPubKeyAddress(tc *testContext, prefix string, gotAddr waddrmgr.ManagedPubKeyAddress, wantAddr *expectedAddr) bool {
	// Ensure pubkey is the expected value for the managed address.
	var gpubBytes []byte
	if gotAddr.Compressed() {
		gpubBytes = gotAddr.PubKey().SerializeCompressed()
	} else {
		gpubBytes = gotAddr.PubKey().SerializeUncompressed()
	}
	if !reflect.DeepEqual(gpubBytes, wantAddr.pubKey) {
		tc.t.Errorf("%s PubKey: unexpected public key - got %x, want "+
			"%x", prefix, gpubBytes, wantAddr.pubKey)
		return false
	}

	// Ensure exported pubkey string is the expected value for the managed
	// address.
	gpubHex := gotAddr.ExportPubKey()
	wantPubHex := hex.EncodeToString(wantAddr.pubKey)
	if gpubHex != wantPubHex {
		tc.t.Errorf("%s ExportPubKey: unexpected public key - got %s, "+
			"want %s", prefix, gpubHex, wantPubHex)
		return false
	}

	// Ensure private key is the expected value for the managed address.
	// Since this is only available when the manager is unlocked, also check
	// for the expected error when the manager is locked.
	gotPrivKey, err := gotAddr.PrivKey()
	switch {
	case tc.watchingOnly:
		// Confirm expected watching-only error.
		testName := fmt.Sprintf("%s PrivKey", prefix)
		if !checkManagerError(tc.t, testName, err, waddrmgr.ErrWatchingOnly) {
			return false
		}
	case tc.unlocked:
		if err != nil {
			tc.t.Errorf("%s PrivKey: unexpected error - got %v",
				prefix, err)
			return false
		}
		gpriv := gotPrivKey.Serialize()
		if !reflect.DeepEqual(gpriv, wantAddr.privKey) {
			tc.t.Errorf("%s PrivKey: unexpected private key - "+
				"got %x, want %x", prefix, gpriv, wantAddr.privKey)
			return false
		}
	default:
		// Confirm expected locked error.
		testName := fmt.Sprintf("%s PrivKey", prefix)
		if !checkManagerError(tc.t, testName, err, waddrmgr.ErrLocked) {
			return false
		}
	}

	// Ensure exported private key in Wallet Import Format (WIF) is the
	// expected value for the managed address.  Since this is only available
	// when the manager is unlocked, also check for the expected error when
	// the manager is locked.
	gotWIF, err := gotAddr.ExportPrivKey()
	switch {
	case tc.watchingOnly:
		// Confirm expected watching-only error.
		testName := fmt.Sprintf("%s ExportPrivKey", prefix)
		if !checkManagerError(tc.t, testName, err, waddrmgr.ErrWatchingOnly) {
			return false
		}
	case tc.unlocked:
		if err != nil {
			tc.t.Errorf("%s ExportPrivKey: unexpected error - "+
				"got %v", prefix, err)
			return false
		}
		if gotWIF.String() != wantAddr.privKeyWIF {
			tc.t.Errorf("%s ExportPrivKey: unexpected WIF - got "+
				"%v, want %v", prefix, gotWIF.String(),
				wantAddr.privKeyWIF)
			return false
		}
	default:
		// Confirm expected locked error.
		testName := fmt.Sprintf("%s ExportPrivKey", prefix)
		if !checkManagerError(tc.t, testName, err, waddrmgr.ErrLocked) {
			return false
		}
	}

	return true
}

// testManagedScriptAddress ensures the data returned by all exported functions
// provided by the passed managed script address matches the corresponding
// fields in the provided expected address.
//
// When the test context indicates the manager is unlocked, the private data
// will also be tested, otherwise, the functions which deal with private data
// are checked to ensure they return the correct error.
func testManagedScriptAddress(tc *testContext, prefix string, gotAddr waddrmgr.ManagedScriptAddress, wantAddr *expectedAddr) bool {
	// Ensure script is the expected value for the managed address.
	// Ensure script is the expected value for the managed address.  Since
	// this is only available when the manager is unlocked, also check for
	// the expected error when the manager is locked.
	gotScript, err := gotAddr.Script()
	switch {
	case tc.watchingOnly:
		// Confirm expected watching-only error.
		testName := fmt.Sprintf("%s Script", prefix)
		if !checkManagerError(tc.t, testName, err, waddrmgr.ErrWatchingOnly) {
			return false
		}
	case tc.unlocked:
		if err != nil {
			tc.t.Errorf("%s Script: unexpected error - got %v",
				prefix, err)
			return false
		}
		if !reflect.DeepEqual(gotScript, wantAddr.script) {
			tc.t.Errorf("%s Script: unexpected script - got %x, "+
				"want %x", prefix, gotScript, wantAddr.script)
			return false
		}
	default:
		// Confirm expected locked error.
		testName := fmt.Sprintf("%s Script", prefix)
		if !checkManagerError(tc.t, testName, err, waddrmgr.ErrLocked) {
			return false
		}
	}

	return true
}

// testAddress ensures the data returned by all exported functions provided by
// the passed managed address matches the corresponding fields in the provided
// expected address.  It also type asserts the managed address to determine its
// specific type and calls the corresponding testing functions accordingly.
//
// When the test context indicates the manager is unlocked, the private data
// will also be tested, otherwise, the functions which deal with private data
// are checked to ensure they return the correct error.
func testAddress(tc *testContext, prefix string, gotAddr waddrmgr.ManagedAddress, wantAddr *expectedAddr) bool {
	if gotAddr.Account() != tc.account {
		tc.t.Errorf("ManagedAddress.Account: unexpected account - got "+
			"%d, want %d", gotAddr.Account(), tc.account)
		return false
	}

	if gotAddr.Address().EncodeAddress() != wantAddr.address {
		tc.t.Errorf("%s EncodeAddress: unexpected address - got %s, "+
			"want %s", prefix, gotAddr.Address().EncodeAddress(),
			wantAddr.address)
		return false
	}

	if !reflect.DeepEqual(gotAddr.AddrHash(), wantAddr.addressHash) {
		tc.t.Errorf("%s AddrHash: unexpected address hash - got %x, "+
			"want %x", prefix, gotAddr.AddrHash(),
			wantAddr.addressHash)
		return false
	}

	if gotAddr.Internal() != wantAddr.internal {
		tc.t.Errorf("%s Internal: unexpected internal flag - got %v, "+
			"want %v", prefix, gotAddr.Internal(), wantAddr.internal)
		return false
	}

	if gotAddr.Compressed() != wantAddr.compressed {
		tc.t.Errorf("%s Compressed: unexpected compressed flag - got "+
			"%v, want %v", prefix, gotAddr.Compressed(),
			wantAddr.compressed)
		return false
	}

	if gotAddr.Imported() != wantAddr.imported {
		tc.t.Errorf("%s Imported: unexpected imported flag - got %v, "+
			"want %v", prefix, gotAddr.Imported(), wantAddr.imported)
		return false
	}

	switch addr := gotAddr.(type) {
	case waddrmgr.ManagedPubKeyAddress:
		if !testManagedPubKeyAddress(tc, prefix, addr, wantAddr) {
			return false
		}

	case waddrmgr.ManagedScriptAddress:
		if !testManagedScriptAddress(tc, prefix, addr, wantAddr) {
			return false
		}
	}

	return true
}

// testExternalAddresses tests several facets of external addresses such as
// generating multiple addresses via NextExternalAddresses, ensuring they can be
// retrieved by Address, and that they work properly when the manager is locked
// and unlocked.
func testExternalAddresses(tc *testContext) bool {
	prefix := testNamePrefix(tc) + " testExternalAddresses"
	var addrs []waddrmgr.ManagedAddress
	if tc.create {
		prefix := prefix + " NextExternalAddresses"
		var err error
		addrs, err = tc.manager.NextExternalAddresses(tc.account, 5)
		if err != nil {
			tc.t.Errorf("%s: unexpected error: %v", prefix, err)
			return false
		}
		if len(addrs) != len(expectedExternalAddrs) {
			tc.t.Errorf("%s: unexpected number of addresses - got "+
				"%d, want %d", prefix, len(addrs),
				len(expectedExternalAddrs))
			return false
		}
	}

	// Setup a closure to test the results since the same tests need to be
	// repeated with the manager locked and unlocked.
	testResults := func() bool {
		// Ensure the returned addresses are the expected ones.  When
		// not in the create phase, there will be no addresses in the
		// addrs slice, so this really only runs during the first phase
		// of the tests.
		for i := 0; i < len(addrs); i++ {
			prefix := fmt.Sprintf("%s ExternalAddress #%d", prefix, i)
			if !testAddress(tc, prefix, addrs[i], &expectedExternalAddrs[i]) {
				return false
			}
		}

		// Ensure the last external address is the expected one.
		leaPrefix := prefix + " LastExternalAddress"
		lastAddr, err := tc.manager.LastExternalAddress(tc.account)
		if err != nil {
			tc.t.Errorf("%s: unexpected error: %v", leaPrefix, err)
			return false
		}
		if !testAddress(tc, leaPrefix, lastAddr, &expectedExternalAddrs[len(expectedExternalAddrs)-1]) {
			return false
		}

		// Now, use the Address API to retrieve each of the expected new
		// addresses and ensure they're accurate.
		chainParams := tc.manager.ChainParams()
		for i := 0; i < len(expectedExternalAddrs); i++ {
			pkHash := expectedExternalAddrs[i].addressHash
			utilAddr, err := btcutil.NewAddressPubKeyHash(pkHash,
				chainParams)
			if err != nil {
				tc.t.Errorf("%s NewAddressPubKeyHash #%d: "+
					"unexpected error: %v", prefix, i, err)
				return false
			}

			prefix := fmt.Sprintf("%s Address #%d", prefix, i)
			addr, err := tc.manager.Address(utilAddr)
			if err != nil {
				tc.t.Errorf("%s: unexpected error: %v", prefix,
					err)
				return false
			}

			if !testAddress(tc, prefix, addr, &expectedExternalAddrs[i]) {
				return false
			}
		}

		return true
	}

	// Since the manager is locked at this point, the public address
	// information is tested and the private functions are checked to ensure
	// they return the expected error.
	if !testResults() {
		return false
	}

	// Everything after this point involves retesting with an unlocked
	// address manager which is not possible for watching-only mode, so
	// just exit now in that case.
	if tc.watchingOnly {
		return true
	}

	// Unlock the manager and retest all of the addresses to ensure the
	// private information is valid as well.
	if err := tc.manager.Unlock(privPassphrase); err != nil {
		tc.t.Errorf("Unlock: unexpected error: %v", err)
		return false
	}
	tc.unlocked = true
	if !testResults() {
		return false
	}

	// Relock the manager for future tests.
	if err := tc.manager.Lock(); err != nil {
		tc.t.Errorf("Lock: unexpected error: %v", err)
		return false
	}
	tc.unlocked = false

	return true
}

// testInternalAddresses tests several facets of internal addresses such as
// generating multiple addresses via NextInternalAddresses, ensuring they can be
// retrieved by Address, and that they work properly when the manager is locked
// and unlocked.
func testInternalAddresses(tc *testContext) bool {
	// When the address manager is not in watching-only mode, unlocked it
	// first to ensure that address generation works correctly when the
	// address manager is unlocked and then locked later.  These tests
	// reverse the order done in the external tests which starts with a
	// locked manager and unlock it afterwards.
	if !tc.watchingOnly {
		// Unlock the manager and retest all of the addresses to ensure the
		// private information is valid as well.
		if err := tc.manager.Unlock(privPassphrase); err != nil {
			tc.t.Errorf("Unlock: unexpected error: %v", err)
			return false
		}
		tc.unlocked = true
	}

	prefix := testNamePrefix(tc) + " testInternalAddresses"
	var addrs []waddrmgr.ManagedAddress
	if tc.create {
		prefix := prefix + " NextInternalAddress"
		var err error
		addrs, err = tc.manager.NextInternalAddresses(tc.account, 5)
		if err != nil {
			tc.t.Errorf("%s: unexpected error: %v", prefix, err)
			return false
		}
		if len(addrs) != len(expectedInternalAddrs) {
			tc.t.Errorf("%s: unexpected number of addresses - got "+
				"%d, want %d", prefix, len(addrs),
				len(expectedInternalAddrs))
			return false
		}
	}

	// Setup a closure to test the results since the same tests need to be
	// repeated with the manager locked and unlocked.
	testResults := func() bool {
		// Ensure the returned addresses are the expected ones.  When
		// not in the create phase, there will be no addresses in the
		// addrs slice, so this really only runs during the first phase
		// of the tests.
		for i := 0; i < len(addrs); i++ {
			prefix := fmt.Sprintf("%s InternalAddress #%d", prefix, i)
			if !testAddress(tc, prefix, addrs[i], &expectedInternalAddrs[i]) {
				return false
			}
		}

		// Ensure the last internal address is the expected one.
		liaPrefix := prefix + " LastInternalAddress"
		lastAddr, err := tc.manager.LastInternalAddress(tc.account)
		if err != nil {
			tc.t.Errorf("%s: unexpected error: %v", liaPrefix, err)
			return false
		}
		if !testAddress(tc, liaPrefix, lastAddr, &expectedInternalAddrs[len(expectedInternalAddrs)-1]) {
			return false
		}

		// Now, use the Address API to retrieve each of the expected new
		// addresses and ensure they're accurate.
		chainParams := tc.manager.ChainParams()
		for i := 0; i < len(expectedInternalAddrs); i++ {
			pkHash := expectedInternalAddrs[i].addressHash
			utilAddr, err := btcutil.NewAddressPubKeyHash(pkHash,
				chainParams)
			if err != nil {
				tc.t.Errorf("%s NewAddressPubKeyHash #%d: "+
					"unexpected error: %v", prefix, i, err)
				return false
			}

			prefix := fmt.Sprintf("%s Address #%d", prefix, i)
			addr, err := tc.manager.Address(utilAddr)
			if err != nil {
				tc.t.Errorf("%s: unexpected error: %v", prefix,
					err)
				return false
			}

			if !testAddress(tc, prefix, addr, &expectedInternalAddrs[i]) {
				return false
			}
		}

		return true
	}

	// The address manager could either be locked or unlocked here depending
	// on whether or not it's a watching-only manager.  When it's unlocked,
	// this will test both the public and private address data are accurate.
	// When it's locked, it must be watching-only, so only the public
	// address information is tested and the private functions are checked
	// to ensure they return the expected ErrWatchingOnly error.
	if !testResults() {
		return false
	}

	// Everything after this point involves locking the address manager and
	// retesting the addresses with a locked manager.  However, for
	// watching-only mode, this has already happened, so just exit now in
	// that case.
	if tc.watchingOnly {
		return true
	}

	// Lock the manager and retest all of the addresses to ensure the
	// public information remains valid and the private functions return
	// the expected error.
	if err := tc.manager.Lock(); err != nil {
		tc.t.Errorf("Lock: unexpected error: %v", err)
		return false
	}
	tc.unlocked = false
	if !testResults() {
		return false
	}

	return true
}

// testLocking tests the basic locking semantics of the address manager work
// as expected.  Other tests ensure addresses behave as expected under locked
// and unlocked conditions.
func testLocking(tc *testContext) bool {
	if tc.unlocked {
		tc.t.Error("testLocking called with an unlocked manager")
		return false
	}
	if !tc.manager.IsLocked() {
		tc.t.Error("IsLocked: returned false on locked manager")
		return false
	}

	// Locking an already lock manager should return an error.  The error
	// should be ErrLocked or ErrWatchingOnly depending on the type of the
	// address manager.
	err := tc.manager.Lock()
	wantErrCode := waddrmgr.ErrLocked
	if tc.watchingOnly {
		wantErrCode = waddrmgr.ErrWatchingOnly
	}
	if !checkManagerError(tc.t, "Lock", err, wantErrCode) {
		return false
	}

	// Ensure unlocking with the correct passphrase doesn't return any
	// unexpected errors and the manager properly reports it is unlocked.
	// Since watching-only address managers can't be unlocked, also ensure
	// the correct error for that case.
	err = tc.manager.Unlock(privPassphrase)
	if tc.watchingOnly {
		if !checkManagerError(tc.t, "Unlock", err, waddrmgr.ErrWatchingOnly) {
			return false
		}
	} else if err != nil {
		tc.t.Errorf("Unlock: unexpected error: %v", err)
		return false
	}
	if !tc.watchingOnly && tc.manager.IsLocked() {
		tc.t.Error("IsLocked: returned true on unlocked manager")
		return false
	}

	// Unlocking the manager again is allowed.  Since watching-only address
	// managers can't be unlocked, also ensure the correct error for that
	// case.
	err = tc.manager.Unlock(privPassphrase)
	if tc.watchingOnly {
		if !checkManagerError(tc.t, "Unlock2", err, waddrmgr.ErrWatchingOnly) {
			return false
		}
	} else if err != nil {
		tc.t.Errorf("Unlock: unexpected error: %v", err)
		return false
	}
	if !tc.watchingOnly && tc.manager.IsLocked() {
		tc.t.Error("IsLocked: returned true on unlocked manager")
		return false
	}

	// Unlocking the manager with an invalid passphrase must result in an
	// error and a locked manager.
	err = tc.manager.Unlock([]byte("invalidpassphrase"))
	wantErrCode = waddrmgr.ErrWrongPassphrase
	if tc.watchingOnly {
		wantErrCode = waddrmgr.ErrWatchingOnly
	}
	if !checkManagerError(tc.t, "Unlock", err, wantErrCode) {
		return false
	}
	if !tc.manager.IsLocked() {
		tc.t.Error("IsLocked: manager is unlocked after failed unlock " +
			"attempt")
		return false
	}

	return true
}

// testImportPrivateKey tests that importing private keys works properly.  It
// ensures they can be retrieved by Address after they have been imported and
// the addresses give the expected values when the manager is locked and
// unlocked.
//
// This function expects the manager is already locked when called and returns
// with the manager locked.
func testImportPrivateKey(tc *testContext) bool {
	tests := []struct {
		name       string
		in         string
		blockstamp waddrmgr.BlockStamp
		expected   expectedAddr
	}{
		{
			name: "wif for uncompressed pubkey address",
			in:   "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
			expected: expectedAddr{
				address:     "1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S",
				addressHash: hexToBytes("a65d1a239d4ec666643d350c7bb8fc44d2881128"),
				internal:    false,
				imported:    true,
				compressed:  false,
				pubKey: hexToBytes("04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3" +
					"d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e558" +
					"42ae2bd115d1ed7cc0e82d934e929c97648cb0a"),
				privKey: hexToBytes("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"),
				// privKeyWIF is set to the in field during tests
			},
		},
		{
			name: "wif for compressed pubkey address",
			in:   "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617",
			expected: expectedAddr{
				address:     "1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK",
				addressHash: hexToBytes("d9351dcbad5b8f3b8bfa2f2cdc85c28118ca9326"),
				internal:    false,
				imported:    true,
				compressed:  true,
				pubKey:      hexToBytes("02d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c"),
				privKey:     hexToBytes("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"),
				// privKeyWIF is set to the in field during tests
			},
		},
	}

	// The manager must be unlocked to import a private key, however a
	// watching-only manager can't be unlocked.
	if !tc.watchingOnly {
		if err := tc.manager.Unlock(privPassphrase); err != nil {
			tc.t.Errorf("Unlock: unexpected error: %v", err)
			return false
		}
		tc.unlocked = true
	}

	// Only import the private keys when in the create phase of testing.
	tc.account = waddrmgr.ImportedAddrAccount
	prefix := testNamePrefix(tc) + " testImportPrivateKey"
	if tc.create {
		for i, test := range tests {
			test.expected.privKeyWIF = test.in
			wif, err := btcutil.DecodeWIF(test.in)
			if err != nil {
				tc.t.Errorf("%s DecodeWIF #%d (%s): unexpected "+
					"error: %v", prefix, i, test.name, err)
				continue
			}
			addr, err := tc.manager.ImportPrivateKey(wif,
				&test.blockstamp)
			if err != nil {
				tc.t.Errorf("%s ImportPrivateKey #%d (%s): "+
					"unexpected error: %v", prefix, i,
					test.name, err)
				continue
			}
			if !testAddress(tc, prefix+" ImportPrivateKey", addr,
				&test.expected) {
				continue
			}
		}
	}

	// Setup a closure to test the results since the same tests need to be
	// repeated with the manager unlocked and locked.
	chainParams := tc.manager.ChainParams()
	testResults := func() bool {
		failed := false
		for i, test := range tests {
			test.expected.privKeyWIF = test.in

			// Use the Address API to retrieve each of the expected
			// new addresses and ensure they're accurate.
			utilAddr, err := btcutil.NewAddressPubKeyHash(
				test.expected.addressHash, chainParams)
			if err != nil {
				tc.t.Errorf("%s NewAddressPubKeyHash #%d (%s): "+
					"unexpected error: %v", prefix, i,
					test.name, err)
				failed = true
				continue
			}
			taPrefix := fmt.Sprintf("%s Address #%d (%s)", prefix,
				i, test.name)
			ma, err := tc.manager.Address(utilAddr)
			if err != nil {
				tc.t.Errorf("%s: unexpected error: %v", taPrefix,
					err)
				failed = true
				continue
			}
			if !testAddress(tc, taPrefix, ma, &test.expected) {
				failed = true
				continue
			}
		}

		return !failed
	}

	// The address manager could either be locked or unlocked here depending
	// on whether or not it's a watching-only manager.  When it's unlocked,
	// this will test both the public and private address data are accurate.
	// When it's locked, it must be watching-only, so only the public
	// address  information is tested and the private functions are checked
	// to ensure they return the expected ErrWatchingOnly error.
	if !testResults() {
		return false
	}

	// Everything after this point involves locking the address manager and
	// retesting the addresses with a locked manager.  However, for
	// watching-only mode, this has already happened, so just exit now in
	// that case.
	if tc.watchingOnly {
		return true
	}

	// Lock the manager and retest all of the addresses to ensure the
	// private information returns the expected error.
	if err := tc.manager.Lock(); err != nil {
		tc.t.Errorf("Lock: unexpected error: %v", err)
		return false
	}
	tc.unlocked = false
	if !testResults() {
		return false
	}

	return true
}

// testImportScript tests that importing scripts works properly.  It ensures
// they can be retrieved by Address after they have been imported and the
// addresses give the expected values when the manager is locked and unlocked.
//
// This function expects the manager is already locked when called and returns
// with the manager locked.
func testImportScript(tc *testContext) bool {
	tests := []struct {
		name       string
		in         []byte
		blockstamp waddrmgr.BlockStamp
		expected   expectedAddr
	}{
		{
			name: "p2sh uncompressed pubkey",
			in: hexToBytes("41048b65a0e6bb200e6dac05e74281b1ab9a41e8" +
				"0006d6b12d8521e09981da97dd96ac72d24d1a7d" +
				"ed9493a9fc20fdb4a714808f0b680f1f1d935277" +
				"48b5e3f629ffac"),
			expected: expectedAddr{
				address:     "3MbyWAu9UaoBewR3cArF1nwf4aQgVwzrA5",
				addressHash: hexToBytes("da6e6a632d96dc5530d7b3c9f3017725d023093e"),
				internal:    false,
				imported:    true,
				compressed:  false,
				// script is set to the in field during tests.
			},
		},
		{
			name: "p2sh multisig",
			in: hexToBytes("524104cb9c3c222c5f7a7d3b9bd152f363a0b6d5" +
				"4c9eb312c4d4f9af1e8551b6c421a6a4ab0e2910" +
				"5f24de20ff463c1c91fcf3bf662cdde4783d4799" +
				"f787cb7c08869b4104ccc588420deeebea22a7e9" +
				"00cc8b68620d2212c374604e3487ca08f1ff3ae1" +
				"2bdc639514d0ec8612a2d3c519f084d9a00cbbe3" +
				"b53d071e9b09e71e610b036aa24104ab47ad1939" +
				"edcb3db65f7fedea62bbf781c5410d3f22a7a3a5" +
				"6ffefb2238af8627363bdf2ed97c1f89784a1aec" +
				"db43384f11d2acc64443c7fc299cef0400421a53ae"),
			expected: expectedAddr{
				address:     "34CRZpt8j81rgh9QhzuBepqPi4cBQSjhjr",
				addressHash: hexToBytes("1b800cec1fe92222f36a502c139bed47c5959715"),
				internal:    false,
				imported:    true,
				compressed:  false,
				// script is set to the in field during tests.
			},
		},
	}

	// The manager must be unlocked to import a private key and also for
	// testing private data.  However, a watching-only manager can't be
	// unlocked.
	if !tc.watchingOnly {
		if err := tc.manager.Unlock(privPassphrase); err != nil {
			tc.t.Errorf("Unlock: unexpected error: %v", err)
			return false
		}
		tc.unlocked = true
	}

	// Only import the scripts when in the create phase of testing.
	tc.account = waddrmgr.ImportedAddrAccount
	prefix := testNamePrefix(tc)
	if tc.create {
		for i, test := range tests {
			test.expected.script = test.in
			prefix := fmt.Sprintf("%s ImportScript #%d (%s)", prefix,
				i, test.name)

			addr, err := tc.manager.ImportScript(test.in,
				&test.blockstamp)
			if err != nil {
				tc.t.Errorf("%s: unexpected error: %v", prefix,
					err)
				continue
			}
			if !testAddress(tc, prefix, addr, &test.expected) {
				continue
			}
		}
	}

	// Setup a closure to test the results since the same tests need to be
	// repeated with the manager unlocked and locked.
	chainParams := tc.manager.ChainParams()
	testResults := func() bool {
		failed := false
		for i, test := range tests {
			test.expected.script = test.in

			// Use the Address API to retrieve each of the expected
			// new addresses and ensure they're accurate.
			utilAddr, err := btcutil.NewAddressScriptHash(test.in,
				chainParams)
			if err != nil {
				tc.t.Errorf("%s NewAddressScriptHash #%d (%s): "+
					"unexpected error: %v", prefix, i,
					test.name, err)
				failed = true
				continue
			}
			taPrefix := fmt.Sprintf("%s Address #%d (%s)", prefix,
				i, test.name)
			ma, err := tc.manager.Address(utilAddr)
			if err != nil {
				tc.t.Errorf("%s: unexpected error: %v", taPrefix,
					err)
				failed = true
				continue
			}
			if !testAddress(tc, taPrefix, ma, &test.expected) {
				failed = true
				continue
			}
		}

		return !failed
	}

	// The address manager could either be locked or unlocked here depending
	// on whether or not it's a watching-only manager.  When it's unlocked,
	// this will test both the public and private address data are accurate.
	// When it's locked, it must be watching-only, so only the public
	// address information is tested and the private functions are checked
	// to ensure they return the expected ErrWatchingOnly error.
	if !testResults() {
		return false
	}

	// Everything after this point involves locking the address manager and
	// retesting the addresses with a locked manager.  However, for
	// watching-only mode, this has already happened, so just exit now in
	// that case.
	if tc.watchingOnly {
		return true
	}

	// Lock the manager and retest all of the addresses to ensure the
	// private information returns the expected error.
	if err := tc.manager.Lock(); err != nil {
		tc.t.Errorf("Lock: unexpected error: %v", err)
		return false
	}
	tc.unlocked = false
	if !testResults() {
		return false
	}

	return true
}

// testMarkUsed ensures used addresses are flagged as such.
func testMarkUsed(tc *testContext) bool {
	tests := []struct {
		name string
		typ  addrType
		in   []byte
	}{
		{
			name: "managed address",
			typ:  addrPubKeyHash,
			in:   hexToBytes("2ef94abb9ee8f785d087c3ec8d6ee467e92d0d0a"),
		},
		{
			name: "script address",
			typ:  addrScriptHash,
			in:   hexToBytes("da6e6a632d96dc5530d7b3c9f3017725d023093e"),
		},
	}

	prefix := "MarkUsed"
	chainParams := tc.manager.ChainParams()
	for i, test := range tests {
		addrHash := test.in

		var addr btcutil.Address
		var err error
		switch test.typ {
		case addrPubKeyHash:
			addr, err = btcutil.NewAddressPubKeyHash(addrHash, chainParams)
		case addrScriptHash:
			addr, err = btcutil.NewAddressScriptHashFromHash(addrHash, chainParams)
		default:
			panic("unreachable")
		}
		if err != nil {
			tc.t.Errorf("%s #%d: NewAddress unexpected error: %v", prefix, i, err)
			continue
		}

		maddr, err := tc.manager.Address(addr)
		if err != nil {
			tc.t.Errorf("%s #%d: Address unexpected error: %v", prefix, i, err)
			continue
		}
		if tc.create {
			// Test that initially the address is not flagged as used
			used, err := maddr.Used()
			if err != nil {
				tc.t.Errorf("%s #%d: Used unexpected error: %v", prefix, i, err)
				continue
			}
			if used != false {
				tc.t.Errorf("%s #%d: unexpected used flag -- got "+
					"%v, want %v", prefix, i, used, false)
			}
		}
		err = tc.manager.MarkUsed(addr)
		if err != nil {
			tc.t.Errorf("%s #%d: unexpected error: %v", prefix, i, err)
			continue
		}
		used, err := maddr.Used()
		if err != nil {
			tc.t.Errorf("%s #%d: Used unexpected error: %v", prefix, i, err)
			continue
		}
		if used != true {
			tc.t.Errorf("%s #%d: unexpected used flag -- got "+
				"%v, want %v", prefix, i, used, true)
		}
	}

	return true
}

// testChangePassphrase ensures changes both the public and privte passphrases
// works as intended.
func testChangePassphrase(tc *testContext) bool {
	// Force an error when changing the passphrase due to failure to
	// generate a new secret key by replacing the generation function one
	// that intentionally errors.
	testName := "ChangePassphrase (public) with invalid new secret key"

	var err error
	waddrmgr.TstRunWithReplacedNewSecretKey(func() {
		err = tc.manager.ChangePassphrase(pubPassphrase, pubPassphrase2, false, fastScrypt)
	})
	if !checkManagerError(tc.t, testName, err, waddrmgr.ErrCrypto) {
		return false
	}

	// Attempt to change public passphrase with invalid old passphrase.
	testName = "ChangePassphrase (public) with invalid old passphrase"
	err = tc.manager.ChangePassphrase([]byte("bogus"), pubPassphrase2, false, fastScrypt)
	if !checkManagerError(tc.t, testName, err, waddrmgr.ErrWrongPassphrase) {
		return false
	}

	// Change the public passphrase.
	testName = "ChangePassphrase (public)"
	err = tc.manager.ChangePassphrase(pubPassphrase, pubPassphrase2, false, fastScrypt)
	if err != nil {
		tc.t.Errorf("%s: unexpected error: %v", testName, err)
		return false
	}

	// Ensure the public passphrase was successfully changed.
	if !tc.manager.TstCheckPublicPassphrase(pubPassphrase2) {
		tc.t.Errorf("%s: passphrase does not match", testName)
		return false
	}

	// Change the private passphrase back to what it was.
	err = tc.manager.ChangePassphrase(pubPassphrase2, pubPassphrase, false, fastScrypt)
	if err != nil {
		tc.t.Errorf("%s: unexpected error: %v", testName, err)
		return false
	}

	// Attempt to change private passphrase with invalid old passphrase.
	// The error should be ErrWrongPassphrase or ErrWatchingOnly depending
	// on the type of the address manager.
	testName = "ChangePassphrase (private) with invalid old passphrase"
	err = tc.manager.ChangePassphrase([]byte("bogus"), privPassphrase2, true, fastScrypt)
	wantErrCode := waddrmgr.ErrWrongPassphrase
	if tc.watchingOnly {
		wantErrCode = waddrmgr.ErrWatchingOnly
	}
	if !checkManagerError(tc.t, testName, err, wantErrCode) {
		return false
	}

	// Everything after this point involves testing that the private
	// passphrase for the address manager can be changed successfully.
	// This is not possible for watching-only mode, so just exit now in that
	// case.
	if tc.watchingOnly {
		return true
	}

	// Change the private passphrase.
	testName = "ChangePassphrase (private)"
	err = tc.manager.ChangePassphrase(privPassphrase, privPassphrase2, true, fastScrypt)
	if err != nil {
		tc.t.Errorf("%s: unexpected error: %v", testName, err)
		return false
	}

	// Unlock the manager with the new passphrase to ensure it changed as
	// expected.
	if err := tc.manager.Unlock(privPassphrase2); err != nil {
		tc.t.Errorf("%s: failed to unlock with new private "+
			"passphrase: %v", testName, err)
		return false
	}
	tc.unlocked = true

	// Change the private passphrase back to what it was while the manager
	// is unlocked to ensure that path works properly as well.
	err = tc.manager.ChangePassphrase(privPassphrase2, privPassphrase, true, fastScrypt)
	if err != nil {
		tc.t.Errorf("%s: unexpected error: %v", testName, err)
		return false
	}
	if tc.manager.IsLocked() {
		tc.t.Errorf("%s: manager is locked", testName)
		return false
	}

	// Relock the manager for future tests.
	if err := tc.manager.Lock(); err != nil {
		tc.t.Errorf("Lock: unexpected error: %v", err)
		return false
	}
	tc.unlocked = false

	return true
}

// testNewAccount tests the new account creation func of the address manager works
// as expected.
func testNewAccount(tc *testContext) bool {
	if tc.watchingOnly {
		// Creating new accounts in watching-only mode should return ErrWatchingOnly
		_, err := tc.manager.NewAccount("test")
		if !checkManagerError(tc.t, "Create account in watching-only mode", err,
			waddrmgr.ErrWatchingOnly) {
			tc.manager.Close()
			return false
		}
		return true
	}
	// Creating new accounts when wallet is locked should return ErrLocked
	_, err := tc.manager.NewAccount("test")
	if !checkManagerError(tc.t, "Create account when wallet is locked", err,
		waddrmgr.ErrLocked) {
		tc.manager.Close()
		return false
	}
	// Unlock the wallet to decrypt cointype keys required
	// to derive account keys
	if err := tc.manager.Unlock(privPassphrase); err != nil {
		tc.t.Errorf("Unlock: unexpected error: %v", err)
		return false
	}
	tc.unlocked = true

	testName := "acct-create"
	expectedAccount := tc.account + 1
	if !tc.create {
		// Create a new account in open mode
		testName = "acct-open"
		expectedAccount++
	}
	account, err := tc.manager.NewAccount(testName)
	if err != nil {
		tc.t.Errorf("NewAccount: unexpected error: %v", err)
		return false
	}
	if account != expectedAccount {
		tc.t.Errorf("NewAccount "+
			"account mismatch -- got %d, "+
			"want %d", account, expectedAccount)
		return false
	}

	// Test duplicate account name error
	_, err = tc.manager.NewAccount(testName)
	wantErrCode := waddrmgr.ErrDuplicateAccount
	if !checkManagerError(tc.t, testName, err, wantErrCode) {
		return false
	}
	// Test account name validation
	testName = "" // Empty account names are not allowed
	_, err = tc.manager.NewAccount(testName)
	wantErrCode = waddrmgr.ErrInvalidAccount
	if !checkManagerError(tc.t, testName, err, wantErrCode) {
		return false
	}
	testName = "imported" // A reserved account name
	_, err = tc.manager.NewAccount(testName)
	wantErrCode = waddrmgr.ErrInvalidAccount
	if !checkManagerError(tc.t, testName, err, wantErrCode) {
		return false
	}
	return true
}

// testLookupAccount tests the basic account lookup func of the address manager
// works as expected.
func testLookupAccount(tc *testContext) bool {
	// Lookup accounts created earlier in testNewAccount
	expectedAccounts := map[string]uint32{
		waddrmgr.TstDefaultAccountName:   waddrmgr.DefaultAccountNum,
		waddrmgr.ImportedAddrAccountName: waddrmgr.ImportedAddrAccount,
	}
	for acctName, expectedAccount := range expectedAccounts {
		account, err := tc.manager.LookupAccount(acctName)
		if err != nil {
			tc.t.Errorf("LookupAccount: unexpected error: %v", err)
			return false
		}
		if account != expectedAccount {
			tc.t.Errorf("LookupAccount "+
				"account mismatch -- got %d, "+
				"want %d", account, expectedAccount)
			return false
		}
	}
	// Test account not found error
	testName := "non existent account"
	_, err := tc.manager.LookupAccount(testName)
	wantErrCode := waddrmgr.ErrAccountNotFound
	if !checkManagerError(tc.t, testName, err, wantErrCode) {
		return false
	}

	// Test last account
	lastAccount, err := tc.manager.LastAccount()
	var expectedLastAccount uint32
	expectedLastAccount = 1
	if !tc.create {
		// Existing wallet manager will have 3 accounts
		expectedLastAccount = 2
	}
	if lastAccount != expectedLastAccount {
		tc.t.Errorf("LookupAccount "+
			"account mismatch -- got %d, "+
			"want %d", lastAccount, expectedLastAccount)
		return false
	}

	// Test account lookup for default account adddress
	var expectedAccount uint32
	for i, addr := range expectedAddrs {
		addr, err := btcutil.NewAddressPubKeyHash(addr.addressHash,
			tc.manager.ChainParams())
		if err != nil {
			tc.t.Errorf("AddrAccount #%d: unexpected error: %v", i, err)
			return false
		}
		account, err := tc.manager.AddrAccount(addr)
		if err != nil {
			tc.t.Errorf("AddrAccount #%d: unexpected error: %v", i, err)
			return false
		}
		if account != expectedAccount {
			tc.t.Errorf("AddrAccount "+
				"account mismatch -- got %d, "+
				"want %d", account, expectedAccount)
			return false
		}
	}
	return true
}

// testRenameAccount tests the rename account func of the address manager works
// as expected.
func testRenameAccount(tc *testContext) bool {
	acctName, err := tc.manager.AccountName(tc.account)
	if err != nil {
		tc.t.Errorf("AccountName: unexpected error: %v", err)
		return false
	}
	testName := acctName + "-renamed"
	err = tc.manager.RenameAccount(tc.account, testName)
	if err != nil {
		tc.t.Errorf("RenameAccount: unexpected error: %v", err)
		return false
	}
	newName, err := tc.manager.AccountName(tc.account)
	if err != nil {
		tc.t.Errorf("AccountName: unexpected error: %v", err)
		return false
	}
	if newName != testName {
		tc.t.Errorf("RenameAccount "+
			"account name mismatch -- got %s, "+
			"want %s", newName, testName)
		return false
	}
	// Test duplicate account name error
	err = tc.manager.RenameAccount(tc.account, testName)
	wantErrCode := waddrmgr.ErrDuplicateAccount
	if !checkManagerError(tc.t, testName, err, wantErrCode) {
		return false
	}
	// Test old account name is no longer valid
	_, err = tc.manager.LookupAccount(acctName)
	wantErrCode = waddrmgr.ErrAccountNotFound
	if !checkManagerError(tc.t, testName, err, wantErrCode) {
		return false
	}
	return true
}

// testForEachAccount tests the retrieve all accounts func of the address
// manager works as expected.
func testForEachAccount(tc *testContext) bool {
	prefix := testNamePrefix(tc) + " testForEachAccount"
	expectedAccounts := []uint32{0, 1}
	if !tc.create {
		// Existing wallet manager will have 3 accounts
		expectedAccounts = append(expectedAccounts, 2)
	}
	// Imported account
	expectedAccounts = append(expectedAccounts, waddrmgr.ImportedAddrAccount)
	var accounts []uint32
	err := tc.manager.ForEachAccount(func(account uint32) error {
		accounts = append(accounts, account)
		return nil
	})
	if err != nil {
		tc.t.Errorf("%s: unexpected error: %v", prefix, err)
		return false
	}
	if len(accounts) != len(expectedAccounts) {
		tc.t.Errorf("%s: unexpected number of accounts - got "+
			"%d, want %d", prefix, len(accounts),
			len(expectedAccounts))
		return false
	}
	for i, account := range accounts {
		if expectedAccounts[i] != account {
			tc.t.Errorf("%s #%d: "+
				"account mismatch -- got %d, "+
				"want %d", prefix, i, account, expectedAccounts[i])
		}
	}
	return true
}

// testForEachAccountAddress tests that iterating through the given
// account addresses using the manager API works as expected.
func testForEachAccountAddress(tc *testContext) bool {
	prefix := testNamePrefix(tc) + " testForEachAccountAddress"
	// Make a map of expected addresses
	expectedAddrMap := make(map[string]*expectedAddr, len(expectedAddrs))
	for i := 0; i < len(expectedAddrs); i++ {
		expectedAddrMap[expectedAddrs[i].address] = &expectedAddrs[i]
	}

	var addrs []waddrmgr.ManagedAddress
	err := tc.manager.ForEachAccountAddress(tc.account,
		func(maddr waddrmgr.ManagedAddress) error {
			addrs = append(addrs, maddr)
			return nil
		})
	if err != nil {
		tc.t.Errorf("%s: unexpected error: %v", prefix, err)
		return false
	}

	for i := 0; i < len(addrs); i++ {
		prefix := fmt.Sprintf("%s: #%d", prefix, i)
		gotAddr := addrs[i]
		wantAddr := expectedAddrMap[gotAddr.Address().String()]
		if !testAddress(tc, prefix, gotAddr, wantAddr) {
			return false
		}
		delete(expectedAddrMap, gotAddr.Address().String())
	}

	if len(expectedAddrMap) != 0 {
		tc.t.Errorf("%s: unexpected addresses -- got %d, want %d", prefix,
			len(expectedAddrMap), 0)
		return false
	}

	return true
}

// testManagerAPI tests the functions provided by the Manager API as well as
// the ManagedAddress, ManagedPubKeyAddress, and ManagedScriptAddress
// interfaces.
func testManagerAPI(tc *testContext) {
	testLocking(tc)
	testExternalAddresses(tc)
	testInternalAddresses(tc)
	testImportPrivateKey(tc)
	testImportScript(tc)
	testMarkUsed(tc)
	testChangePassphrase(tc)

	// Reset default account
	tc.account = 0
	testNewAccount(tc)
	testLookupAccount(tc)
	testForEachAccount(tc)
	testForEachAccountAddress(tc)

	// Rename account 1 "acct-create"
	tc.account = 1
	testRenameAccount(tc)
}

// testWatchingOnly tests various facets of a watching-only address
// manager such as running the full set of API tests against a newly converted
// copy as well as when it is opened from an existing namespace.
func testWatchingOnly(tc *testContext) bool {
	// Make a copy of the current database so the copy can be converted to
	// watching only.
	woMgrName := "mgrtestwo.bin"
	_ = os.Remove(woMgrName)
	fi, err := os.OpenFile(woMgrName, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		tc.t.Errorf("%v", err)
		return false
	}
	if err := tc.db.Copy(fi); err != nil {
		fi.Close()
		tc.t.Errorf("%v", err)
		return false
	}
	fi.Close()
	defer os.Remove(woMgrName)

	// Open the new database copy and get the address manager namespace.
	db, namespace, err := openDbNamespace(woMgrName)
	if err != nil {
		tc.t.Errorf("openDbNamespace: unexpected error: %v", err)
		return false
	}
	defer db.Close()

	// Open the manager using the namespace and convert it to watching-only.
	mgr, err := waddrmgr.Open(namespace, pubPassphrase,
		&chaincfg.MainNetParams, nil)
	if err != nil {
		tc.t.Errorf("%v", err)
		return false
	}
	if err := mgr.ConvertToWatchingOnly(); err != nil {
		tc.t.Errorf("%v", err)
		return false
	}

	// Run all of the manager API tests against the converted manager and
	// close it.
	testManagerAPI(&testContext{
		t:            tc.t,
		db:           db,
		manager:      mgr,
		account:      0,
		create:       false,
		watchingOnly: true,
	})
	mgr.Close()

	// Open the watching-only manager and run all the tests again.
	mgr, err = waddrmgr.Open(namespace, pubPassphrase, &chaincfg.MainNetParams,
		nil)
	if err != nil {
		tc.t.Errorf("Open Watching-Only: unexpected error: %v", err)
		return false
	}
	defer mgr.Close()

	testManagerAPI(&testContext{
		t:            tc.t,
		db:           db,
		manager:      mgr,
		account:      0,
		create:       false,
		watchingOnly: true,
	})

	return true
}

// testSync tests various facets of setting the manager sync state.
func testSync(tc *testContext) bool {
	tests := []struct {
		name string
		hash *chainhash.Hash
	}{
		{
			name: "Block 1",
			hash: newHash("00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"),
		},
		{
			name: "Block 2",
			hash: newHash("000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd"),
		},
		{
			name: "Block 3",
			hash: newHash("0000000082b5015589a3fdf2d4baff403e6f0be035a5d9742c1cae6295464449"),
		},
		{
			name: "Block 4",
			hash: newHash("000000004ebadb55ee9096c9a2f8880e09da59c0d68b1c228da88e48844a1485"),
		},
		{
			name: "Block 5",
			hash: newHash("000000009b7262315dbf071787ad3656097b892abffd1f95a1a022f896f533fc"),
		},
		{
			name: "Block 6",
			hash: newHash("000000003031a0e73735690c5a1ff2a4be82553b2a12b776fbd3a215dc8f778d"),
		},
		{
			name: "Block 7",
			hash: newHash("0000000071966c2b1d065fd446b1e485b2c9d9594acd2007ccbd5441cfc89444"),
		},
		{
			name: "Block 8",
			hash: newHash("00000000408c48f847aa786c2268fc3e6ec2af68e8468a34a28c61b7f1de0dc6"),
		},
		{
			name: "Block 9",
			hash: newHash("000000008d9dc510f23c2657fc4f67bea30078cc05a90eb89e84cc475c080805"),
		},
		{
			name: "Block 10",
			hash: newHash("000000002c05cc2e78923c34df87fd108b22221ac6076c18f3ade378a4d915e9"),
		},
		{
			name: "Block 11",
			hash: newHash("0000000097be56d606cdd9c54b04d4747e957d3608abe69198c661f2add73073"),
		},
		{
			name: "Block 12",
			hash: newHash("0000000027c2488e2510d1acf4369787784fa20ee084c258b58d9fbd43802b5e"),
		},
		{
			name: "Block 13",
			hash: newHash("000000005c51de2031a895adc145ee2242e919a01c6d61fb222a54a54b4d3089"),
		},
		{
			name: "Block 14",
			hash: newHash("0000000080f17a0c5a67f663a9bc9969eb37e81666d9321125f0e293656f8a37"),
		},
		{
			name: "Block 15",
			hash: newHash("00000000b3322c8c3ef7d2cf6da009a776e6a99ee65ec5a32f3f345712238473"),
		},
		{
			name: "Block 16",
			hash: newHash("00000000174a25bb399b009cc8deff1c4b3ea84df7e93affaaf60dc3416cc4f5"),
		},
		{
			name: "Block 17",
			hash: newHash("000000003ff1d0d70147acfbef5d6a87460ff5bcfce807c2d5b6f0a66bfdf809"),
		},
		{
			name: "Block 18",
			hash: newHash("000000008693e98cf893e4c85a446b410bb4dfa129bd1be582c09ed3f0261116"),
		},
		{
			name: "Block 19",
			hash: newHash("00000000841cb802ca97cf20fb9470480cae9e5daa5d06b4a18ae2d5dd7f186f"),
		},
		{
			name: "Block 20",
			hash: newHash("0000000067a97a2a37b8f190a17f0221e9c3f4fa824ddffdc2e205eae834c8d7"),
		},
		{
			name: "Block 21",
			hash: newHash("000000006f016342d1275be946166cff975c8b27542de70a7113ac6d1ef3294f"),
		},
	}

	// Ensure there are enough test vectors to prove the maximum number of
	// recent hashes is working properly.
	maxRecentHashes := waddrmgr.TstMaxRecentHashes
	if len(tests) < maxRecentHashes-1 {
		tc.t.Errorf("Not enough hashes to test max recent hashes - "+
			"need %d, have %d", maxRecentHashes-1, len(tests))
		return false
	}

	for i, test := range tests {
		blockStamp := waddrmgr.BlockStamp{
			Height: int32(i) + 1,
			Hash:   *test.hash,
		}
		if err := tc.manager.SetSyncedTo(&blockStamp); err != nil {
			tc.t.Errorf("SetSyncedTo unexpected err: %v", err)
			return false
		}

		// Ensure the manager now claims it is synced to the block stamp
		// that was just set.
		gotBlockStamp := tc.manager.SyncedTo()
		if gotBlockStamp != blockStamp {
			tc.t.Errorf("SyncedTo unexpected block stamp -- got "+
				"%v, want %v", gotBlockStamp, blockStamp)
			return false
		}

		// Ensure the recent blocks iterator works properly.
		j := 0
		iter := tc.manager.NewIterateRecentBlocks()
		for cont := iter != nil; cont; cont = iter.Prev() {
			wantHeight := int32(i) - int32(j) + 1
			var wantHash *chainhash.Hash
			if wantHeight == 0 {
				wantHash = chaincfg.MainNetParams.GenesisHash
			} else {
				wantHash = tests[wantHeight-1].hash
			}

			gotBS := iter.BlockStamp()
			if gotBS.Height != wantHeight {
				tc.t.Errorf("NewIterateRecentBlocks block "+
					"stamp height mismatch -- got %d, "+
					"want %d", gotBS.Height, wantHeight)
				return false
			}
			if gotBS.Hash != *wantHash {
				tc.t.Errorf("NewIterateRecentBlocks block "+
					"stamp hash mismatch -- got %v, "+
					"want %v", gotBS.Hash, wantHash)
				return false
			}
			j++
		}

		// Ensure the maximum number of recent hashes works as expected.
		if i >= maxRecentHashes-1 && j != maxRecentHashes {
			tc.t.Errorf("NewIterateRecentBlocks iterated more than "+
				"the max number of expected blocks -- got %d, "+
				"want %d", j, maxRecentHashes)
			return false
		}
	}

	// Ensure rollback to block in recent history works as expected.
	blockStamp := waddrmgr.BlockStamp{
		Height: 10,
		Hash:   *tests[9].hash,
	}
	if err := tc.manager.SetSyncedTo(&blockStamp); err != nil {
		tc.t.Errorf("SetSyncedTo unexpected err on rollback to block "+
			"in recent history: %v", err)
		return false
	}
	gotBlockStamp := tc.manager.SyncedTo()
	if gotBlockStamp != blockStamp {
		tc.t.Errorf("SyncedTo unexpected block stamp on rollback -- "+
			"got %v, want %v", gotBlockStamp, blockStamp)
		return false
	}

	// Ensure syncing to a block that is in the future as compared to the
	// current  block stamp clears the old recent blocks.
	blockStamp = waddrmgr.BlockStamp{
		Height: 100,
		Hash:   *newHash("000000007bc154e0fa7ea32218a72fe2c1bb9f86cf8c9ebf9a715ed27fdb229a"),
	}
	if err := tc.manager.SetSyncedTo(&blockStamp); err != nil {
		tc.t.Errorf("SetSyncedTo unexpected err on future block stamp: "+
			"%v", err)
		return false
	}
	numRecentBlocks := 0
	iter := tc.manager.NewIterateRecentBlocks()
	for cont := iter != nil; cont; cont = iter.Prev() {
		numRecentBlocks++
	}
	if numRecentBlocks != 1 {
		tc.t.Errorf("Unexpected number of blocks after future block "+
			"stamp -- got %d, want %d", numRecentBlocks, 1)
		return false
	}

	// Rollback to a block that is not in the recent block history and
	// ensure it results in only that block.
	blockStamp = waddrmgr.BlockStamp{
		Height: 1,
		Hash:   *tests[0].hash,
	}
	if err := tc.manager.SetSyncedTo(&blockStamp); err != nil {
		tc.t.Errorf("SetSyncedTo unexpected err on rollback to block "+
			"not in recent history: %v", err)
		return false
	}
	gotBlockStamp = tc.manager.SyncedTo()
	if gotBlockStamp != blockStamp {
		tc.t.Errorf("SyncedTo unexpected block stamp on rollback to "+
			"block not in recent history -- got %v, want %v",
			gotBlockStamp, blockStamp)
		return false
	}
	numRecentBlocks = 0
	iter = tc.manager.NewIterateRecentBlocks()
	for cont := iter != nil; cont; cont = iter.Prev() {
		numRecentBlocks++
	}
	if numRecentBlocks != 1 {
		tc.t.Errorf("Unexpected number of blocks after rollback to "+
			"block not in recent history -- got %d, want %d",
			numRecentBlocks, 1)
		return false
	}

	// Ensure syncing the manager to nil results in the synced to state
	// being the earliest block (genesis block in this case).
	if err := tc.manager.SetSyncedTo(nil); err != nil {
		tc.t.Errorf("SetSyncedTo unexpected err on nil: %v", err)
		return false
	}
	blockStamp = waddrmgr.BlockStamp{
		Height: 0,
		Hash:   *chaincfg.MainNetParams.GenesisHash,
	}
	gotBlockStamp = tc.manager.SyncedTo()
	if gotBlockStamp != blockStamp {
		tc.t.Errorf("SyncedTo unexpected block stamp on nil -- "+
			"got %v, want %v", gotBlockStamp, blockStamp)
		return false
	}

	return true
}

// TestManager performs a full suite of tests against the address manager API.
// It makes use of a test context because the address manager is persistent and
// much of the testing involves having specific state.
func TestManager(t *testing.T) {
	t.Parallel()

	dbName := "mgrtest.bin"
	_ = os.Remove(dbName)
	db, mgrNamespace, err := createDbNamespace(dbName)
	if err != nil {
		t.Errorf("createDbNamespace: unexpected error: %v", err)
		return
	}
	defer os.Remove(dbName)
	defer db.Close()

	// Open manager that does not exist to ensure the expected error is
	// returned.
	_, err = waddrmgr.Open(mgrNamespace, pubPassphrase,
		&chaincfg.MainNetParams, nil)
	if !checkManagerError(t, "Open non-existant", err, waddrmgr.ErrNoExist) {
		return
	}

	// Create a new manager.
	err = waddrmgr.Create(mgrNamespace, seed, pubPassphrase,
		privPassphrase, &chaincfg.MainNetParams, fastScrypt)
	if err != nil {
		t.Errorf("Create: unexpected error: %v", err)
		return
	}
	mgr, err := waddrmgr.Open(mgrNamespace, pubPassphrase,
		&chaincfg.MainNetParams, nil)
	if err != nil {
		t.Errorf("Open: unexpected error: %v", err)
		return
	}

	// NOTE: Not using deferred close here since part of the tests is
	// explicitly closing the manager and then opening the existing one.

	// Attempt to create the manager again to ensure the expected error is
	// returned.
	err = waddrmgr.Create(mgrNamespace, seed, pubPassphrase,
		privPassphrase, &chaincfg.MainNetParams, fastScrypt)
	if !checkManagerError(t, "Create existing", err, waddrmgr.ErrAlreadyExists) {
		mgr.Close()
		return
	}

	// Run all of the manager API tests in create mode and close the
	// manager after they've completed
	testManagerAPI(&testContext{
		t:            t,
		db:           db,
		manager:      mgr,
		account:      0,
		create:       true,
		watchingOnly: false,
	})
	mgr.Close()

	// Ensure the expected error is returned if the latest manager version
	// constant is bumped without writing code to actually do the upgrade.
	*waddrmgr.TstLatestMgrVersion++
	_, err = waddrmgr.Open(mgrNamespace, pubPassphrase,
		&chaincfg.MainNetParams, nil)
	if !checkManagerError(t, "Upgrade needed", err, waddrmgr.ErrUpgrade) {
		return
	}
	*waddrmgr.TstLatestMgrVersion--

	// Open the manager and run all the tests again in open mode which
	// avoids reinserting new addresses like the create mode tests do.
	mgr, err = waddrmgr.Open(mgrNamespace, pubPassphrase,
		&chaincfg.MainNetParams, nil)
	if err != nil {
		t.Errorf("Open: unexpected error: %v", err)
		return
	}
	defer mgr.Close()

	tc := &testContext{
		t:            t,
		db:           db,
		manager:      mgr,
		account:      0,
		create:       false,
		watchingOnly: false,
	}
	testManagerAPI(tc)

	// Now that the address manager has been tested in both the newly
	// created and opened modes, test a watching-only version.
	testWatchingOnly(tc)

	// Ensure that the manager sync state functionality works as expected.
	testSync(tc)

	// Unlock the manager so it can be closed with it unlocked to ensure
	// it works without issue.
	if err := mgr.Unlock(privPassphrase); err != nil {
		t.Errorf("Unlock: unexpected error: %v", err)
	}
}

// TestEncryptDecryptErrors ensures that errors which occur while encrypting and
// decrypting data return the expected errors.
func TestEncryptDecryptErrors(t *testing.T) {
	teardown, mgr := setupManager(t)
	defer teardown()

	invalidKeyType := waddrmgr.CryptoKeyType(0xff)
	if _, err := mgr.Encrypt(invalidKeyType, []byte{}); err == nil {
		t.Fatalf("Encrypt accepted an invalid key type!")
	}

	if _, err := mgr.Decrypt(invalidKeyType, []byte{}); err == nil {
		t.Fatalf("Encrypt accepted an invalid key type!")
	}

	if !mgr.IsLocked() {
		t.Fatal("Manager should be locked at this point.")
	}

	var err error
	// Now the mgr is locked and encrypting/decrypting with private
	// keys should fail.
	_, err = mgr.Encrypt(waddrmgr.CKTPrivate, []byte{})
	checkManagerError(t, "encryption with private key fails when manager is locked",
		err, waddrmgr.ErrLocked)

	_, err = mgr.Decrypt(waddrmgr.CKTPrivate, []byte{})
	checkManagerError(t, "decryption with private key fails when manager is locked",
		err, waddrmgr.ErrLocked)

	// Unlock the manager for these tests
	if err = mgr.Unlock(privPassphrase); err != nil {
		t.Fatal("Attempted to unlock the manager, but failed:", err)
	}

	// Make sure to cover the ErrCrypto error path in Encrypt.
	waddrmgr.TstRunWithFailingCryptoKeyPriv(mgr, func() {
		_, err = mgr.Encrypt(waddrmgr.CKTPrivate, []byte{})
	})
	checkManagerError(t, "failed encryption", err, waddrmgr.ErrCrypto)

	// Make sure to cover the ErrCrypto error path in Decrypt.
	waddrmgr.TstRunWithFailingCryptoKeyPriv(mgr, func() {
		_, err = mgr.Decrypt(waddrmgr.CKTPrivate, []byte{})
	})
	checkManagerError(t, "failed decryption", err, waddrmgr.ErrCrypto)
}

// TestEncryptDecrypt ensures that encrypting and decrypting data with the
// the various crypto key types works as expected.
func TestEncryptDecrypt(t *testing.T) {
	teardown, mgr := setupManager(t)
	defer teardown()

	plainText := []byte("this is a plaintext")

	// Make sure address manager is unlocked
	if err := mgr.Unlock(privPassphrase); err != nil {
		t.Fatal("Attempted to unlock the manager, but failed:", err)
	}

	keyTypes := []waddrmgr.CryptoKeyType{
		waddrmgr.CKTPublic,
		waddrmgr.CKTPrivate,
		waddrmgr.CKTScript,
	}

	for _, keyType := range keyTypes {
		cipherText, err := mgr.Encrypt(keyType, plainText)
		if err != nil {
			t.Fatalf("Failed to encrypt plaintext: %v", err)
		}

		decryptedCipherText, err := mgr.Decrypt(keyType, cipherText)
		if err != nil {
			t.Fatalf("Failed to decrypt plaintext: %v", err)
		}

		if !reflect.DeepEqual(decryptedCipherText, plainText) {
			t.Fatal("Got:", decryptedCipherText, ", want:", plainText)
		}
	}
}
