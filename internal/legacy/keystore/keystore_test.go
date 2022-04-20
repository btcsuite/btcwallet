// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package keystore

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/davecgh/go-spew/spew"
)

const dummyDir = ""

var tstNetParams = &chaincfg.MainNetParams

func makeBS(height int32) *BlockStamp {
	return &BlockStamp{
		Hash:   new(chainhash.Hash),
		Height: height,
	}
}

func TestBtcAddressSerializer(t *testing.T) {
	fakeWallet := &Store{net: (*netParams)(tstNetParams)}
	kdfp := &kdfParameters{
		mem:   1024,
		nIter: 5,
	}
	if _, err := rand.Read(kdfp.salt[:]); err != nil {
		t.Error(err.Error())
		return
	}
	key := kdf([]byte("banana"), kdfp)
	privKey := make([]byte, 32)
	if _, err := rand.Read(privKey); err != nil {
		t.Error(err.Error())
		return
	}
	addr, err := newBtcAddress(fakeWallet, privKey, nil,
		makeBS(0), true)
	if err != nil {
		t.Error(err.Error())
		return
	}
	err = addr.encrypt(key)
	if err != nil {
		t.Error(err.Error())
		return
	}

	buf := new(bytes.Buffer)

	if _, err := addr.WriteTo(buf); err != nil {
		t.Error(err.Error())
		return
	}

	var readAddr btcAddress
	readAddr.store = fakeWallet
	_, err = readAddr.ReadFrom(buf)
	if err != nil {
		t.Error(err.Error())
		return
	}

	if _, err = readAddr.unlock(key); err != nil {
		t.Error(err.Error())
		return
	}

	if !reflect.DeepEqual(addr, &readAddr) {
		t.Error("Original and read btcAddress differ.")
	}
}

func TestScriptAddressSerializer(t *testing.T) {
	fakeWallet := &Store{net: (*netParams)(tstNetParams)}
	script := []byte{txscript.OP_TRUE, txscript.OP_DUP,
		txscript.OP_DROP}
	addr, err := newScriptAddress(fakeWallet, script, makeBS(0))
	if err != nil {
		t.Error(err.Error())
		return
	}

	buf := new(bytes.Buffer)

	if _, err := addr.WriteTo(buf); err != nil {
		t.Error(err.Error())
		return
	}

	var readAddr scriptAddress
	readAddr.store = fakeWallet
	_, err = readAddr.ReadFrom(buf)
	if err != nil {
		t.Error(err.Error())
		return
	}

	if !reflect.DeepEqual(addr, &readAddr) {
		t.Error("Original and read btcAddress differ.")
	}
}

func TestWalletCreationSerialization(t *testing.T) {
	createdAt := makeBS(0)
	w1, err := New(dummyDir, "A wallet for testing.",
		[]byte("banana"), tstNetParams, createdAt)
	if err != nil {
		t.Error("Error creating new wallet: " + err.Error())
		return
	}

	buf := new(bytes.Buffer)

	if _, err := w1.WriteTo(buf); err != nil {
		t.Error("Error writing new wallet: " + err.Error())
		return
	}

	w2 := new(Store)
	_, err = w2.ReadFrom(buf)
	if err != nil {
		t.Error("Error reading newly written wallet: " + err.Error())
		return
	}

	w1.Lock()
	w2.Lock()

	if err = w1.Unlock([]byte("banana")); err != nil {
		t.Error("Decrypting original wallet failed: " + err.Error())
		return
	}

	if err = w2.Unlock([]byte("banana")); err != nil {
		t.Error("Decrypting newly read wallet failed: " + err.Error())
		return
	}

	//	if !reflect.DeepEqual(w1, w2) {
	//		t.Error("Created and read-in wallets do not match.")
	//		spew.Dump(w1, w2)
	//		return
	//	}
}

func TestChaining(t *testing.T) {
	tests := []struct {
		name                       string
		cc                         []byte
		origPrivateKey             []byte
		nextPrivateKeyUncompressed []byte
		nextPrivateKeyCompressed   []byte
		nextPublicKeyUncompressed  []byte
		nextPublicKeyCompressed    []byte
	}{
		{
			name:           "chaintest 1",
			cc:             []byte("3318959fff419ab8b556facb3c429a86"),
			origPrivateKey: []byte("5ffc975976eaaa1f7b179f384ebbc053"),
			nextPrivateKeyUncompressed: []byte{
				0xd3, 0xfe, 0x2e, 0x96, 0x44, 0x12, 0x2d, 0xaa,
				0x80, 0x8e, 0x36, 0x17, 0xb5, 0x9f, 0x8c, 0xd2,
				0x72, 0x8c, 0xaf, 0xf1, 0xdb, 0xd6, 0x4a, 0x92,
				0xd7, 0xc7, 0xee, 0x2b, 0x56, 0x34, 0xe2, 0x87,
			},
			nextPrivateKeyCompressed: []byte{
				0x08, 0x56, 0x7a, 0x1b, 0x89, 0x56, 0x2e, 0xfa,
				0xb4, 0x02, 0x59, 0x69, 0x10, 0xc3, 0x60, 0x1f,
				0x34, 0xf0, 0x55, 0x02, 0x8a, 0xbf, 0x37, 0xf5,
				0x22, 0x80, 0x9f, 0xd2, 0xe5, 0x42, 0x5b, 0x2d,
			},
			nextPublicKeyUncompressed: []byte{
				0x04, 0xdd, 0x70, 0x31, 0xa5, 0xf9, 0x06, 0x70,
				0xd3, 0x9a, 0x24, 0x5b, 0xd5, 0x73, 0xdd, 0xb6,
				0x15, 0x81, 0x0b, 0x78, 0x19, 0xbc, 0xc8, 0x26,
				0xc9, 0x16, 0x86, 0x73, 0xae, 0xe4, 0xc0, 0xed,
				0x39, 0x81, 0xb4, 0x86, 0x2d, 0x19, 0x8c, 0x67,
				0x9c, 0x93, 0x99, 0xf6, 0xd2, 0x3f, 0xd1, 0x53,
				0x9e, 0xed, 0xbd, 0x07, 0xd6, 0x4f, 0xa9, 0x81,
				0x61, 0x85, 0x46, 0x84, 0xb1, 0xa0, 0xed, 0xbc,
				0xa7,
			},
			nextPublicKeyCompressed: []byte{
				0x02, 0x2c, 0x48, 0x73, 0x37, 0x35, 0x74, 0x7f,
				0x05, 0x58, 0xc1, 0x4e, 0x0d, 0x18, 0xc2, 0xbf,
				0xcc, 0x83, 0xa2, 0x4d, 0x64, 0xab, 0xba, 0xea,
				0xeb, 0x4c, 0xcd, 0x4c, 0x0c, 0x21, 0xc4, 0x30,
				0x0f,
			},
		},
	}

	for _, test := range tests {
		// Create both uncompressed and compressed public keys for original
		// private key.
		origPubUncompressed := pubkeyFromPrivkey(test.origPrivateKey, false)
		origPubCompressed := pubkeyFromPrivkey(test.origPrivateKey, true)

		// Create next chained private keys, chained from both the uncompressed
		// and compressed pubkeys.
		nextPrivUncompressed, err := chainedPrivKey(test.origPrivateKey,
			origPubUncompressed, test.cc)
		if err != nil {
			t.Errorf("%s: Uncompressed chainedPrivKey failed: %v", test.name, err)
			return
		}
		nextPrivCompressed, err := chainedPrivKey(test.origPrivateKey,
			origPubCompressed, test.cc)
		if err != nil {
			t.Errorf("%s: Compressed chainedPrivKey failed: %v", test.name, err)
			return
		}

		// Verify that the new private keys match the expected values
		// in the test case.
		if !bytes.Equal(nextPrivUncompressed, test.nextPrivateKeyUncompressed) {
			t.Errorf("%s: Next private key (from uncompressed pubkey) does not match expected.\nGot: %s\nExpected: %s",
				test.name, spew.Sdump(nextPrivUncompressed), spew.Sdump(test.nextPrivateKeyUncompressed))
			return
		}
		if !bytes.Equal(nextPrivCompressed, test.nextPrivateKeyCompressed) {
			t.Errorf("%s: Next private key (from compressed pubkey) does not match expected.\nGot: %s\nExpected: %s",
				test.name, spew.Sdump(nextPrivCompressed), spew.Sdump(test.nextPrivateKeyCompressed))
			return
		}

		// Create the next pubkeys generated from the next private keys.
		nextPubUncompressedFromPriv := pubkeyFromPrivkey(nextPrivUncompressed, false)
		nextPubCompressedFromPriv := pubkeyFromPrivkey(nextPrivCompressed, true)

		// Create the next pubkeys by chaining directly off the original
		// pubkeys (without using the original's private key).
		nextPubUncompressedFromPub, err := chainedPubKey(origPubUncompressed, test.cc)
		if err != nil {
			t.Errorf("%s: Uncompressed chainedPubKey failed: %v", test.name, err)
			return
		}
		nextPubCompressedFromPub, err := chainedPubKey(origPubCompressed, test.cc)
		if err != nil {
			t.Errorf("%s: Compressed chainedPubKey failed: %v", test.name, err)
			return
		}

		// Public keys (used to generate the bitcoin address) MUST match.
		if !bytes.Equal(nextPubUncompressedFromPriv, nextPubUncompressedFromPub) {
			t.Errorf("%s: Uncompressed public keys do not match.", test.name)
		}
		if !bytes.Equal(nextPubCompressedFromPriv, nextPubCompressedFromPub) {
			t.Errorf("%s: Compressed public keys do not match.", test.name)
		}

		// Verify that all generated public keys match the expected
		// values in the test case.
		if !bytes.Equal(nextPubUncompressedFromPub, test.nextPublicKeyUncompressed) {
			t.Errorf("%s: Next uncompressed public keys do not match expected value.\nGot: %s\nExpected: %s",
				test.name, spew.Sdump(nextPubUncompressedFromPub), spew.Sdump(test.nextPublicKeyUncompressed))
			return
		}
		if !bytes.Equal(nextPubCompressedFromPub, test.nextPublicKeyCompressed) {
			t.Errorf("%s: Next compressed public keys do not match expected value.\nGot: %s\nExpected: %s",
				test.name, spew.Sdump(nextPubCompressedFromPub), spew.Sdump(test.nextPublicKeyCompressed))
			return
		}

		// Sign data with the next private keys and verify signature with
		// the next pubkeys.
		data := "String to sign."
		privkeyUncompressed, _ := btcec.PrivKeyFromBytes(nextPrivUncompressed)
		privkeyCompressed, _ := btcec.PrivKeyFromBytes(nextPrivCompressed)
		sig := ecdsa.Sign(privkeyUncompressed, []byte(data))
		ok := sig.Verify([]byte(data), privkeyUncompressed.PubKey())
		if !ok {
			t.Errorf("%s: btcec signature verification failed for next keypair (chained from uncompressed pubkey).",
				test.name)
			return
		}
		sig = ecdsa.Sign(privkeyCompressed, []byte(data))
		ok = sig.Verify([]byte(data), privkeyCompressed.PubKey())
		if !ok {
			t.Errorf("%s: btcec signature verification failed for next keypair (chained from compressed pubkey).",
				test.name)
			return
		}
	}
}

func TestWalletPubkeyChaining(t *testing.T) {
	w, err := New(dummyDir, "A wallet for testing.",
		[]byte("banana"), tstNetParams, makeBS(0))
	if err != nil {
		t.Error("Error creating new wallet: " + err.Error())
		return
	}
	if !w.IsLocked() {
		t.Error("New wallet is not locked.")
	}

	// Get next chained address.  The wallet is locked, so this will chain
	// off the last pubkey, not privkey.
	addrWithoutPrivkey, err := w.NextChainedAddress(makeBS(0))
	if err != nil {
		t.Errorf("Failed to extend address chain from pubkey: %v", err)
		return
	}

	// Lookup address info.  This should succeed even without the private
	// key available.
	info, err := w.Address(addrWithoutPrivkey)
	if err != nil {
		t.Errorf("Failed to get info about address without private key: %v", err)
		return
	}

	pkinfo := info.(PubKeyAddress)
	// sanity checks
	if !info.Compressed() {
		t.Errorf("Pubkey should be compressed.")
		return
	}
	if info.Imported() {
		t.Errorf("Should not be marked as imported.")
		return
	}

	pka := info.(PubKeyAddress)

	// Try to lookup it's private key.  This should fail.
	_, err = pka.PrivKey()
	if err == nil {
		t.Errorf("Incorrectly returned nil error for looking up private key for address without one saved.")
		return
	}

	// Deserialize w and serialize into a new wallet.  The rest of the checks
	// in this test test against both a fresh, as well as an "opened and closed"
	// wallet with the missing private key.
	serializedWallet := new(bytes.Buffer)
	_, err = w.WriteTo(serializedWallet)
	if err != nil {
		t.Errorf("Error writing wallet with missing private key: %v", err)
		return
	}
	w2 := new(Store)
	_, err = w2.ReadFrom(serializedWallet)
	if err != nil {
		t.Errorf("Error reading wallet with missing private key: %v", err)
		return
	}

	// Unlock wallet.  This should trigger creating the private key for
	// the address.
	if err = w.Unlock([]byte("banana")); err != nil {
		t.Errorf("Can't unlock original wallet: %v", err)
		return
	}
	if err = w2.Unlock([]byte("banana")); err != nil {
		t.Errorf("Can't unlock re-read wallet: %v", err)
		return
	}

	// Same address, better variable name.
	addrWithPrivKey := addrWithoutPrivkey

	// Try a private key lookup again.  The private key should now be available.
	key1, err := pka.PrivKey()
	if err != nil {
		t.Errorf("Private key for original wallet was not created! %v", err)
		return
	}

	info2, err := w.Address(addrWithPrivKey)
	if err != nil {
		t.Errorf("no address in re-read wallet")
	}
	pka2 := info2.(PubKeyAddress)
	key2, err := pka2.PrivKey()
	if err != nil {
		t.Errorf("Private key for re-read wallet was not created! %v", err)
		return
	}

	// Keys returned by both wallets must match.
	if !reflect.DeepEqual(key1, key2) {
		t.Errorf("Private keys for address originally created without one mismtach between original and re-read wallet.")
		return
	}

	// Sign some data with the private key, then verify signature with the pubkey.
	hash := []byte("hash to sign")
	sig := ecdsa.Sign(key1, hash)
	pubKey := pkinfo.PubKey()
	ok := sig.Verify(hash, pubKey)
	if !ok {
		t.Errorf("btcec signature verification failed; address's pubkey mismatches the privkey.")
		return
	}

	nextAddr, err := w.NextChainedAddress(makeBS(0))
	if err != nil {
		t.Errorf("Unable to create next address after finding the privkey: %v", err)
		return
	}

	nextInfo, err := w.Address(nextAddr)
	if err != nil {
		t.Errorf("Couldn't get info about the next address in the chain: %v", err)
		return
	}
	nextPkInfo := nextInfo.(PubKeyAddress)
	nextKey, err := nextPkInfo.PrivKey()
	if err != nil {
		t.Errorf("Couldn't get private key for the next address in the chain: %v", err)
		return
	}

	// Do a signature check here as well, this time for the next
	// address after the one made without the private key.
	sig = ecdsa.Sign(nextKey, hash)
	pubKey = nextPkInfo.PubKey()
	ok = sig.Verify(hash, pubKey)
	if !ok {
		t.Errorf("btcec signature verification failed; next address's keypair does not match.")
		return
	}

	// Check that the serialized wallet correctly unmarked the 'needs private
	// keys later' flag.
	buf := new(bytes.Buffer)
	w2.WriteTo(buf)
	w2.ReadFrom(buf)
	err = w2.Unlock([]byte("banana"))
	if err != nil {
		t.Errorf("Unlock after serialize/deserialize failed: %v", err)
		return
	}
}

func TestWatchingWalletExport(t *testing.T) {
	createdAt := makeBS(0)
	w, err := New(dummyDir, "A wallet for testing.",
		[]byte("banana"), tstNetParams, createdAt)
	if err != nil {
		t.Error("Error creating new wallet: " + err.Error())
		return
	}

	// Maintain a set of the active addresses in the wallet.
	activeAddrs := make(map[addressKey]struct{})

	// Add root address.
	activeAddrs[getAddressKey(w.LastChainedAddress())] = struct{}{}

	// Create watching wallet from w.
	ww, err := w.ExportWatchingWallet()
	if err != nil {
		t.Errorf("Could not create watching wallet: %v", err)
		return
	}

	// Verify correctness of wallet flags.
	if ww.flags.useEncryption {
		t.Errorf("Watching wallet marked as using encryption (but nothing to encrypt).")
		return
	}
	if !ww.flags.watchingOnly {
		t.Errorf("Wallet should be watching-only but is not marked so.")
		return
	}

	// Verify that all flags are set as expected.
	if ww.keyGenerator.flags.encrypted {
		t.Errorf("Watching root address should not be encrypted (nothing to encrypt)")
		return
	}
	if ww.keyGenerator.flags.hasPrivKey {
		t.Errorf("Watching root address marked as having a private key.")
		return
	}
	if !ww.keyGenerator.flags.hasPubKey {
		t.Errorf("Watching root address marked as missing a public key.")
		return
	}
	if ww.keyGenerator.flags.createPrivKeyNextUnlock {
		t.Errorf("Watching root address marked as needing a private key to be generated later.")
		return
	}
	for apkh, waddr := range ww.addrMap {
		switch addr := waddr.(type) {
		case *btcAddress:
			if addr.flags.encrypted {
				t.Errorf("Chained address should not be encrypted (nothing to encrypt)")
				return
			}
			if addr.flags.hasPrivKey {
				t.Errorf("Chained address marked as having a private key.")
				return
			}
			if !addr.flags.hasPubKey {
				t.Errorf("Chained address marked as missing a public key.")
				return
			}
			if addr.flags.createPrivKeyNextUnlock {
				t.Errorf("Chained address marked as needing a private key to be generated later.")
				return
			}
		case *scriptAddress:
			t.Errorf("Chained address was a script!")
			return
		default:
			t.Errorf("Chained address unknown type!")
			return
		}

		if _, ok := activeAddrs[apkh]; !ok {
			t.Errorf("Address from watching wallet not found in original wallet.")
			return
		}
		delete(activeAddrs, apkh)
	}
	if len(activeAddrs) != 0 {
		t.Errorf("%v address(es) were not exported to watching wallet.", len(activeAddrs))
		return
	}

	// Check that the new addresses created by each wallet match.  The
	// original wallet is unlocked so addresses are chained with privkeys.
	if err := w.Unlock([]byte("banana")); err != nil {
		t.Errorf("Unlocking original wallet failed: %v", err)
	}

	// Test that ExtendActiveAddresses for the watching wallet match
	// manually requested addresses of the original wallet.
	var newAddrs []btcutil.Address
	for i := 0; i < 10; i++ {
		addr, err := w.NextChainedAddress(createdAt)
		if err != nil {
			t.Errorf("Cannot get next chained address for original wallet: %v", err)
			return
		}
		newAddrs = append(newAddrs, addr)
	}
	newWWAddrs, err := ww.ExtendActiveAddresses(10)
	if err != nil {
		t.Errorf("Cannot extend active addresses for watching wallet: %v", err)
		return
	}
	for i := range newAddrs {
		if newAddrs[i].EncodeAddress() != newWWAddrs[i].EncodeAddress() {
			t.Errorf("Extended active addresses do not match manually requested addresses.")
			return
		}
	}

	// Test ExtendActiveAddresses for the original wallet after manually
	// requesting addresses for the watching wallet.
	newWWAddrs = nil
	for i := 0; i < 10; i++ {
		addr, err := ww.NextChainedAddress(createdAt)
		if err != nil {
			t.Errorf("Cannot get next chained address for watching wallet: %v", err)
			return
		}
		newWWAddrs = append(newWWAddrs, addr)
	}
	newAddrs, err = w.ExtendActiveAddresses(10)
	if err != nil {
		t.Errorf("Cannot extend active addresses for original wallet: %v", err)
		return
	}
	for i := range newAddrs {
		if newAddrs[i].EncodeAddress() != newWWAddrs[i].EncodeAddress() {
			t.Errorf("Extended active addresses do not match manually requested addresses.")
			return
		}
	}

	// Test (de)serialization of watching wallet.
	buf := new(bytes.Buffer)
	_, err = ww.WriteTo(buf)
	if err != nil {
		t.Errorf("Cannot write watching wallet: %v", err)
		return
	}
	ww2 := new(Store)
	_, err = ww2.ReadFrom(buf)
	if err != nil {
		t.Errorf("Cannot read watching wallet: %v", err)
		return
	}

	// Check that (de)serialized watching wallet matches the exported wallet.
	if !reflect.DeepEqual(ww, ww2) {
		t.Error("Exported and read-in watching wallets do not match.")
		return
	}

	// Verify that nonsensical functions fail with correct error.
	if err := ww.Lock(); err != ErrWatchingOnly {
		t.Errorf("Nonsensical func Lock returned no or incorrect error: %v", err)
		return
	}
	if err := ww.Unlock([]byte("banana")); err != ErrWatchingOnly {
		t.Errorf("Nonsensical func Unlock returned no or incorrect error: %v", err)
		return
	}
	generator, err := ww.Address(w.keyGenerator.Address())
	if err != nil {
		t.Errorf("generator isnt' present in wallet")
	}
	gpk := generator.(PubKeyAddress)
	if _, err := gpk.PrivKey(); err != ErrWatchingOnly {
		t.Errorf("Nonsensical func AddressKey returned no or incorrect error: %v", err)
		return
	}
	if _, err := ww.ExportWatchingWallet(); err != ErrWatchingOnly {
		t.Errorf("Nonsensical func ExportWatchingWallet returned no or incorrect error: %v", err)
		return
	}
	pk, _ := btcec.PrivKeyFromBytes(make([]byte, 32))
	wif, err := btcutil.NewWIF(pk, tstNetParams, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ww.ImportPrivateKey(wif, createdAt); err != ErrWatchingOnly {
		t.Errorf("Nonsensical func ImportPrivateKey returned no or incorrect error: %v", err)
		return
	}
}

func TestImportPrivateKey(t *testing.T) {
	createHeight := int32(100)
	createdAt := makeBS(createHeight)
	w, err := New(dummyDir, "A wallet for testing.",
		[]byte("banana"), tstNetParams, createdAt)
	if err != nil {
		t.Error("Error creating new wallet: " + err.Error())
		return
	}

	if err = w.Unlock([]byte("banana")); err != nil {
		t.Errorf("Can't unlock original wallet: %v", err)
		return
	}

	pk, err := btcec.NewPrivateKey()
	if err != nil {
		t.Error("Error generating private key: " + err.Error())
		return
	}

	// verify that the entire wallet's sync height matches the
	// expected createHeight.
	if _, h := w.SyncedTo(); h != createHeight {
		t.Errorf("Initial sync height %v does not match expected %v.", h, createHeight)
		return
	}

	// import priv key
	wif, err := btcutil.NewWIF(pk, tstNetParams, false)
	if err != nil {
		t.Fatal(err)
	}
	importHeight := int32(50)
	importedAt := makeBS(importHeight)
	address, err := w.ImportPrivateKey(wif, importedAt)
	if err != nil {
		t.Error("importing private key: " + err.Error())
		return
	}

	addr, err := w.Address(address)
	if err != nil {
		t.Error("privkey just imported missing: " + err.Error())
		return
	}
	pka := addr.(PubKeyAddress)

	// lookup address
	pk2, err := pka.PrivKey()
	if err != nil {
		t.Error("error looking up key: " + err.Error())
	}

	if !reflect.DeepEqual(pk, pk2) {
		t.Error("original and looked-up private keys do not match.")
		return
	}

	// verify that the sync height now match the (smaller) import height.
	if _, h := w.SyncedTo(); h != importHeight {
		t.Errorf("After import sync height %v does not match expected %v.", h, importHeight)
		return
	}

	// serialise and deseralise and check still there.

	// Test (de)serialization of wallet.
	buf := new(bytes.Buffer)
	_, err = w.WriteTo(buf)
	if err != nil {
		t.Errorf("Cannot write wallet: %v", err)
		return
	}
	w2 := new(Store)
	_, err = w2.ReadFrom(buf)
	if err != nil {
		t.Errorf("Cannot read wallet: %v", err)
		return
	}

	// Verify that the  sync height match expected after the reserialization.
	if _, h := w2.SyncedTo(); h != importHeight {
		t.Errorf("After reserialization sync height %v does not match expected %v.", h, importHeight)
		return
	}

	// Mark imported address as partially synced with a block somewhere in
	// between the import height and the chain height.
	partialHeight := (createHeight-importHeight)/2 + importHeight
	if err := w2.SetSyncStatus(address, PartialSync(partialHeight)); err != nil {
		t.Errorf("Cannot mark address partially synced: %v", err)
		return
	}
	if _, h := w2.SyncedTo(); h != partialHeight {
		t.Errorf("After address partial sync, sync height %v does not match expected %v.", h, partialHeight)
		return
	}

	// Test serialization with the partial sync.
	buf.Reset()
	_, err = w2.WriteTo(buf)
	if err != nil {
		t.Errorf("Cannot write wallet: %v", err)
		return
	}
	w3 := new(Store)
	_, err = w3.ReadFrom(buf)
	if err != nil {
		t.Errorf("Cannot read wallet: %v", err)
		return
	}

	// Test correct partial height after serialization.
	if _, h := w3.SyncedTo(); h != partialHeight {
		t.Errorf("After address partial sync and reserialization, sync height %v does not match expected %v.",
			h, partialHeight)
		return
	}

	// Mark imported address as not synced at all, and verify sync height is now
	// the import height.
	if err := w3.SetSyncStatus(address, Unsynced(0)); err != nil {
		t.Errorf("Cannot mark address synced: %v", err)
		return
	}
	if _, h := w3.SyncedTo(); h != importHeight {
		t.Errorf("After address unsync, sync height %v does not match expected %v.", h, importHeight)
		return
	}

	// Mark imported address as synced with the recently-seen blocks, and verify
	// that the sync height now equals the most recent block (the one at wallet
	// creation).
	if err := w3.SetSyncStatus(address, FullSync{}); err != nil {
		t.Errorf("Cannot mark address synced: %v", err)
		return
	}
	if _, h := w3.SyncedTo(); h != createHeight {
		t.Errorf("After address sync, sync height %v does not match expected %v.", h, createHeight)
		return
	}

	if err = w3.Unlock([]byte("banana")); err != nil {
		t.Errorf("Can't unlock deserialised wallet: %v", err)
		return
	}

	addr3, err := w3.Address(address)
	if err != nil {
		t.Error("privkey in deserialised wallet missing : " +
			err.Error())
		return
	}
	pka3 := addr3.(PubKeyAddress)

	// lookup address
	pk2, err = pka3.PrivKey()
	if err != nil {
		t.Error("error looking up key in deserialized wallet: " + err.Error())
	}

	if !reflect.DeepEqual(pk, pk2) {
		t.Error("original and deserialized private keys do not match.")
		return
	}

}

func TestImportScript(t *testing.T) {
	createHeight := int32(100)
	createdAt := makeBS(createHeight)
	w, err := New(dummyDir, "A wallet for testing.",
		[]byte("banana"), tstNetParams, createdAt)
	if err != nil {
		t.Error("Error creating new wallet: " + err.Error())
		return
	}

	if err = w.Unlock([]byte("banana")); err != nil {
		t.Errorf("Can't unlock original wallet: %v", err)
		return
	}

	// verify that the entire wallet's sync height matches the
	// expected createHeight.
	if _, h := w.SyncedTo(); h != createHeight {
		t.Errorf("Initial sync height %v does not match expected %v.", h, createHeight)
		return
	}

	script := []byte{txscript.OP_TRUE, txscript.OP_DUP,
		txscript.OP_DROP}
	importHeight := int32(50)
	stamp := makeBS(importHeight)
	address, err := w.ImportScript(script, stamp)
	if err != nil {
		t.Error("error importing script: " + err.Error())
		return
	}

	// lookup address
	ainfo, err := w.Address(address)
	if err != nil {
		t.Error("error looking up script: " + err.Error())
	}

	sinfo := ainfo.(ScriptAddress)

	if !bytes.Equal(script, sinfo.Script()) {
		t.Error("original and looked-up script do not match.")
		return
	}

	if sinfo.ScriptClass() != txscript.NonStandardTy {
		t.Error("script type incorrect.")
		return
	}

	if sinfo.RequiredSigs() != 0 {
		t.Error("required sigs funny number")
		return
	}

	if len(sinfo.Addresses()) != 0 {
		t.Error("addresses in bogus script.")
		return
	}

	if sinfo.Address().EncodeAddress() != address.EncodeAddress() {
		t.Error("script address doesn't match entry.")
		return
	}

	if string(sinfo.Address().ScriptAddress()) != sinfo.AddrHash() {
		t.Error("script hash doesn't match address.")
		return
	}

	if sinfo.FirstBlock() != importHeight {
		t.Error("funny first block")
		return
	}

	if !sinfo.Imported() {
		t.Error("imported script info not imported.")
		return
	}

	if sinfo.Change() {
		t.Error("imported script is change.")
		return
	}

	if sinfo.Compressed() {
		t.Error("imported script is compressed.")
		return
	}

	// verify that the sync height now match the (smaller) import height.
	if _, h := w.SyncedTo(); h != importHeight {
		t.Errorf("After import sync height %v does not match expected %v.", h, importHeight)
		return
	}

	// Check that it's included along with the active payment addresses.
	found := false
	for _, wa := range w.SortedActiveAddresses() {
		if wa.Address() == address {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Imported script address was not returned with sorted active payment addresses.")
		return
	}
	if _, ok := w.ActiveAddresses()[address]; !ok {
		t.Errorf("Imported script address was not returned with unsorted active payment addresses.")
		return
	}

	// serialise and deseralise and check still there.

	// Test (de)serialization of wallet.
	buf := new(bytes.Buffer)
	_, err = w.WriteTo(buf)
	if err != nil {
		t.Errorf("Cannot write wallet: %v", err)
		return
	}
	w2 := new(Store)
	_, err = w2.ReadFrom(buf)
	if err != nil {
		t.Errorf("Cannot read wallet: %v", err)
		return
	}

	// Verify that the sync height matches expected after the reserialization.
	if _, h := w2.SyncedTo(); h != importHeight {
		t.Errorf("After reserialization sync height %v does not match expected %v.", h, importHeight)
		return
	}

	// lookup address
	ainfo2, err := w2.Address(address)
	if err != nil {
		t.Error("error looking up info in deserialized wallet: " + err.Error())
	}

	sinfo2 := ainfo2.(ScriptAddress)
	// Check all the same again. We can't use reflect.DeepEquals since
	// the internals have pointers back to the wallet struct.
	if sinfo2.Address().EncodeAddress() != address.EncodeAddress() {
		t.Error("script address doesn't match entry.")
		return
	}

	if string(sinfo2.Address().ScriptAddress()) != sinfo2.AddrHash() {
		t.Error("script hash doesn't match address.")
		return
	}

	if sinfo2.FirstBlock() != importHeight {
		t.Error("funny first block")
		return
	}

	if !sinfo2.Imported() {
		t.Error("imported script info not imported.")
		return
	}

	if sinfo2.Change() {
		t.Error("imported script is change.")
		return
	}

	if sinfo2.Compressed() {
		t.Error("imported script is compressed.")
		return
	}

	if !bytes.Equal(sinfo.Script(), sinfo2.Script()) {
		t.Errorf("original and serailised scriptinfo scripts "+
			"don't match %s != %s", spew.Sdump(sinfo.Script()),
			spew.Sdump(sinfo2.Script()))
	}

	if sinfo.ScriptClass() != sinfo2.ScriptClass() {
		t.Errorf("original and serailised scriptinfo class "+
			"don't match: %s != %s", sinfo.ScriptClass(),
			sinfo2.ScriptClass())
		return
	}

	if !reflect.DeepEqual(sinfo.Addresses(), sinfo2.Addresses()) {
		t.Errorf("original and serailised scriptinfo addresses "+
			"don't match (%s) != (%s)", spew.Sdump(sinfo.Addresses),
			spew.Sdump(sinfo2.Addresses()))
		return
	}

	if sinfo.RequiredSigs() != sinfo2.RequiredSigs() {
		t.Errorf("original and serailised scriptinfo requiredsigs "+
			"don't match %d != %d", sinfo.RequiredSigs(),
			sinfo2.RequiredSigs())
		return
	}

	// Check that it's included along with the active payment addresses.
	found = false
	for _, wa := range w.SortedActiveAddresses() {
		if wa.Address() == address {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("After reserialiation, imported script address was not returned with sorted " +
			"active payment addresses.")
		return
	}
	if _, ok := w.ActiveAddresses()[address]; !ok {
		t.Errorf("After reserialiation, imported script address was not returned with unsorted " +
			"active payment addresses.")
		return
	}

	// Mark imported address as partially synced with a block somewhere in
	// between the import height and the chain height.
	partialHeight := (createHeight-importHeight)/2 + importHeight
	if err := w2.SetSyncStatus(address, PartialSync(partialHeight)); err != nil {
		t.Errorf("Cannot mark address partially synced: %v", err)
		return
	}
	if _, h := w2.SyncedTo(); h != partialHeight {
		t.Errorf("After address partial sync, sync height %v does not match expected %v.", h, partialHeight)
		return
	}

	// Test serialization with the partial sync.
	buf.Reset()
	_, err = w2.WriteTo(buf)
	if err != nil {
		t.Errorf("Cannot write wallet: %v", err)
		return
	}
	w3 := new(Store)
	_, err = w3.ReadFrom(buf)
	if err != nil {
		t.Errorf("Cannot read wallet: %v", err)
		return
	}

	// Test correct partial height after serialization.
	if _, h := w3.SyncedTo(); h != partialHeight {
		t.Errorf("After address partial sync and reserialization, sync height %v does not match expected %v.",
			h, partialHeight)
		return
	}

	// Mark imported address as not synced at all, and verify sync height is now
	// the import height.
	if err := w3.SetSyncStatus(address, Unsynced(0)); err != nil {
		t.Errorf("Cannot mark address synced: %v", err)
		return
	}
	if _, h := w3.SyncedTo(); h != importHeight {
		t.Errorf("After address unsync, sync height %v does not match expected %v.", h, importHeight)
		return
	}

	// Mark imported address as synced with the recently-seen blocks, and verify
	// that the sync height now equals the most recent block (the one at wallet
	// creation).
	if err := w3.SetSyncStatus(address, FullSync{}); err != nil {
		t.Errorf("Cannot mark address synced: %v", err)
		return
	}
	if _, h := w3.SyncedTo(); h != createHeight {
		t.Errorf("After address sync, sync height %v does not match expected %v.", h, createHeight)
		return
	}

	if err = w3.Unlock([]byte("banana")); err != nil {
		t.Errorf("Can't unlock deserialised wallet: %v", err)
		return
	}
}

func TestChangePassphrase(t *testing.T) {
	createdAt := makeBS(0)
	w, err := New(dummyDir, "A wallet for testing.",
		[]byte("banana"), tstNetParams, createdAt)
	if err != nil {
		t.Error("Error creating new wallet: " + err.Error())
		return
	}

	// Changing the passphrase with a locked wallet must fail with ErrWalletLocked.
	if err := w.ChangePassphrase([]byte("potato")); err != ErrLocked {
		t.Errorf("Changing passphrase on a locked wallet did not fail correctly: %v", err)
		return
	}

	// Unlock wallet so the passphrase can be changed.
	if err := w.Unlock([]byte("banana")); err != nil {
		t.Errorf("Cannot unlock: %v", err)
		return
	}

	// Get root address and its private key.  This is compared to the private
	// key post passphrase change.
	rootAddr := w.LastChainedAddress()

	rootAddrInfo, err := w.Address(rootAddr)
	if err != nil {
		t.Error("can't find root address: " + err.Error())
		return
	}
	rapka := rootAddrInfo.(PubKeyAddress)

	rootPrivKey, err := rapka.PrivKey()
	if err != nil {
		t.Errorf("Cannot get root address' private key: %v", err)
		return
	}

	// Change passphrase.
	if err := w.ChangePassphrase([]byte("potato")); err != nil {
		t.Errorf("Changing passphrase failed: %v", err)
		return
	}

	// Wallet should still be unlocked.
	if w.IsLocked() {
		t.Errorf("Wallet should be unlocked after passphrase change.")
		return
	}

	// Lock it.
	if err := w.Lock(); err != nil {
		t.Errorf("Cannot lock wallet after passphrase change: %v", err)
		return
	}

	// Unlock with old passphrase.  This must fail with ErrWrongPassphrase.
	if err := w.Unlock([]byte("banana")); err != ErrWrongPassphrase {
		t.Errorf("Unlocking with old passphrases did not fail correctly: %v", err)
		return
	}

	// Unlock with new passphrase.  This must succeed.
	if err := w.Unlock([]byte("potato")); err != nil {
		t.Errorf("Unlocking with new passphrase failed: %v", err)
		return
	}

	// Get root address' private key again.
	rootAddrInfo2, err := w.Address(rootAddr)
	if err != nil {
		t.Error("can't find root address: " + err.Error())
		return
	}
	rapka2 := rootAddrInfo2.(PubKeyAddress)

	rootPrivKey2, err := rapka2.PrivKey()
	if err != nil {
		t.Errorf("Cannot get root address' private key after passphrase change: %v", err)
		return
	}

	// Private keys must match.
	if !reflect.DeepEqual(rootPrivKey, rootPrivKey2) {
		t.Errorf("Private keys before and after unlock differ.")
		return
	}
}
