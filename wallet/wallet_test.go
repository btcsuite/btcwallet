/*
 * Copyright (c) 2013, 2014 Conformal Systems LLC <info@conformal.com>
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

package wallet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"github.com/conformal/btcec"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
	"github.com/davecgh/go-spew/spew"
	"math/big"
	"os"
	"reflect"
	"testing"
)

var _ = spew.Dump

func TestBtcAddressSerializer(t *testing.T) {
	kdfp := &kdfParameters{
		mem:   1024,
		nIter: 5,
	}
	if _, err := rand.Read(kdfp.salt[:]); err != nil {
		t.Error(err.Error())
		return
	}
	key := Key([]byte("banana"), kdfp)
	privKey := make([]byte, 32)
	if _, err := rand.Read(privKey); err != nil {
		t.Error(err.Error())
		return
	}
	addr, err := newBtcAddress(privKey, nil, &BlockStamp{}, true)
	if err != nil {
		t.Error(err.Error())
		return
	}
	err = addr.encrypt(key)
	if err != nil {
		t.Error(err.Error())
		return
	}

	file, err := os.Create("btcaddress.bin")
	if err != nil {
		t.Error(err.Error())
		return
	}
	defer file.Close()

	if _, err := addr.WriteTo(file); err != nil {
		t.Error(err.Error())
		return
	}

	file.Seek(0, 0)

	var readAddr btcAddress
	_, err = readAddr.ReadFrom(file)
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

func TestWalletCreationSerialization(t *testing.T) {
	createdAt := &BlockStamp{}
	w1, err := NewWallet("banana wallet", "A wallet for testing.",
		[]byte("banana"), btcwire.MainNet, createdAt, 100)
	if err != nil {
		t.Error("Error creating new wallet: " + err.Error())
		return
	}

	file, err := os.Create("newwallet.bin")
	if err != nil {
		t.Error(err.Error())
		return
	}
	defer file.Close()

	if _, err := w1.WriteTo(file); err != nil {
		t.Error("Error writing new wallet: " + err.Error())
		return
	}

	file.Seek(0, 0)

	w2 := new(Wallet)
	_, err = w2.ReadFrom(file)
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

	if !reflect.DeepEqual(w1, w2) {
		t.Error("Created and read-in wallets do not match.")
		spew.Dump(w1, w2)
		return
	}
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
		nextPrivUncompressed, err := ChainedPrivKey(test.origPrivateKey,
			origPubUncompressed, test.cc)
		if err != nil {
			t.Errorf("%s: Uncompressed ChainedPrivKey failed: %v", test.name, err)
			return
		}
		nextPrivCompressed, err := ChainedPrivKey(test.origPrivateKey,
			origPubCompressed, test.cc)
		if err != nil {
			t.Errorf("%s: Compressed ChainedPrivKey failed: %v", test.name, err)
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
		nextPubUncompressedFromPub, err := ChainedPubKey(origPubUncompressed, test.cc)
		if err != nil {
			t.Errorf("%s: Uncompressed ChainedPubKey failed: %v", test.name, err)
			return
		}
		nextPubCompressedFromPub, err := ChainedPubKey(origPubCompressed, test.cc)
		if err != nil {
			t.Errorf("%s: Compressed ChainedPubKey failed: %v", test.name, err)
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
		pubkeyUncompressed, err := btcec.ParsePubKey(nextPubUncompressedFromPub, btcec.S256())
		if err != nil {
			t.Errorf("%s: Unable to parse next uncompressed pubkey: %v", test.name, err)
			return
		}
		pubkeyCompressed, err := btcec.ParsePubKey(nextPubCompressedFromPub, btcec.S256())
		if err != nil {
			t.Errorf("%s: Unable to parse next compressed pubkey: %v", test.name, err)
			return
		}
		privkeyUncompressed := &ecdsa.PrivateKey{
			PublicKey: *pubkeyUncompressed,
			D:         new(big.Int).SetBytes(nextPrivUncompressed),
		}
		privkeyCompressed := &ecdsa.PrivateKey{
			PublicKey: *pubkeyCompressed,
			D:         new(big.Int).SetBytes(nextPrivCompressed),
		}
		data := "String to sign."
		r, s, err := ecdsa.Sign(rand.Reader, privkeyUncompressed, []byte(data))
		if err != nil {
			t.Errorf("%s: Unable to sign data with next private key (chained from uncompressed pubkey): %v",
				test.name, err)
			return
		}
		ok := ecdsa.Verify(&privkeyUncompressed.PublicKey, []byte(data), r, s)
		if !ok {
			t.Errorf("%s: ecdsa verification failed for next keypair (chained from uncompressed pubkey).",
				test.name)
			return
		}
		r, s, err = ecdsa.Sign(rand.Reader, privkeyCompressed, []byte(data))
		if err != nil {
			t.Errorf("%s: Unable to sign data with next private key (chained from compressed pubkey): %v",
				test.name, err)
			return
		}
		ok = ecdsa.Verify(&privkeyCompressed.PublicKey, []byte(data), r, s)
		if !ok {
			t.Errorf("%s: ecdsa verification failed for next keypair (chained from compressed pubkey).",
				test.name)
			return
		}
	}
}

func TestWalletPubkeyChaining(t *testing.T) {
	// Set a reasonable keypool size that isn't too big nor too small for testing.
	const keypoolSize = 5

	w, err := NewWallet("banana wallet", "A wallet for testing.",
		[]byte("banana"), btcwire.MainNet, &BlockStamp{}, keypoolSize)
	if err != nil {
		t.Error("Error creating new wallet: " + err.Error())
		return
	}
	if !w.IsLocked() {
		t.Error("New wallet is not locked.")
	}

	// Wallet should have a total of 6 addresses, one for the root, plus 5 in
	// the keypool with their private keys set.  Ask for as many new addresses
	// as needed to deplete the pool.
	for i := 0; i < keypoolSize; i++ {
		_, err := w.NextChainedAddress(&BlockStamp{}, keypoolSize)
		if err != nil {
			t.Errorf("Error getting next address from keypool: %v", err)
			return
		}
	}

	// Get next chained address after depleting the keypool.  This will extend
	// the chain based on the last pubkey, not privkey.
	addrWithoutPrivkey, err := w.NextChainedAddress(&BlockStamp{}, keypoolSize)
	if err != nil {
		t.Errorf("Failed to extend address chain from pubkey: %v", err)
		return
	}

	// Lookup address info.  This should succeed even without the private
	// key available.
	info, err := w.AddressInfo(addrWithoutPrivkey)
	if err != nil {
		t.Errorf("Failed to get info about address without private key: %v", err)
		return
	}
	// sanity checks
	if !info.Compressed {
		t.Errorf("Pubkey should be compressed.")
		return
	}
	if info.Imported {
		t.Errorf("Should not be marked as imported.")
		return
	}

	// Try to lookup it's private key.  This should fail.
	_, err = w.AddressKey(addrWithoutPrivkey)
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
	w2 := new(Wallet)
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
	key1, err := w.AddressKey(addrWithPrivKey)
	if err != nil {
		t.Errorf("Private key for original wallet was not created! %v", err)
		return
	}
	key2, err := w2.AddressKey(addrWithPrivKey)
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
	r, s, err := ecdsa.Sign(rand.Reader, key1, hash)
	if err != nil {
		t.Errorf("Unable to sign hash with the created private key: %v", err)
		return
	}
	pubKeyStr, _ := hex.DecodeString(info.Pubkey)
	pubKey, err := btcec.ParsePubKey(pubKeyStr, btcec.S256())
	ok := ecdsa.Verify(pubKey, hash, r, s)
	if !ok {
		t.Errorf("ECDSA verification failed; address's pubkey mismatches the privkey.")
		return
	}

	// Test that normal keypool extension and address creation continues to
	// work.  With the wallet still unlocked, create a new address.  This
	// will cause the keypool to refill and return the first address from the
	// keypool.
	nextAddr, err := w.NextChainedAddress(&BlockStamp{}, keypoolSize)
	if err != nil {
		t.Errorf("Unable to create next address or refill keypool after finding the privkey: %v", err)
		return
	}

	nextInfo, err := w.AddressInfo(nextAddr)
	if err != nil {
		t.Errorf("Couldn't get info about the next address in the chain: %v", err)
		return
	}
	nextKey, err := w.AddressKey(nextAddr)
	if err != nil {
		t.Errorf("Couldn't get private key for the next address in the chain: %v", err)
		return
	}

	// Do an ECDSA signature check here as well, this time for the next
	// address after the one made without the private key.
	r, s, err = ecdsa.Sign(rand.Reader, nextKey, hash)
	if err != nil {
		t.Errorf("Unable to sign hash with the created private key: %v", err)
		return
	}
	pubKeyStr, _ = hex.DecodeString(nextInfo.Pubkey)
	pubKey, err = btcec.ParsePubKey(pubKeyStr, btcec.S256())
	ok = ecdsa.Verify(pubKey, hash, r, s)
	if !ok {
		t.Errorf("ECDSA verification failed; next address's keypair does not match.")
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
	const keypoolSize = 10
	createdAt := &BlockStamp{}
	w, err := NewWallet("banana wallet", "A wallet for testing.",
		[]byte("banana"), btcwire.MainNet, createdAt, keypoolSize)
	if err != nil {
		t.Error("Error creating new wallet: " + err.Error())
		return
	}

	// Maintain a set of the active addresses in the wallet.
	activeAddrs := make(map[btcutil.AddressPubKeyHash]struct{})

	// Add root address.
	activeAddrs[*w.LastChainedAddress()] = struct{}{}

	// Get as many new active addresses as necessary to deplete the keypool.
	// This is done as we will want to test that new addresses created by
	// the watching wallet do not pull from previous public keys in the
	// original keypool.
	for i := 0; i < keypoolSize; i++ {
		apkh, err := w.NextChainedAddress(createdAt, keypoolSize)
		if err != nil {
			t.Errorf("unable to get next address: %v", err)
			return
		}
		activeAddrs[*apkh] = struct{}{}
	}

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
	for apkh, addr := range ww.addrMap {
		if addr.flags.encrypted {
			t.Errorf("Chained address should not be encrypted (nothing to encrypt)")
			return
		}
		if ww.keyGenerator.flags.hasPrivKey {
			t.Errorf("Chained address marked as having a private key.")
			return
		}
		if !ww.keyGenerator.flags.hasPubKey {
			t.Errorf("Chained address marked as missing a public key.")
			return
		}
		if ww.keyGenerator.flags.createPrivKeyNextUnlock {
			t.Errorf("Chained address marked as needing a private key to be generated later.")
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
	// original wallet is unlocked so the keypool is refilled and chained
	// addresses use the previous' privkey, not pubkey.
	if err := w.Unlock([]byte("banana")); err != nil {
		t.Errorf("Unlocking original wallet failed: %v", err)
	}
	for i := 0; i < keypoolSize; i++ {
		addr, err := w.NextChainedAddress(createdAt, keypoolSize)
		if err != nil {
			t.Errorf("Cannot get next chained address for original wallet: %v", err)
			return
		}
		waddr, err := ww.NextChainedAddress(createdAt, keypoolSize)
		if err != nil {
			t.Errorf("Cannot get next chained address for watching wallet: %v", err)
			return
		}
		if addr.String() != waddr.String() {
			t.Errorf("Next addresses for each wallet do not match eachother.")
			return
		}
	}

	// Test that ExtendActiveAddresses for the watching wallet match
	// manually requested addresses of the original wallet.
	newAddrs := make([]btcutil.Address, 0, keypoolSize)
	for i := 0; i < keypoolSize; i++ {
		addr, err := w.NextChainedAddress(createdAt, keypoolSize)
		if err != nil {
			t.Errorf("Cannot get next chained address for original wallet: %v", err)
			return
		}
		newAddrs = append(newAddrs, addr)
	}
	newWWAddrs, err := ww.ExtendActiveAddresses(keypoolSize, keypoolSize)
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
	newWWAddrs = make([]btcutil.Address, 0, keypoolSize)
	for i := 0; i < keypoolSize; i++ {
		addr, err := ww.NextChainedAddress(createdAt, keypoolSize)
		if err != nil {
			t.Errorf("Cannot get next chained address for watching wallet: %v", err)
			return
		}
		newWWAddrs = append(newWWAddrs, addr)
	}
	newAddrs, err = w.ExtendActiveAddresses(keypoolSize, keypoolSize)
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
	ww2 := new(Wallet)
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
	if err := ww.Lock(); err != ErrWalletIsWatchingOnly {
		t.Errorf("Nonsensical func Lock returned no or incorrect error: %v", err)
		return
	}
	if err := ww.Unlock([]byte("banana")); err != ErrWalletIsWatchingOnly {
		t.Errorf("Nonsensical func Unlock returned no or incorrect error: %v", err)
		return
	}
	if _, err := ww.AddressKey(w.keyGenerator.address(ww.net)); err != ErrWalletIsWatchingOnly {
		t.Errorf("Nonsensical func AddressKey returned no or incorrect error: %v", err)
		return
	}
	if _, err := ww.ExportWatchingWallet(); err != ErrWalletIsWatchingOnly {
		t.Errorf("Nonsensical func ExportWatchingWallet returned no or incorrect error: %v", err)
		return
	}
	if _, err := ww.ImportPrivateKey(make([]byte, 32), true, createdAt); err != ErrWalletIsWatchingOnly {
		t.Errorf("Nonsensical func ImportPrivateKey returned no or incorrect error: %v", err)
		return
	}
}

func TestChangePassphrase(t *testing.T) {
	const keypoolSize = 10
	createdAt := &BlockStamp{}
	w, err := NewWallet("banana wallet", "A wallet for testing.",
		[]byte("banana"), btcwire.MainNet, createdAt, keypoolSize)
	if err != nil {
		t.Error("Error creating new wallet: " + err.Error())
		return
	}

	// Changing the passphrase with a locked wallet must fail with ErrWalletLocked.
	if err := w.ChangePassphrase([]byte("potato")); err != ErrWalletLocked {
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
	rootPrivKey, err := w.AddressKey(rootAddr)
	if err != nil {
		t.Errorf("Cannot get root address' private key: %v", err)
		return
	}

	// Change passphrase.
	if err := w.ChangePassphrase([]byte("potato")); err != nil {
		t.Errorf("Changing passhprase failed: %v", err)
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
	rootPrivKey2, err := w.AddressKey(rootAddr)
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
