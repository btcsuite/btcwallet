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
	"github.com/conformal/btcec"
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
