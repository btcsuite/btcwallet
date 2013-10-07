/*
 * Copyright (c) 2013 Conformal Systems LLC <info@conformal.com>
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
	"crypto/rand"
	"github.com/conformal/btcwire"
	"github.com/davecgh/go-spew/spew"
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
	rand.Read(kdfp.salt[:])
	key := Key([]byte("banana"), kdfp)
	privKey := make([]byte, 32)
	rand.Read(privKey)
	addr, err := newBtcAddress(privKey, nil)
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

	if err = readAddr.unlock(key); err != nil {
		t.Error(err.Error())
		return
	}

	if !reflect.DeepEqual(addr, &readAddr) {
		t.Error("Original and read btcAddress differ.")
	}
}

func TestWalletCreationSerialization(t *testing.T) {
	w1, err := NewWallet("banana wallet", "A wallet for testing.", []byte("banana"), btcwire.MainNet)
	if err != nil {
		t.Error("Error creating new wallet: " + err.Error())
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
