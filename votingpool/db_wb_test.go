/*
 * Copyright (c) 2015 The btcsuite developers
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

package votingpool

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcwallet/walletdb"
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
