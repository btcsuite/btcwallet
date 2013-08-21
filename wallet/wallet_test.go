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
	"bytes"
	"encoding/binary"
	"github.com/davecgh/go-spew/spew"
	"os"
	"testing"
)

func TestBtcAddressSerializer(t *testing.T) {
	var addr = btcAddress{
		pubKeyHash: [20]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
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
		spew.Dump(&readAddr)
		t.Error(err.Error())
		return
	}

	buf1, buf2 := new(bytes.Buffer), new(bytes.Buffer)
	binary.Write(buf1, binary.LittleEndian, addr)
	binary.Write(buf2, binary.LittleEndian, readAddr)
	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Error("Original and read btcAddress differ.")
	}
}
