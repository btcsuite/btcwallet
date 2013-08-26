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

package tx

import (
	"bytes"
	"encoding/binary"
	"github.com/conformal/btcwire"
	"github.com/davecgh/go-spew/spew"
	"io"
	"testing"
)

var (
	utxoByteSize = binary.Size(Utxo{})
)

func TestUtxoWriteRead(t *testing.T) {
	utxo1 := &Utxo{
		TxHash: [btcwire.HashSize]byte{
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
			30, 31,
		},
		Amt:    69,
		Height: 1337,
	}
	bufWriter := &bytes.Buffer{}
	n, err := utxo1.WriteTo(bufWriter)
	if err != nil {
		t.Error(err)
	}
	if int(n) != binary.Size(utxo1) {
		t.Error("Writing Utxo: Size Mismatch")
	}
	utxoBytes := bufWriter.Bytes()

	utxo2 := new(Utxo)
	n, err = utxo2.ReadFrom(bytes.NewBuffer(utxoBytes))
	if err != nil {
		t.Error(err)
	}
	if int(n) != binary.Size(utxo2) {
		t.Error("Reading Utxo: Size Mismatch")
	}

	buf1, buf2 := new(bytes.Buffer), new(bytes.Buffer)
	binary.Write(buf1, binary.LittleEndian, utxo1)
	binary.Write(buf2, binary.LittleEndian, utxo2)
	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		spew.Dump(utxo1, utxo2)
		t.Error("Utxos do not match.")
	}

	truncatedReadBuf := bytes.NewBuffer(utxoBytes)
	truncatedReadBuf.Truncate(btcwire.HashSize)
	utxo3 := new(Utxo)
	n, err = utxo3.ReadFrom(truncatedReadBuf)
	if err != io.EOF {
		t.Error("Expected err = io.EOF reading from truncated buffer.")
	}
	if n != btcwire.HashSize {
		t.Error("Incorrect number of bytes read from truncated buffer.")
	}
}

func TestUtxoStoreWriteRead(t *testing.T) {
	store1 := new(UtxoStore)
	for i := 0; i < 10; i++ {
		utxo := new(Utxo)
		for j, _ := range utxo.TxHash[:] {
			utxo.TxHash[j] = byte(i)
		}
		utxo.Amt = int64(i + 1)
		utxo.Height = int64(i + 2)
		store1.Confirmed = append(store1.Confirmed, utxo)
	}
	for i := 10; i < 20; i++ {
		utxo := new(Utxo)
		for j, _ := range utxo.TxHash[:] {
			utxo.TxHash[j] = byte(i)
		}
		utxo.Amt = int64(i + 1)
		utxo.Height = int64(i + 2)
		store1.Unconfirmed = append(store1.Unconfirmed, utxo)
	}

	bufWriter := &bytes.Buffer{}
	n, err := store1.WriteTo(bufWriter)
	if err != nil {
		t.Error(err)
	}
	if n != 20*(1+int64(utxoByteSize)) {
		t.Error("Incorrect number of bytes written.")
	}

	storeBytes := bufWriter.Bytes()

	store2 := new(UtxoStore)
	n, err = store2.ReadFrom(bytes.NewBuffer(storeBytes))
	if err != nil {
		t.Error(err)
	}
	if int(n) != len(storeBytes) {
		t.Error("Incorrect number of bytes read.")
	}

	switch {
	case len(store1.Confirmed) != len(store2.Confirmed):
		fallthrough
	case len(store1.Unconfirmed) != len(store2.Unconfirmed):
		t.Error("Stores are not equal.")
	}

	for i, _ := range store1.Confirmed {
		buf1, buf2 := new(bytes.Buffer), new(bytes.Buffer)
		binary.Write(buf1, binary.LittleEndian, store1.Confirmed[i])
		binary.Write(buf2, binary.LittleEndian, store2.Confirmed[i])
		if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
			t.Error("Store Utxos do not match.")
		}
	}
	for i, _ := range store1.Unconfirmed {
		buf1, buf2 := new(bytes.Buffer), new(bytes.Buffer)
		binary.Write(buf1, binary.LittleEndian, store1.Unconfirmed[i])
		binary.Write(buf2, binary.LittleEndian, store2.Unconfirmed[i])
		if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
			t.Error("Store Utxos do not match.")
		}
	}

	truncatedReadBuf := bytes.NewBuffer(storeBytes)
	truncatedReadBuf.Truncate(10*(1+utxoByteSize) + btcwire.HashSize)
	store3 := new(UtxoStore)
	n, err = store3.ReadFrom(truncatedReadBuf)
	if err != io.EOF {
		t.Error("Expected err = io.EOF reading from truncated buffer.")
	}
	if n != 10*(1+int64(utxoByteSize))+btcwire.HashSize {
		t.Error("Incorrect number of bytes read from truncated buffer.")
	}
}
