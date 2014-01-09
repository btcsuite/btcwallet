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

package tx

import (
	"bytes"
	"code.google.com/p/go.crypto/ripemd160"
	"github.com/conformal/btcwire"
	"github.com/davecgh/go-spew/spew"
	"io"
	"reflect"
	"testing"
)

var (
	recvtx = &RecvTx{
		TxID: [btcwire.HashSize]byte{
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
			30, 31,
		},
		TxOutIdx: 0,
		BlockHash: [btcwire.HashSize]byte{
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
			30, 31,
		},
		BlockHeight: 69,
		Amount:      69,
		ReceiverHash: []byte{
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			16, 17, 18, 19,
		},
	}

	sendtx = &SendTx{
		TxID: [btcwire.HashSize]byte{
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
			30, 31,
		},
		Time: 12345,
		BlockHash: [btcwire.HashSize]byte{
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
			30, 31,
		},
		BlockHeight: 69,
		BlockTime:   54321,
		BlockIndex:  3,
		Receivers: []Pair{
			Pair{
				PubkeyHash: []byte{
					20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
					34, 35, 36, 37, 38, 39,
				},
				Amount: 69,
			},
			Pair{
				PubkeyHash: []byte{
					40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
					54, 55, 56, 57, 58, 59,
				},
				Amount: 96,
			},
		},
	}
)

func TestUtxoWriteRead(t *testing.T) {
	utxo1 := &Utxo{
		AddrHash: [ripemd160.Size]byte{
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			16, 17, 18, 19,
		},
		Out: OutPoint{
			Hash: [btcwire.HashSize]byte{
				0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
				16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
				30, 31,
			},
			Index: 1,
		},
		Subscript: []byte{},
		Amt:       69,
		Height:    1337,
	}
	bufWriter := &bytes.Buffer{}
	written, err := utxo1.WriteTo(bufWriter)
	if err != nil {
		t.Error(err)
	}
	utxoBytes := bufWriter.Bytes()

	utxo2 := new(Utxo)
	read, err := utxo2.ReadFrom(bytes.NewBuffer(utxoBytes))
	if err != nil {
		t.Error(err)
	}
	if written != read {
		t.Error("Reading and Writing Utxo: Size Mismatch")
	}

	if !reflect.DeepEqual(utxo1, utxo2) {
		spew.Dump(utxo1, utxo2)
		t.Error("Utxos do not match.")
	}

	truncatedReadBuf := bytes.NewBuffer(utxoBytes)
	truncatedReadBuf.Truncate(btcwire.HashSize)
	utxo3 := new(Utxo)
	n, err := utxo3.ReadFrom(truncatedReadBuf)
	if err != io.EOF {
		t.Error("Expected err = io.EOF reading from truncated buffer.")
	}
	if n != btcwire.HashSize {
		t.Error("Incorrect number of bytes read from truncated buffer.")
	}
}

func TestUtxoStoreWriteRead(t *testing.T) {
	store1 := new(UtxoStore)
	for i := 0; i < 20; i++ {
		utxo := new(Utxo)
		for j := range utxo.Out.Hash[:] {
			utxo.Out.Hash[j] = byte(i + 1)
		}
		utxo.Out.Index = uint32(i + 2)
		utxo.Subscript = []byte{}
		utxo.Amt = uint64(i + 3)
		utxo.Height = int32(i + 4)
		utxo.BlockHash = [btcwire.HashSize]byte{
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
			30, 31,
		}
		*store1 = append(*store1, utxo)
	}

	bufWriter := &bytes.Buffer{}
	nWritten, err := store1.WriteTo(bufWriter)
	if err != nil {
		t.Error(err)
	}
	if nWritten != int64(bufWriter.Len()) {
		t.Errorf("Wrote %v bytes but write buffer has %v bytes.", nWritten, bufWriter.Len())
	}

	storeBytes := bufWriter.Bytes()
	bufReader := bytes.NewBuffer(storeBytes)
	if nWritten != int64(bufReader.Len()) {
		t.Errorf("Wrote %v bytes but read buffer has %v bytes.", nWritten, bufReader.Len())
	}

	store2 := new(UtxoStore)
	nRead, err := store2.ReadFrom(bufReader)
	if err != nil {
		t.Error(err)
	}
	if nWritten != nRead {
		t.Errorf("Bytes written (%v) does not match bytes read (%v).", nWritten, nRead)
	}

	if !reflect.DeepEqual(store1, store2) {
		spew.Dump(store1, store2)
		t.Error("Stores do not match.")
	}

	truncatedLen := 101
	truncatedReadBuf := bytes.NewBuffer(storeBytes[:truncatedLen])
	store3 := new(UtxoStore)
	n, err := store3.ReadFrom(truncatedReadBuf)
	if err != io.EOF {
		t.Errorf("Expected err = io.EOF reading from truncated buffer, got: %v", err)
	}
	if int(n) != truncatedLen {
		t.Errorf("Incorrect number of bytes (%v) read from truncated buffer (len %v).", n, truncatedLen)
	}
}

func TestRecvTxWriteRead(t *testing.T) {
	bufWriter := &bytes.Buffer{}
	n, err := recvtx.WriteTo(bufWriter)
	if err != nil {
		t.Error(err)
		return
	}
	txBytes := bufWriter.Bytes()

	tx := new(RecvTx)
	n, err = tx.ReadFrom(bytes.NewBuffer(txBytes))
	if err != nil {
		t.Errorf("Read %v bytes before erroring with: %v", n, err)
		return
	}

	if !reflect.DeepEqual(recvtx, tx) {
		t.Error("Txs do not match.")
		return
	}

	truncatedReadBuf := bytes.NewBuffer(txBytes)
	truncatedReadBuf.Truncate(btcwire.HashSize)
	n, err = tx.ReadFrom(truncatedReadBuf)
	if err != io.EOF {
		t.Error("Expected err = io.EOF reading from truncated buffer.")
		return
	}
	if n != btcwire.HashSize {
		t.Error("Incorrect number of bytes read from truncated buffer.")
		return
	}
}

func TestSendTxWriteRead(t *testing.T) {
	bufWriter := &bytes.Buffer{}
	n1, err := sendtx.WriteTo(bufWriter)
	if err != nil {
		t.Error(err)
		return
	}
	txBytes := bufWriter.Bytes()

	tx := new(SendTx)
	n2, err := tx.ReadFrom(bytes.NewBuffer(txBytes))
	if err != nil {
		t.Errorf("Read %v bytes before erroring with: %v", n2, err)
		return
	}
	if n1 != n2 {
		t.Errorf("Number of bytes written and read mismatch, %d != %d",
			n1, n2)
		return
	}

	if !reflect.DeepEqual(sendtx, tx) {
		t.Error("Txs do not match.")
		return
	}

	truncatedReadBuf := bytes.NewBuffer(txBytes)
	truncatedReadBuf.Truncate(btcwire.HashSize)
	n, err := tx.ReadFrom(truncatedReadBuf)
	if err != io.EOF {
		t.Error("Expected err = io.EOF reading from truncated buffer.")
		return
	}
	if n != btcwire.HashSize {
		t.Error("Incorrect number of bytes read from truncated buffer.")
		return
	}
}

func TestTxStoreWriteRead(t *testing.T) {
	s := []interface{}{recvtx, sendtx}
	store := TxStore(s)

	bufWriter := &bytes.Buffer{}
	n1, err := store.WriteTo(bufWriter)
	if err != nil {
		t.Error(err)
		return
	}
	txsBytes := bufWriter.Bytes()

	txs := TxStore{}
	n2, err := txs.ReadFrom(bytes.NewBuffer(txsBytes))
	if err != nil {
		t.Errorf("Read %v bytes before erroring with: %v", n2, err)
		return
	}
	if n1 != n2 {
		t.Error("Number of bytes written and read mismatch.")
		return
	}

	if !reflect.DeepEqual(store, txs) {
		spew.Dump(store, txs)
		t.Error("TxStores do not match.")
		return
	}

	truncatedReadBuf := bytes.NewBuffer(txsBytes)
	truncatedReadBuf.Truncate(50)
	n, err := txs.ReadFrom(truncatedReadBuf)
	if err != io.EOF {
		t.Error("Expected err = io.EOF reading from truncated buffer.")
		return
	}
	if n != 50 {
		t.Error("Incorrect number of bytes read from truncated buffer.")
		return
	}
}
