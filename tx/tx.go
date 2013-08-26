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
	"code.google.com/p/go.crypto/ripemd160"
	"encoding/binary"
	"fmt"
	"github.com/conformal/btcwire"
	"io"
)

// Byte headers prepending confirmed and unconfirmed serialized UTXOs.
const (
	ConfirmedUtxoHeader byte = iota
	UnconfirmedUtxoHeader
)

// Byte headers prepending received and sent serialized transactions.
const (
	RecvTxHeader byte = iota
	SendTxHeader
)

type UtxoStore struct {
	Confirmed   []*Utxo
	Unconfirmed []*Utxo
}

type Utxo struct {
	TxHash btcwire.ShaHash
	Amt    int64 // Measured in Satoshis
	Height int64
}

// TxStore is a slice holding RecvTx and SendTx pointers.
type TxStore []interface{}

type RecvTx struct {
	TxHash       btcwire.ShaHash
	Amt          int64 // Measured in Satoshis
	SenderAddr   [ripemd160.Size]byte
	ReceiverAddr [ripemd160.Size]byte
}

type SendTx struct {
	TxHash        btcwire.ShaHash
	Amt           int64 // Measured in Satoshis
	SenderAddr    [ripemd160.Size]byte
	ReceiverAddrs []struct {
		Addr [ripemd160.Size]byte
		Amt  int64
	}
}

// We want to use binaryRead and binaryWrite instead of binary.Read
// and binary.Write because those from the binary package do not return
// the number of bytes actually written or read.  We need to return
// this value to correctly support the io.ReaderFrom and io.WriterTo
// interfaces.
func binaryRead(r io.Reader, order binary.ByteOrder, data interface{}) (n int64, err error) {
	var read int
	buf := make([]byte, binary.Size(data))
	if read, err = r.Read(buf); err != nil {
		return int64(read), err
	}
	return int64(read), binary.Read(bytes.NewBuffer(buf), order, data)
}

// See comment for binaryRead().
func binaryWrite(w io.Writer, order binary.ByteOrder, data interface{}) (n int64, err error) {
	var buf bytes.Buffer
	if err = binary.Write(&buf, order, data); err != nil {
		return 0, err
	}

	written, err := w.Write(buf.Bytes())
	return int64(written), err
}

// ReadFrom satisifies the io.ReaderFrom interface.  Utxo structs are
// read in from r until an io.EOF is reached.  If an io.EOF is reached
// before a Utxo is finished being read, err will be non-nil.
func (u *UtxoStore) ReadFrom(r io.Reader) (n int64, err error) {
	var read int64
	for {
		// Read header
		var header byte
		read, err = binaryRead(r, binary.LittleEndian, &header)
		if err != nil {
			// EOF here is not an error.
			if err == io.EOF {
				return n + read, nil
			}
			return n + read, err
		}
		n += read

		// Read Utxo
		var slicep *[]*Utxo
		switch header {
		case ConfirmedUtxoHeader:
			slicep = &u.Confirmed
		case UnconfirmedUtxoHeader:
			slicep = &u.Unconfirmed
		default:
			return n, fmt.Errorf("Unknown Utxo header.")
		}
		utxo := new(Utxo)
		read, err = utxo.ReadFrom(r)
		if err != nil {
			return n + read, err
		}
		n += read
		*slicep = append(*slicep, utxo)
	}
}

// WriteTo satisifies the io.WriterTo interface.  Each Utxo is written
// to w, prepended by a single byte header to distinguish between
// confirmed and unconfirmed outputs.
func (u *UtxoStore) WriteTo(w io.Writer) (n int64, err error) {
	var written int64

	for _, utxo := range u.Confirmed {
		// Write header
		written, err = binaryWrite(w, binary.LittleEndian, ConfirmedUtxoHeader)
		if err != nil {
			return n + written, err
		}
		n += written

		// Write Utxo
		written, err = utxo.WriteTo(w)
		if err != nil {
			return n + written, err
		}
		n += written
	}

	for _, utxo := range u.Unconfirmed {
		// Write header
		written, err = binaryWrite(w, binary.LittleEndian, UnconfirmedUtxoHeader)
		if err != nil {
			return n + written, err
		}
		n += written

		// Write Utxo
		written, err = utxo.WriteTo(w)
		if err != nil {
			return n + written, err
		}
		n += written
	}

	return n, nil
}

// ReadFrom satisifies the io.ReaderFrom interface.  A Utxo is read
// from r with the format:
//
//  [TxHash (32 bytes), Amt (8 bytes), Height (8 bytes)]
//
// Each field is read little endian.
func (u *Utxo) ReadFrom(r io.Reader) (n int64, err error) {
	datas := []interface{}{
		&u.TxHash,
		&u.Amt,
		&u.Height,
	}
	var read int64
	for _, data := range datas {
		read, err = binaryRead(r, binary.LittleEndian, data)
		if err != nil {
			return n + read, err
		}
		n += read
	}
	return n, nil
}

// WriteTo satisifies the io.WriterTo interface.  A Utxo is written to
// w in the format:
//
//  [TxHash (32 bytes), Amt (8 bytes), Height (8 bytes)]
//
// Each field is written little endian.
func (u *Utxo) WriteTo(w io.Writer) (n int64, err error) {
	datas := []interface{}{
		&u.TxHash,
		&u.Amt,
		&u.Height,
	}
	var written int64
	for _, data := range datas {
		written, err = binaryWrite(w, binary.LittleEndian, data)
		if err != nil {
			return n + written, err
		}
		n += written
	}
	return n, nil
}

// ReadFrom satisifies the io.ReaderFrom interface.  A TxStore is read
// in from r with the format:
//
//  [[TxHeader (1 byte), Tx (varies in size)]...]
func (txs *TxStore) ReadFrom(r io.Reader) (n int64, err error) {
	store := []interface{}{}
	defer func() {
		*txs = store
	}()
	var read int64
	for {
		// Read header
		var header byte
		read, err = binaryRead(r, binary.LittleEndian, &header)
		if err != nil {
			// io.EOF is not an error here.
			if err == io.EOF {
				return n + read, nil
			}
			return n + read, err
		}
		n += read

		var tx io.ReaderFrom
		switch header {
		case RecvTxHeader:
			tx = new(RecvTx)
		case SendTxHeader:
			tx = new(SendTx)
		default:
			return n, fmt.Errorf("Unknown Tx header")
		}

		// Read tx
		read, err = tx.ReadFrom(r)
		if err != nil {
			return n + read, err
		}
		n += read

		store = append(store, tx)
	}
}

// WriteTo satisifies the io.WriterTo interface.  A TxStore is written
// to w in the format:
//
//  [[TxHeader (1 byte), Tx (varies in size)]...]
func (txs *TxStore) WriteTo(w io.Writer) (n int64, err error) {
	store := ([]interface{})(*txs)
	var written int64
	for _, tx := range store {
		switch tx.(type) {
		case *RecvTx:
			written, err = binaryWrite(w, binary.LittleEndian, RecvTxHeader)
			if err != nil {
				return n + written, err
			}
			n += written
		case *SendTx:
			written, err = binaryWrite(w, binary.LittleEndian, SendTxHeader)
			if err != nil {
				return n + written, err
			}
			n += written
		default:
			return n, fmt.Errorf("Unknown type in TxStore")
		}
		wt := tx.(io.WriterTo)
		written, err = wt.WriteTo(w)
		if err != nil {
			return n + written, err
		}
		n += written
	}
	return n, nil
}

// ReadFrom satisifies the io.ReaderFrom interface.  A RecTx is read
// in from r with the format:
//
//  [TxHash (32 bytes), Amt (8 bytes), SenderAddr (20 bytes), ReceiverAddr (20 bytes)]
//
// Each field is read little endian.
func (tx *RecvTx) ReadFrom(r io.Reader) (n int64, err error) {
	datas := []interface{}{
		&tx.TxHash,
		&tx.Amt,
		&tx.SenderAddr,
		&tx.ReceiverAddr,
	}
	var read int64
	for _, data := range datas {
		read, err = binaryRead(r, binary.LittleEndian, data)
		if err != nil {
			return n + read, err
		}
		n += read
	}
	return n, nil
}

// WriteTo satisifies the io.WriterTo interface.  A RecvTx is written to
// w in the format:
//
//  [TxHash (32 bytes), Amt (8 bytes), SenderAddr (20 bytes), ReceiverAddr (20 bytes)]
//
// Each field is written little endian.
func (tx *RecvTx) WriteTo(w io.Writer) (n int64, err error) {
	datas := []interface{}{
		&tx.TxHash,
		&tx.Amt,
		&tx.SenderAddr,
		&tx.ReceiverAddr,
	}
	var written int64
	for _, data := range datas {
		written, err = binaryWrite(w, binary.LittleEndian, data)
		if err != nil {
			return n + written, err
		}
		n += written
	}
	return n, nil
}

// ReadFrom satisifies the io.WriterTo interface.  A SendTx is read
// from r with the format:
//
//  [TxHash (32 bytes), SenderAddr (20 bytes), len(ReceiverAddrs) (4 bytes), ReceiverAddrs[Addr (20 bytes), Amt (8 bytes)]...]
//
// Each field is read little endian.
func (tx *SendTx) ReadFrom(r io.Reader) (n int64, err error) {
	var nReceivers uint32
	datas := []interface{}{
		&tx.TxHash,
		&tx.Amt,
		&tx.SenderAddr,
		&nReceivers,
	}
	var read int64
	for _, data := range datas {
		read, err = binaryRead(r, binary.LittleEndian, data)
		if err != nil {
			return n + read, err
		}
		n += read
	}
	if nReceivers == 0 {
		// XXX: Is this valid? Entire output is a fee for the miner?
		return n, nil
	}

	tx.ReceiverAddrs = make([]struct {
		Addr [ripemd160.Size]byte
		Amt  int64
	},
		nReceivers)
	for i := uint32(0); i < nReceivers; i++ {
		datas := []interface{}{
			&tx.ReceiverAddrs[i].Addr,
			&tx.ReceiverAddrs[i].Amt,
		}
		for _, data := range datas {
			read, err = binaryRead(r, binary.LittleEndian, data)
			if err != nil {
				return n + read, err
			}
			n += read
		}
	}
	return n, nil
}

// WriteTo satisifies the io.WriterTo interface.  A RecvTx is written to
// w in the format:
//
//  [TxHash (32 bytes), SenderAddr (20 bytes), len(ReceiverAddrs) (4 bytes), ReceiverAddrs[Addr (20 bytes), Amt (8 bytes)]...]
//
// Each field is written little endian.
func (tx *SendTx) WriteTo(w io.Writer) (n int64, err error) {
	nReceivers := uint32(len(tx.ReceiverAddrs))
	if int64(nReceivers) != int64(len(tx.ReceiverAddrs)) {
		return n, fmt.Errorf("Too many receiving addresses.")
	}
	datas := []interface{}{
		&tx.TxHash,
		&tx.Amt,
		&tx.SenderAddr,
		nReceivers,
	}
	var written int64
	for _, data := range datas {
		written, err = binaryWrite(w, binary.LittleEndian, data)
		if err != nil {
			return n + written, err
		}
		n += written
	}

	for i, _ := range tx.ReceiverAddrs {
		datas := []interface{}{
			&tx.ReceiverAddrs[i].Addr,
			&tx.ReceiverAddrs[i].Amt,
		}
		for _, data := range datas {
			written, err = binaryWrite(w, binary.LittleEndian, data)
			if err != nil {
				return n + written, err
			}
			n += written
		}
	}
	return n, nil
}
