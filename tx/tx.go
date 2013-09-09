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
	"errors"
	"fmt"
	"github.com/conformal/btcwire"
	"io"
)

// Byte headers prepending received and sent serialized transactions.
const (
	RecvTxHeader byte = iota
	SendTxHeader
)

// UtxoStore is a type used for holding all Utxo structures for all
// addresses in a wallet.
type UtxoStore []*Utxo

// Utxo is a type storing information about a single unspent
// transaction output.
type Utxo struct {
	Addr      [ripemd160.Size]byte
	Out       OutPoint
	Subscript PkScript
	Amt       uint64 // Measured in Satoshis
	Height    int64
	BlockHash btcwire.ShaHash
}

// OutPoint is a btcwire.OutPoint with custom methods for serialization.
type OutPoint btcwire.OutPoint

// PkScript is a custom type with methods to serialize pubkey scripts
// of variable length.
type PkScript []byte

// TxStore is a slice holding RecvTx and SendTx pointers.
type TxStore []interface{}

// RecvTx is a type storing information about a transaction that was
// received by an address in a wallet.
type RecvTx struct {
	TxHash       btcwire.ShaHash
	BlockHash    btcwire.ShaHash
	Height       int64
	Amt          uint64 // Measured in Satoshis
	SenderAddr   [ripemd160.Size]byte
	ReceiverAddr [ripemd160.Size]byte
}

// SendTx is a type storing information about a transaction that was
// sent by an address in a wallet.
type SendTx struct {
	TxHash        btcwire.ShaHash
	BlockHash     btcwire.ShaHash
	Height        int64
	Fee           uint64 // Measured in Satoshis
	SenderAddr    [ripemd160.Size]byte
	ReceiverAddrs []struct {
		Addr [ripemd160.Size]byte
		Amt  uint64 // Measured in Satoshis
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
	if read < binary.Size(data) {
		return int64(read), io.EOF
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
		// Read Utxo
		utxo := new(Utxo)
		read, err = utxo.ReadFrom(r)
		if err != nil {
			if read == 0 && err == io.EOF {
				return n, nil
			}
			return n + read, err
		}
		n += read
		*u = append(*u, utxo)
	}
}

// WriteTo satisifies the io.WriterTo interface.  Each Utxo is written
// to w, prepended by a single byte header to distinguish between
// confirmed and unconfirmed outputs.
func (u *UtxoStore) WriteTo(w io.Writer) (n int64, err error) {
	var written int64
	for _, utxo := range *u {
		// Write Utxo
		written, err = utxo.WriteTo(w)
		if err != nil {
			return n + written, err
		}
		n += written
	}

	return n, nil
}

// Rollback removes all utxos from and after the block specified
// by a block height and hash.
//
// Correct results rely on u being sorted by block height in
// increasing order.
func (u *UtxoStore) Rollback(height int64, hash *btcwire.ShaHash) (modified bool) {
	s := *u

	// endlen specifies the final length of the rolled-back UtxoStore.
	// Past endlen, array elements are nilled.  We do this instead of
	// just reslicing with a shorter length to avoid leaving elements
	// in the underlying array so they can be garbage collected.
	endlen := len(s)
	defer func() {
		modified = endlen != len(s)
		for i := endlen; i < len(s); i++ {
			s[i] = nil
		}
		*u = s[:endlen]
		return
	}()

	for i := len(s) - 1; i >= 0; i-- {
		if height > s[i].Height {
			break
		}
		if height == s[i].Height && *hash == s[i].BlockHash {
			endlen = i
		}
	}
	return
}

// ReadFrom satisifies the io.ReaderFrom interface.  A Utxo is read
// from r with the format:
//
//  [Addr (20 bytes), Out (36 bytes), Subscript (varies), Amt (8 bytes), Height (8 bytes), BlockHash (32 bytes)]
//
// Each field is read little endian.
func (u *Utxo) ReadFrom(r io.Reader) (n int64, err error) {
	datas := []interface{}{
		&u.Addr,
		&u.Out,
		&u.Subscript,
		&u.Amt,
		&u.Height,
		&u.BlockHash,
	}
	var read int64
	for _, data := range datas {
		if rf, ok := data.(io.ReaderFrom); ok {
			read, err = rf.ReadFrom(r)
		} else {
			read, err = binaryRead(r, binary.LittleEndian, data)
		}
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
//  [Addr (20 bytes), Out (36 bytes), Subscript (varies), Amt (8 bytes), Height (8 bytes), BlockHash (32 bytes)]
//
// Each field is written little endian.
func (u *Utxo) WriteTo(w io.Writer) (n int64, err error) {
	datas := []interface{}{
		&u.Addr,
		&u.Out,
		&u.Subscript,
		&u.Amt,
		&u.Height,
		&u.BlockHash,
	}
	var written int64
	for _, data := range datas {
		if wt, ok := data.(io.WriterTo); ok {
			written, err = wt.WriteTo(w)
		} else {
			written, err = binaryWrite(w, binary.LittleEndian, data)
		}
		if err != nil {
			return n + written, err
		}
		n += written
	}
	return n, nil
}

// ReadFrom satisifies the io.ReaderFrom interface.  An OutPoint is read
// from r with the format:
//
//  [Hash (32 bytes), Index (4 bytes)]
//
// Each field is read little endian.
func (o *OutPoint) ReadFrom(r io.Reader) (n int64, err error) {
	datas := []interface{}{
		&o.Hash,
		&o.Index,
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

// WriteTo satisifies the io.WriterTo interface.  An OutPoint is written
// to w in the format:
//
//  [Hash (32 bytes), Index (4 bytes)]
//
// Each field is written little endian.
func (o *OutPoint) WriteTo(w io.Writer) (n int64, err error) {
	datas := []interface{}{
		&o.Hash,
		&o.Index,
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

// ReadFrom satisifies the io.ReaderFrom interface.  A PkScript is read
// from r with the format:
//
//  [Length (4 byte unsigned integer), ScriptBytes (Length bytes)]
//
// Length is read little endian.
func (s *PkScript) ReadFrom(r io.Reader) (n int64, err error) {
	var scriptlen uint32
	var read int64
	read, err = binaryRead(r, binary.LittleEndian, &scriptlen)
	if err != nil {
		return n + read, err
	}
	n += read

	scriptbuf := new(bytes.Buffer)
	read, err = scriptbuf.ReadFrom(io.LimitReader(r, int64(scriptlen)))
	if err != nil {
		return n + read, err
	}
	n += read
	*s = scriptbuf.Bytes()

	return n, nil
}

// WriteTo satisifies the io.WriterTo interface.  A PkScript is written
// to w in the format:
//
//  [Length (4 byte unsigned integer), ScriptBytes (Length bytes)]
//
// Length is written little endian.
func (s *PkScript) WriteTo(w io.Writer) (n int64, err error) {
	var written int64
	written, err = binaryWrite(w, binary.LittleEndian, uint32(len(*s)))
	if err != nil {
		return n + written, nil
	}
	n += written

	written, err = bytes.NewBuffer(*s).WriteTo(w)
	if err != nil {
		return n + written, nil
	}
	n += written

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
			return n, fmt.Errorf("unknown Tx header")
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
			return n, fmt.Errorf("unknown type in TxStore")
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

// Rollback removes all txs from and after the block specified by a
// block height and hash.
//
// Correct results rely on txs being sorted by block height in
// increasing order.
func (txs *TxStore) Rollback(height int64, hash *btcwire.ShaHash) (modified bool) {
	s := ([]interface{})(*txs)

	// endlen specifies the final length of the rolled-back TxStore.
	// Past endlen, array elements are nilled.  We do this instead of
	// just reslicing with a shorter length to avoid leaving elements
	// in the underlying array so they can be garbage collected.
	endlen := len(s)
	defer func() {
		modified = endlen != len(s)
		for i := endlen; i < len(s); i++ {
			s[i] = nil
		}
		*txs = s[:endlen]
		return
	}()

	for i := len(s) - 1; i >= 0; i-- {
		var txheight int64
		var txhash *btcwire.ShaHash
		switch s[i].(type) {
		case *RecvTx:
			tx := s[i].(*RecvTx)
			if height > tx.Height {
				break
			}
			txheight = tx.Height
			txhash = &tx.BlockHash
		case *SendTx:
			tx := s[i].(*SendTx)
			if height > tx.Height {
				break
			}
			txheight = tx.Height
			txhash = &tx.BlockHash
		}
		if height == txheight && *hash == *txhash {
			endlen = i
		}
	}
	return
}

// ReadFrom satisifies the io.ReaderFrom interface.  A RecTx is read
// in from r with the format:
//
//  [TxHash (32 bytes), BlockHash (32 bytes), Height (8 bytes), Amt (8 bytes), SenderAddr (20 bytes), ReceiverAddr (20 bytes)]
//
// Each field is read little endian.
func (tx *RecvTx) ReadFrom(r io.Reader) (n int64, err error) {
	datas := []interface{}{
		&tx.TxHash,
		&tx.BlockHash,
		&tx.Height,
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
//  [TxHash (32 bytes), BlockHash (32 bytes), Height (8 bytes), Amt (8 bytes), SenderAddr (20 bytes), ReceiverAddr (20 bytes)]
//
// Each field is written little endian.
func (tx *RecvTx) WriteTo(w io.Writer) (n int64, err error) {
	datas := []interface{}{
		&tx.TxHash,
		&tx.BlockHash,
		&tx.Height,
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
//  [TxHash (32 bytes), Height (8 bytes), Fee (8 bytes), SenderAddr (20 bytes), len(ReceiverAddrs) (4 bytes), ReceiverAddrs[Addr (20 bytes), Amt (8 bytes)]...]
//
// Each field is read little endian.
func (tx *SendTx) ReadFrom(r io.Reader) (n int64, err error) {
	var nReceivers uint32
	datas := []interface{}{
		&tx.TxHash,
		&tx.Height,
		&tx.Fee,
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
		Amt  uint64
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

// WriteTo satisifies the io.WriterTo interface.  A SendTx is written to
// w in the format:
//
//  [TxHash (32 bytes), Height (8 bytes), Fee (8 bytes), SenderAddr (20 bytes), len(ReceiverAddrs) (4 bytes), ReceiverAddrs[Addr (20 bytes), Amt (8 bytes)]...]
//
// Each field is written little endian.
func (tx *SendTx) WriteTo(w io.Writer) (n int64, err error) {
	nReceivers := uint32(len(tx.ReceiverAddrs))
	if int64(nReceivers) != int64(len(tx.ReceiverAddrs)) {
		return n, errors.New("too many receiving addresses")
	}
	datas := []interface{}{
		&tx.TxHash,
		&tx.Height,
		&tx.Fee,
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

	for i := range tx.ReceiverAddrs {
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
