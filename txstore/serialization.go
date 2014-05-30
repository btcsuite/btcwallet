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

package txstore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
)

// All Store versions (both old and current).
const (
	versFirst uint32 = iota

	// versRecvTxIndex is the version where the txout index
	// was added to the RecvTx struct.
	versRecvTxIndex

	// versMarkSentChange is the version where serialized SentTx
	// added a flags field, used for marking a sent transaction
	// as change.
	versMarkSentChange

	// versCombined is the version where the old utxo and tx stores
	// were combined into a single data structure.
	versCombined

	// versFastRewrite is the version where the combined store was
	// rewritten with a focus on insertion and lookup speed.
	versFastRewrite

	// versCurrent is the current tx file version.
	versCurrent = versFastRewrite
)

// byteOrder is the byte order used to read and write txstore binary data.
var byteOrder = binary.LittleEndian

// ReadFrom satisifies the io.ReaderFrom interface by deserializing a
// transaction store from an io.Reader.
func (s *Store) ReadFrom(r io.Reader) (int64, error) {
	var buf [4]byte
	uint32Bytes := buf[:4]

	// Read current file version.
	n, err := io.ReadFull(r, uint32Bytes)
	n64 := int64(n)
	if err != nil {
		return n64, err
	}
	vers := byteOrder.Uint32(uint32Bytes)

	// Reading files with versions before versFastRewrite is unsupported.
	if vers < versFastRewrite {
		return n64, ErrUnsupportedVersion
	}

	// Reset store.
	*s = *New()

	// Read block structures.  Begin by reading the total number of block
	// structures to be read, and then iterate that many times to read
	// each block.
	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n64, err
	}
	blockCount := byteOrder.Uint32(uint32Bytes)
	// The blocks slice is *not* preallocated to blockCount size to prevent
	// accidentally allocating so much memory that the process dies.
	for i := uint32(0); i < blockCount; i++ {
		b := &blockTxCollection{
			txIndexes: map[int]uint32{},
			unspent:   map[int]uint32{},
		}
		tmpn64, err := b.ReadFrom(r)
		n64 += tmpn64
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return n64, err
		}
		s.blocks = append(s.blocks, b)
		s.blockIndexes[b.Height] = i

		// Recreate unspent map.  If any of the block's transactions
		// contain unspent credits, mark the store's unspent map to
		// reflect that this block contains transactions with unspent
		// credits.
		if len(b.unspent) != 0 {
			s.unspent[b.Height] = struct{}{}
		}
	}

	// Read unconfirmed transactions and their spend tracking.
	tmpn64, err := s.unconfirmed.ReadFrom(r)
	n64 += tmpn64
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n64, err
	}

	return n64, nil
}

// WriteTo satisifies the io.WriterTo interface by serializing a transaction
// store to an io.Writer.
func (s *Store) WriteTo(w io.Writer) (int64, error) {
	var buf [4]byte
	uint32Bytes := buf[:4]

	// Write current file version.
	byteOrder.PutUint32(uint32Bytes, versCurrent)
	n, err := w.Write(uint32Bytes)
	n64 := int64(n)
	if err != nil {
		return n64, err
	}

	// Write block structures.  This begins with a uint32 specifying that
	// some N blocks have been written, followed by N serialized transaction
	// store blocks.
	//
	// The store's blockIndexes map is intentionally not written.  Instead,
	// it is recreated on reads after reading each block.
	byteOrder.PutUint32(uint32Bytes, uint32(len(s.blocks)))
	n, err = w.Write(uint32Bytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}
	for _, b := range s.blocks {
		n, err := b.WriteTo(w)
		n64 += n
		if err != nil {
			return n64, err
		}
	}

	// Write unconfirmed transactions and their spend tracking.
	tmpn64, err := s.unconfirmed.WriteTo(w)
	n64 += tmpn64
	if err != nil {
		return n64, err
	}

	// The store's unspent map is intentionally not written.  Instead, it
	// is recreated on reads after each block transaction collection has
	// been read.  This makes reads more expensive, but writing faster, and
	// as writes are far more common in application use, this was deemed to
	// be an acceptable tradeoff.

	return n64, nil
}

func (b *blockTxCollection) ReadFrom(r io.Reader) (int64, error) {
	var buf [8]byte
	uint64Bytes := buf[:8]
	uint32Bytes := buf[:4]

	// Read block hash, unix time (int64), and height (int32).
	n, err := io.ReadFull(r, b.Hash[:])
	n64 := int64(n)
	if err != nil {
		return n64, err
	}
	n, err = io.ReadFull(r, uint64Bytes)
	n64 += int64(n)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n64, err
	}
	b.Time = time.Unix(int64(byteOrder.Uint64(uint64Bytes)), 0)
	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n64, err
	}
	b.Height = int32(byteOrder.Uint32(uint32Bytes))

	// Read amount deltas as a result of transactions in this block.  This
	// is the net total spendable balance as a result of transaction debits
	// and credits, and the block reward (not immediately spendable) for
	// coinbase outputs.  Both are int64s.
	n, err = io.ReadFull(r, uint64Bytes)
	n64 += int64(n)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n64, err
	}
	b.amountDeltas.Spendable = btcutil.Amount(byteOrder.Uint64(uint64Bytes))
	n, err = io.ReadFull(r, uint64Bytes)
	n64 += int64(n)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n64, err
	}
	b.amountDeltas.Reward = btcutil.Amount(byteOrder.Uint64(uint64Bytes))

	// Read number of transaction records (as a uint32) followed by a read
	// for each expected record.
	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n64, err
	}
	txCount := byteOrder.Uint32(uint32Bytes)
	// The txs slice is *not* preallocated to txcount size to prevent
	// accidentally allocating so much memory that the process dies.
	for i := uint32(0); i < txCount; i++ {
		t := &txRecord{}
		tmpn64, err := t.ReadFrom(r)
		n64 += tmpn64
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return n64, err
		}
		b.txs = append(b.txs, t)

		// Recreate txIndexes map.  For each transaction record, map the
		// block index of the underlying transaction to the slice index
		// of the record.
		b.txIndexes[t.tx.Index()] = i

		// Recreate unspent map.  For each credit of this transaction,
		// if any credit is unspent, mark it in unspent map.
		for _, c := range t.credits {
			if c == nil {
				continue
			}
			if c.spentBy == nil {
				b.unspent[t.tx.Index()] = i
				break
			}
		}
	}

	return n64, nil
}

func (b *blockTxCollection) WriteTo(w io.Writer) (int64, error) {
	var buf [8]byte
	uint64Bytes := buf[:8]
	uint32Bytes := buf[:4]

	// Write block hash, unix time (int64), and height (int32).
	n, err := w.Write(b.Hash[:])
	n64 := int64(n)
	if err != nil {
		return n64, err
	}
	byteOrder.PutUint64(uint64Bytes, uint64(b.Time.Unix()))
	n, err = w.Write(uint64Bytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}
	byteOrder.PutUint32(uint32Bytes, uint32(b.Height))
	n, err = w.Write(uint32Bytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}

	// Write amount deltas as a result of transactions in this block.
	// This is the net total spendable balance as a result of transaction
	// debits and credits, and the block reward (not immediately spendable)
	// for coinbase outputs.  Both are int64s.
	byteOrder.PutUint64(uint64Bytes, uint64(b.amountDeltas.Spendable))
	n, err = w.Write(uint64Bytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}
	byteOrder.PutUint64(uint64Bytes, uint64(b.amountDeltas.Reward))
	n, err = w.Write(uint64Bytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}

	// Write number of transaction records (as a uint32) followed by each
	// transaction record.
	byteOrder.PutUint32(uint32Bytes, uint32(len(b.txs)))
	n, err = w.Write(uint32Bytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}
	for _, t := range b.txs {
		n, err := t.WriteTo(w)
		n64 += n
		if err != nil {
			return n64, err
		}
	}

	// The block's txIndexes and unspent bookkeeping maps are intentionally
	// not written.  They are instead recreated on reads.  This makes reads
	// more expensive, but writing faster, and as writes are far more common
	// in application use, this was deemed to be an acceptable tradeoff.

	return n64, nil
}

const (
	nilPointer byte = iota
	validPointer
)

func byteMarksValidPointer(b byte) (bool, error) {
	switch b {
	case nilPointer:
		return false, nil
	case validPointer:
		return true, nil
	default:
		s := "invalid byte representation of valid pointer"
		return false, errors.New(s)
	}
}

const (
	falseByte byte = iota
	trueByte
)

func byteAsBool(b byte) (bool, error) {
	switch b {
	case falseByte:
		return false, nil
	case trueByte:
		return true, nil
	default:
		return false, errors.New("invalid byte representation of bool")
	}
}

func (t *txRecord) ReadFrom(r io.Reader) (int64, error) {
	var buf [8]byte
	uint64Bytes := buf[:8]
	uint32Bytes := buf[:4]
	singleByte := buf[:1]

	// Read transaction index (as a uint32).
	n, err := io.ReadFull(r, uint32Bytes)
	n64 := int64(n)
	if err != nil {
		return n64, err
	}
	txIndex := int(byteOrder.Uint32(uint32Bytes))

	// Deserialize transaction.
	msgTx := new(msgTx)
	tmpn64, err := msgTx.ReadFrom(r)
	n64 += tmpn64
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n64, err
	}

	// Create and save the btcutil.Tx of the read MsgTx and set its index.
	tx := btcutil.NewTx((*btcwire.MsgTx)(msgTx))
	tx.SetIndex(txIndex)
	t.tx = tx

	// Read identifier for existance of debits.
	n, err = io.ReadFull(r, singleByte)
	n64 += int64(n)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n64, err
	}
	hasDebits, err := byteMarksValidPointer(singleByte[0])
	if err != nil {
		return n64, err
	}

	// If debits have been set, read them.  Otherwise, set to nil.
	if hasDebits {
		// Read debited amount (int64).
		n, err := io.ReadFull(r, uint64Bytes)
		n64 += int64(n)
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return n64, err
		}
		amount := btcutil.Amount(byteOrder.Uint64(uint64Bytes))

		// Read number of written outputs (as a uint32) this record
		// debits from.
		n, err = io.ReadFull(r, uint32Bytes)
		n64 += int64(n)
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return n64, err
		}
		spendsCount := byteOrder.Uint32(uint32Bytes)

		// For each expected output key, allocate and read the key,
		// appending the result to the spends slice.  This slice is
		// originally set to nil (*not* preallocated to spendsCount
		// size) to prevent accidentally allocating so much memory that
		// the process dies.
		var spends []*BlockOutputKey
		for i := uint32(0); i < spendsCount; i++ {
			k := &BlockOutputKey{}
			tmpn64, err := k.ReadFrom(r)
			n64 += tmpn64
			if err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return n64, err
			}
			spends = append(spends, k)
		}

		t.debits = &debits{amount, spends}
	} else {
		t.debits = nil
	}

	// Read number of pointers (as a uint32) written to be read into the
	// credits slice (although some may be nil).
	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n64, err
	}
	creditsCount := byteOrder.Uint32(uint32Bytes)

	// For each expected credits slice element, check whether the credit
	// exists or the pointer is nil.  If nil, append nil to credits and
	// continue with the next.  If non-nil, allocated and read the full
	// credit structure.  This slice is originally set to nil (*not*
	// preallocated to creditsCount size) to prevent accidentally allocating
	// so much memory that the process dies.
	var credits []*credit
	for i := uint32(0); i < creditsCount; i++ {
		// Read identifer for a valid pointer.
		n, err := io.ReadFull(r, singleByte)
		n64 += int64(n)
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return n64, err
		}
		validCredit, err := byteMarksValidPointer(singleByte[0])
		if err != nil {
			return n64, err
		}

		if !validCredit {
			credits = append(credits, nil)
		} else {
			// Read single byte that specifies whether this credit
			// was added as change.
			n, err = io.ReadFull(r, singleByte)
			n64 += int64(n)
			if err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return n64, err
			}
			change, err := byteAsBool(singleByte[0])
			if err != nil {
				return n64, err
			}

			// Read single byte that specifies whether this credit
			// is locked.
			n, err = io.ReadFull(r, singleByte)
			n64 += int64(n)
			if err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return n64, err
			}
			locked, err := byteAsBool(singleByte[0])
			if err != nil {
				return n64, err
			}

			// Read identifier for a valid pointer.
			n, err = io.ReadFull(r, singleByte)
			n64 += int64(n)
			if err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return n64, err
			}
			validSpentBy, err := byteMarksValidPointer(singleByte[0])
			if err != nil {
				return n64, err
			}

			// If spentBy pointer is valid, allocate and read a
			// transaction lookup key.
			var spentBy *BlockTxKey
			if validSpentBy {
				spentBy = &BlockTxKey{}
				tmpn64, err := spentBy.ReadFrom(r)
				n64 += tmpn64
				if err != nil {
					if err == io.EOF {
						err = io.ErrUnexpectedEOF
					}
					return n64, err
				}
			}

			c := &credit{change, locked, spentBy}
			credits = append(credits, c)
		}

	}
	t.credits = credits

	// Read received unix time (int64).
	n, err = io.ReadFull(r, uint64Bytes)
	n64 += int64(n)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n64, err
	}
	received := int64(byteOrder.Uint64(uint64Bytes))
	t.received = time.Unix(received, 0)

	return n64, nil
}

func (t *txRecord) WriteTo(w io.Writer) (int64, error) {
	var buf [8]byte
	uint64Bytes := buf[:8]
	uint32Bytes := buf[:4]

	// Write transaction index (as a uint32).
	byteOrder.PutUint32(uint32Bytes, uint32(t.tx.Index()))
	n, err := w.Write(uint32Bytes)
	n64 := int64(n)
	if err != nil {
		return n64, err
	}

	// Serialize and write transaction.
	tmpn64, err := (*msgTx)(t.tx.MsgTx()).WriteTo(w)
	n64 += tmpn64
	if err != nil {
		return n64, err
	}

	// Write debit records, if any.  This begins with a single byte to
	// identify whether the record contains any debits or not.
	if t.debits == nil {
		// Write identifier for nil debits.
		n, err = w.Write([]byte{nilPointer})
		n64 += int64(n)
		if err != nil {
			return n64, err
		}
	} else {
		// Write identifier for valid debits.
		n, err = w.Write([]byte{validPointer})
		n64 += int64(n)
		if err != nil {
			return n64, err
		}

		// Write debited amount (int64).
		byteOrder.PutUint64(uint64Bytes, uint64(t.debits.amount))
		n, err := w.Write(uint64Bytes)
		n64 += int64(n)
		if err != nil {
			return n64, err
		}

		// Write number of outputs (as a uint32) this record debits
		// from.
		byteOrder.PutUint32(uint32Bytes, uint32(len(t.debits.spends)))
		n, err = w.Write(uint32Bytes)
		n64 += int64(n)
		if err != nil {
			return n64, err
		}

		// Write each lookup key for a spent transaction output.
		for _, k := range t.debits.spends {
			tmpn64, err := k.WriteTo(w)
			n64 += tmpn64
			if err != nil {
				return n64, err
			}
		}
	}

	// Write number of pointers (as a uint32) in the credits slice (although
	// some may be nil).  Then, for each element in the credits slice, write
	// an identifier whether the element is nil or valid, and if valid,
	// write the credit structure.
	byteOrder.PutUint32(uint32Bytes, uint32(len(t.credits)))
	n, err = w.Write(uint32Bytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}
	for _, c := range t.credits {
		if c == nil {
			// Write identifier for nil credit.
			n, err := w.Write([]byte{nilPointer})
			n64 += int64(n)
			if err != nil {
				return n64, err
			}
		} else {
			// Write identifier for valid credit.
			n, err := w.Write([]byte{validPointer})
			n64 += int64(n)
			if err != nil {
				return n64, err
			}

			// Write a single byte to specify whether this credit
			// was added as change.
			changeByte := falseByte
			if c.change {
				changeByte = trueByte
			}
			n, err = w.Write([]byte{changeByte})
			n64 += int64(n)
			if err != nil {
				return n64, err
			}

			// Write a single byte to specify whether this credit
			// is locked.
			lockByte := falseByte
			if c.change {
				lockByte = trueByte
			}
			n, err = w.Write([]byte{lockByte})
			n64 += int64(n)
			if err != nil {
				return n64, err
			}

			// If this credit is unspent, write an identifier for
			// an invalid pointer.  Otherwise, write the identifier
			// for a valid pointer and write the spending tx key.
			if c.spentBy == nil {
				// Write identifier for an unspent credit.
				n, err := w.Write([]byte{nilPointer})
				n64 += int64(n)
				if err != nil {
					return n64, err
				}
			} else {
				// Write identifier for an unspent credit.
				n, err := w.Write([]byte{validPointer})
				n64 += int64(n)
				if err != nil {
					return n64, err
				}

				// Write transaction lookup key.
				tmpn64, err := c.spentBy.WriteTo(w)
				n64 += tmpn64
				if err != nil {
					return n64, err
				}
			}
		}
	}

	// Write received unix time (int64).
	byteOrder.PutUint64(uint64Bytes, uint64(t.received.Unix()))
	n, err = w.Write(uint64Bytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}

	return n64, nil
}

type msgTx btcwire.MsgTx

func (tx *msgTx) ReadFrom(r io.Reader) (int64, error) {
	// Read from a TeeReader to return the number of read bytes.
	buf := new(bytes.Buffer)
	tr := io.TeeReader(r, buf)
	if err := (*btcwire.MsgTx)(tx).Deserialize(tr); err != nil {
		if buf.Len() != 0 && err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return int64(buf.Len()), err
	}

	return int64((*btcwire.MsgTx)(tx).SerializeSize()), nil
}

func (tx *msgTx) WriteTo(w io.Writer) (int64, error) {
	// Write to a buffer and then copy to w so the total number of bytes
	// written can be returned to the caller.  Writing to a to a
	// bytes.Buffer never fails except for OOM panics, so check and panic
	// on any unexpected non-nil returned errors.
	buf := new(bytes.Buffer)
	if err := (*btcwire.MsgTx)(tx).Serialize(buf); err != nil {
		panic(err)
	}
	return io.Copy(w, buf)
}

// ReadFrom reads a mined transaction output lookup key from r.  The total
// number of bytes read is returned.
func (k *BlockOutputKey) ReadFrom(r io.Reader) (int64, error) {
	var buf [4]byte
	uint32Bytes := buf[:4]

	// Read embedded BlockTxKey.
	n64, err := k.BlockTxKey.ReadFrom(r)
	if err != nil {
		return n64, err
	}

	// Read output index (uint32).
	n, err := io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n64, err
	}
	k.OutputIndex = byteOrder.Uint32(uint32Bytes)

	return n64, nil
}

// WriteTo writes a mined transaction output lookup key to w.  The total number
// of bytes written is returned.
func (k *BlockOutputKey) WriteTo(w io.Writer) (int64, error) {
	var buf [4]byte
	uint32Bytes := buf[:4]

	// Write embedded BlockTxKey.
	n64, err := k.BlockTxKey.WriteTo(w)
	if err != nil {
		return n64, err
	}

	// Write output index (uint32).
	byteOrder.PutUint32(uint32Bytes, k.OutputIndex)
	n, err := w.Write(uint32Bytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}

	return n64, nil
}

// ReadFrom reads a mined transaction lookup key from r.  The total number of
// bytes read is returned.
func (k *BlockTxKey) ReadFrom(r io.Reader) (int64, error) {
	var buf [4]byte
	uint32Bytes := buf[:4]

	// Read block index (as a uint32).
	n, err := io.ReadFull(r, uint32Bytes)
	n64 := int64(n)
	if err != nil {
		return n64, err
	}
	k.BlockIndex = int(byteOrder.Uint32(uint32Bytes))

	// Read block height (int32).
	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n64, err
	}
	k.BlockHeight = int32(byteOrder.Uint32(uint32Bytes))

	return n64, nil
}

// WriteTo writes a mined transaction lookup key to w.  The total number of
// bytes written is returned.
func (k *BlockTxKey) WriteTo(w io.Writer) (int64, error) {
	var buf [4]byte
	uint32Bytes := buf[:4]

	// Write block index (as a uint32).
	byteOrder.PutUint32(uint32Bytes, uint32(k.BlockIndex))
	n, err := w.Write(uint32Bytes)
	n64 := int64(n)
	if err != nil {
		return n64, err
	}

	// Write block height (int32).
	byteOrder.PutUint32(uint32Bytes, uint32(k.BlockHeight))
	n, err = w.Write(uint32Bytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}

	return n64, nil
}

func (u *unconfirmedStore) ReadFrom(r io.Reader) (int64, error) {
	var buf [4]byte
	uint32Bytes := buf[:4]

	// Read length (as a uint32) of transaction record key/value pairs,
	// followed by each transaction record.
	n, err := io.ReadFull(r, uint32Bytes)
	n64 := int64(n)
	if err != nil {
		return n64, err
	}
	txCount := byteOrder.Uint32(uint32Bytes)
	for i := uint32(0); i < txCount; i++ {
		t := &txRecord{}
		tmpn64, err := t.ReadFrom(r)
		n64 += tmpn64
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return n64, err
		}

		u.txs[*t.tx.Sha()] = t
	}

	// Read length (as a uint32) of key/value pairs in the
	// spentBlockOutPoints and spentBlockOutPointKeys maps, followed by the
	// outpoint, the block transaction lookup key, and the transaction hash
	// of the spending transaction record.
	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n64, err
	}
	spentBlockOutPointCount := byteOrder.Uint32(uint32Bytes)
	for i := uint32(0); i < spentBlockOutPointCount; i++ {
		// Read outpoint hash and index (uint32).
		op := btcwire.OutPoint{}
		n, err := io.ReadFull(r, op.Hash[:])
		n64 += int64(n)
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return n64, err
		}
		n, err = io.ReadFull(r, uint32Bytes)
		n64 += int64(n)
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return n64, err
		}
		op.Index = byteOrder.Uint32(uint32Bytes)

		// Read block transaction lookup key, and create the full block
		// output key from it and the previously-read outpoint index.
		opKey := BlockOutputKey{OutputIndex: op.Index}
		tmpn64, err := opKey.BlockTxKey.ReadFrom(r)
		n64 += tmpn64
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return n64, err
		}

		// Read transaction record hash and check that it was previously
		// read into the txs map.  Use full record as the map value.
		var txHash btcwire.ShaHash
		n, err = io.ReadFull(r, txHash[:])
		n64 += int64(n)
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return n64, err
		}
		t, ok := u.txs[txHash]
		if !ok {
			return n64, fmt.Errorf("missing unconfirmed "+
				"transaction record for transaction %v", txHash)
		}

		u.spentBlockOutPoints[opKey] = t
		u.spentBlockOutPointKeys[op] = opKey
	}

	// Read length (as a uint32) of key/value pairs in the spentUnconfirmed
	// map, followed by the outpoint and hash of the transaction record.
	// Use this hash as the lookup key for the full transaction record
	// previously read into the txs map.
	n, err = io.ReadFull(r, uint32Bytes)
	n64 += int64(n)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n64, err
	}
	spentUnconfirmedCount := byteOrder.Uint32(uint32Bytes)
	for i := uint32(0); i < spentUnconfirmedCount; i++ {
		// Read outpoint hash and index (uint32).
		op := btcwire.OutPoint{}
		n, err := io.ReadFull(r, op.Hash[:])
		n64 += int64(n)
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return n64, err
		}
		n, err = io.ReadFull(r, uint32Bytes)
		n64 += int64(n)
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return n64, err
		}
		op.Index = byteOrder.Uint32(uint32Bytes)

		// Read transaction record hash and check that it was previously
		// read into the txs map.  Use full record as the map value.
		var txHash btcwire.ShaHash
		n, err = io.ReadFull(r, txHash[:])
		n64 += int64(n)
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return n64, err
		}
		t, ok := u.txs[txHash]
		if !ok {
			return n64, fmt.Errorf("missing unconfirmed "+
				"transaction record for transaction %v", txHash)
		}

		u.spentUnconfirmed[op] = t
	}

	// Recreate the previousOutpoints map.  For each transaction record
	// saved in the txs map, map each previous outpoint to the record
	// itself.
	for _, t := range u.txs {
		for _, input := range t.tx.MsgTx().TxIn {
			u.previousOutpoints[input.PreviousOutpoint] = t
		}
	}

	return n64, nil
}

func (u *unconfirmedStore) WriteTo(w io.Writer) (int64, error) {
	var buf [4]byte
	uint32Bytes := buf[:4]

	// Write length of key/values pairs in txs map, followed by each
	// transaction record.
	byteOrder.PutUint32(uint32Bytes, uint32(len(u.txs)))
	n, err := w.Write(uint32Bytes)
	n64 := int64(n)
	if err != nil {
		return n64, err
	}
	for _, t := range u.txs {
		tmpn64, err := t.WriteTo(w)
		n64 += tmpn64
		if err != nil {
			return n64, err
		}
	}

	// Write length (as a uint32) of key/value pairs in the
	// spentBlockOutPoints and spentBlockOutPointKeys maps (these lengths
	// must be equal), followed by the outpoint, the block transaction
	// lookup key, and the hash of the transaction record.
	if len(u.spentBlockOutPoints) != len(u.spentBlockOutPointKeys) {
		return n64, errors.New("spent block tx maps lengths differ")
	}
	byteOrder.PutUint32(uint32Bytes, uint32(len(u.spentBlockOutPoints)))
	n, err = w.Write(uint32Bytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}
	for op, opKey := range u.spentBlockOutPointKeys {
		// Write outpoint hash and the index (uint32).
		n, err := w.Write(op.Hash[:])
		n64 += int64(n)
		if err != nil {
			return n64, err
		}
		byteOrder.PutUint32(uint32Bytes, op.Index)
		n, err = w.Write(uint32Bytes)
		n64 += int64(n)
		if err != nil {
			return n64, err
		}

		// Write the block transaction lookup key.  This is not the full
		// output key, as the index has already been serialized as part
		// of the outpoint written above.
		tmpn64, err := opKey.BlockTxKey.WriteTo(w)
		n64 += tmpn64
		if err != nil {
			return n64, err
		}

		// Lookup transaction record and write the transaction hash.
		t, ok := u.spentBlockOutPoints[opKey]
		if !ok {
			return n64, MissingCreditError(opKey)
		}
		n, err = w.Write(t.tx.Sha()[:])
		n64 += int64(n)
		if err != nil {
			return n64, err
		}
	}

	// Write length (as a uint32) of key/value pairs in the spentUnconfirmed
	// map, followed by the outpoint and hash of the transaction record.
	byteOrder.PutUint32(uint32Bytes, uint32(len(u.spentUnconfirmed)))
	n, err = w.Write(uint32Bytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}
	for op, t := range u.spentUnconfirmed {
		// Write outpoint hash and the index (uint32).
		n, err := w.Write(op.Hash[:])
		n64 += int64(n)
		if err != nil {
			return n64, err
		}
		byteOrder.PutUint32(uint32Bytes, op.Index)
		n, err = w.Write(uint32Bytes)
		n64 += int64(n)
		if err != nil {
			return n64, err
		}

		// Write transaction record hash.
		n, err = w.Write(t.tx.Sha()[:])
		n64 += int64(n)
		if err != nil {
			return n64, err
		}
	}

	// The previousOutpoints map is intentionally not written, as it can
	// be fully recreated by iterating each transaction record and adding
	// a key/value pair for each prevous outpoint.  This is performed when
	// reading the unconfirmed store.  This makes reads slightly more
	// expensive, but writing faster, and as writes are far more common in
	// application use, this was deemed to be an acceptable tradeoff.

	return n64, nil
}
