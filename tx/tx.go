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
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
	"io"
)

var (
	// ErrInvalidFormat represents an error where the expected
	// format of serialized data was not matched.
	ErrInvalidFormat = errors.New("invalid format")

	// ErrBadLength represents an error when writing a slice
	// where the length does not match the expected.
	ErrBadLength = errors.New("bad length")
)

// Byte headers prepending received and sent serialized transactions.
const (
	recvTxHeader byte = iota
	sendTxHeader
)

// ReaderFromVersion is an io.ReaderFrom and io.WriterTo that
// can specify any particular wallet file format for reading
// depending on the wallet file version.
type ReaderFromVersion interface {
	ReadFromVersion(uint32, io.Reader) (int64, error)
	io.WriterTo
}

// Various UTXO file versions.
const (
	utxoVersFirst uint32 = iota
)

// Various Tx file versions.
const (
	txVersFirst uint32 = iota

	// txVersRecvTxIndex is the version where the txout index
	// was added to the RecvTx struct.
	txVersRecvTxIndex

	// txVersMarkSentChange is the version where serialized SentTx
	// added a flags field, used for marking a sent transaction
	// as change.
	txVersMarkSentChange
)

// Current versions.
const (
	utxoVersCurrent = utxoVersFirst
	txVersCurrent   = txVersMarkSentChange
)

// UtxoStore is a type used for holding all Utxo structures for all
// addresses in a wallet.
type UtxoStore []*Utxo

// Utxo is a type storing information about a single unspent
// transaction output.
type Utxo struct {
	AddrHash  [ripemd160.Size]byte
	Out       OutPoint
	Subscript PkScript
	Amt       uint64 // Measured in Satoshis

	// Height is -1 if Utxo has not yet appeared in a block.
	Height int32

	// BlockHash is zeroed if Utxo has not yet appeared in a block.
	BlockHash btcwire.ShaHash
}

// OutPoint is a btcwire.OutPoint with custom methods for serialization.
type OutPoint btcwire.OutPoint

// PkScript is a custom type with methods to serialize pubkey scripts
// of variable length.
type PkScript []byte

// Tx is a generic type that can be used in place of either of the tx types in
// a TxStore.
type Tx interface {
	io.WriterTo
	ReadFromVersion(uint32, io.Reader) (int64, error)
	TxInfo(string, int32, btcwire.BitcoinNet) []map[string]interface{}
	GetBlockHeight() int32
	GetBlockHash() *btcwire.ShaHash
	GetBlockTime() int64
	GetTime() int64
	GetTxID() *btcwire.ShaHash
	Copy() Tx
}

// TxStore is a slice holding RecvTx and SendTx pointers.
type TxStore []Tx

const (
	addressUnknown byte = iota
	addressKnown
)

// pubkeyHash is a slice holding 20 bytes (for a known pubkey hash
// of a Bitcoin address), or nil (for an unknown address).
type pubkeyHash []byte

// Enforce that pubkeyHash satisifies the io.ReaderFrom and
// io.WriterTo interfaces.
var pubkeyHashVar = pubkeyHash([]byte{})
var _ io.ReaderFrom = &pubkeyHashVar
var _ io.WriterTo = &pubkeyHashVar

// ReadFrom satisifies the io.ReaderFrom interface.
func (p *pubkeyHash) ReadFrom(r io.Reader) (int64, error) {
	var read int64

	// Read header byte.
	header := make([]byte, 1)
	n, err := r.Read(header)
	if err != nil {
		return int64(n), err
	}
	read += int64(n)

	switch header[0] {
	case addressUnknown:
		*p = nil
		return read, nil

	case addressKnown:
		addrHash := make([]byte, ripemd160.Size)
		n, err := binaryRead(r, binary.LittleEndian, &addrHash)
		if err != nil {
			return read + int64(n), err
		}
		read += int64(n)
		*p = addrHash
		return read, nil

	default:
		return read, ErrInvalidFormat
	}
}

// WriteTo satisifies the io.WriterTo interface.
func (p *pubkeyHash) WriteTo(w io.Writer) (int64, error) {
	var written int64

	switch {
	case *p == nil:
		n, err := w.Write([]byte{addressUnknown})
		return int64(n), err

	case len(*p) == ripemd160.Size:
		// Write header.
		n, err := w.Write([]byte{addressKnown})
		if err != nil {
			return int64(n), err
		}
		written += int64(n)

		// Write hash160.
		n, err = w.Write(*p)
		if err != nil {
			return written + int64(n), err
		}
		written += int64(n)
		return written, err

	default: // bad!
		return 0, ErrBadLength
	}
}

// RecvTx is a type storing information about a transaction that was
// received by an address in a wallet.
type RecvTx struct {
	TxID         btcwire.ShaHash
	TxOutIdx     uint32
	TimeReceived int64
	BlockHeight  int32
	BlockHash    btcwire.ShaHash
	BlockIndex   int32
	BlockTime    int64
	Amount       int64 // Measured in Satoshis
	ReceiverHash pubkeyHash
}

// Pairs is a Pair slice with custom serialization and unserialization
// functions.
type Pairs []Pair

// Enforce that Pairs satisifies the io.ReaderFrom and io.WriterTo
// interfaces.
var pairsVar = Pairs([]Pair{})
var _ io.ReaderFrom = &pairsVar
var _ io.WriterTo = &pairsVar

func (p *Pairs) ReadFromVersion(vers uint32, r io.Reader) (int64, error) {
	var read int64

	nPairsBytes := make([]byte, 4) // Raw bytes for a uint32.
	n, err := r.Read(nPairsBytes)
	if err != nil {
		return int64(n), err
	}
	read += int64(n)
	nPairs := binary.LittleEndian.Uint32(nPairsBytes)
	s := make([]Pair, nPairs)

	for i := range s {
		n, err := s[i].ReadFromVersion(vers, r)
		if err != nil {
			return read + n, err
		}
		read += n
	}

	*p = s
	return read, nil
}

func (p *Pairs) ReadFrom(r io.Reader) (int64, error) {
	return p.ReadFromVersion(txVersCurrent, r)
}

// WriteTo writes a Pair slice to w.  Part of the io.WriterTo interface.
func (p *Pairs) WriteTo(w io.Writer) (int64, error) {
	var written int64

	nPairs := uint32(len(*p))
	nPairsBytes := make([]byte, 4) // Raw bytes for a uint32
	binary.LittleEndian.PutUint32(nPairsBytes, nPairs)
	n, err := w.Write(nPairsBytes)
	if err != nil {
		return int64(n), err
	}
	written += int64(n)

	s := *p
	for i := range s {
		n, err := s[i].WriteTo(w)
		if err != nil {
			return written + n, err
		}
		written += n
	}

	return written, nil
}

// Pair represents an amount paid to a single pubkey hash.  Pair includes
// custom serialization and unserialization functions by implementing the
// io.ReaderFromt and io.WriterTo interfaces.
type Pair struct {
	PubkeyHash pubkeyHash
	Amount     int64 // Measured in Satoshis
	Change     bool
}

// Enforce that Pair satisifies the io.ReaderFrom and io.WriterTo
// interfaces.
var _ io.ReaderFrom = &Pair{}
var _ io.WriterTo = &Pair{}

func (p *Pair) ReadFromVersion(vers uint32, r io.Reader) (int64, error) {
	if vers >= txVersMarkSentChange {
		// Use latest version
		return p.ReadFrom(r)
	}

	// Old version did not read flags.
	var read int64

	n, err := p.PubkeyHash.ReadFrom(r)
	if err != nil {
		return n, err
	}
	read += n

	amountBytes := make([]byte, 8) // raw bytes for a uint64
	nr, err := r.Read(amountBytes)
	if err != nil {
		return read + int64(nr), err
	}
	read += int64(nr)
	p.Amount = int64(binary.LittleEndian.Uint64(amountBytes))

	return read, nil
}

// ReadFrom reads a serialized Pair from r.  Part of the io.ReaderFrom
// interface.
func (p *Pair) ReadFrom(r io.Reader) (int64, error) {
	var read int64

	n, err := p.PubkeyHash.ReadFrom(r)
	if err != nil {
		return n, err
	}
	read += n

	amountBytes := make([]byte, 8) // raw bytes for a uint64
	nr, err := r.Read(amountBytes)
	if err != nil {
		return read + int64(nr), err
	}
	read += int64(nr)
	p.Amount = int64(binary.LittleEndian.Uint64(amountBytes))

	// Read flags.
	flags := make([]byte, 1) // raw bytes for 1 byte of flags
	nr, err = r.Read(flags)
	if err != nil {
		return read + int64(nr), err
	}
	read += int64(nr)
	p.Change = flags[0]&1<<0 == 1<<0

	return read, nil
}

// WriteTo serializes a Pair, writing it to w.  Part of the
// io.WriterTo interface.
func (p *Pair) WriteTo(w io.Writer) (int64, error) {
	var written int64

	n, err := p.PubkeyHash.WriteTo(w)
	if err != nil {
		return n, err
	}
	written += n

	amountBytes := make([]byte, 8) // raw bytes for a uint64
	binary.LittleEndian.PutUint64(amountBytes, uint64(p.Amount))
	nw, err := w.Write(amountBytes)
	if err != nil {
		return written + int64(nw), err
	}
	written += int64(nw)

	// Set and write flags.
	flags := byte(0)
	if p.Change {
		flags |= 1 << 0
	}
	flagBytes := []byte{flags}
	nw, err = w.Write(flagBytes)
	if err != nil {
		return written + int64(nw), err
	}
	written += int64(nw)

	return written, nil
}

// SendTx is a type storing information about a transaction that was
// sent by an address in a wallet.
type SendTx struct {
	TxID        btcwire.ShaHash
	Time        int64
	BlockHeight int32
	BlockHash   btcwire.ShaHash
	BlockIndex  int32
	BlockTime   int64
	Fee         int64 // Measured in Satoshis
	Receivers   Pairs
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
func (u *UtxoStore) ReadFrom(r io.Reader) (int64, error) {
	var read int64

	// Read the file version.  This is currently not used.
	versionBytes := make([]byte, 4) // bytes for a uint32
	n, err := r.Read(versionBytes)
	if err != nil {
		return int64(n), err
	}
	read = int64(n)

	for {
		// Read Utxo
		utxo := new(Utxo)
		n, err := utxo.ReadFrom(r)
		if err != nil {
			if n == 0 && err == io.EOF {
				err = nil
			}
			return read + n, err
		}
		read += n
		*u = append(*u, utxo)
	}
}

// WriteTo satisifies the io.WriterTo interface.  Each Utxo is written
// to w, prepended by a single byte header to distinguish between
// confirmed and unconfirmed outputs.
func (u *UtxoStore) WriteTo(w io.Writer) (int64, error) {
	var written int64

	// Write file version.  This is currently not used.
	versionBytes := make([]byte, 4) // bytes for a uint32
	binary.LittleEndian.PutUint32(versionBytes, utxoVersCurrent)
	n, err := w.Write(versionBytes)
	if err != nil {
		return int64(n), err
	}
	written = int64(n)

	// Write each utxo in the store.
	for _, utxo := range *u {
		// Write Utxo
		n, err := utxo.WriteTo(w)
		if err != nil {
			return written + n, err
		}
		written += n
	}

	return written, nil
}

// Insert inserts an Utxo into the store.
func (u *UtxoStore) Insert(utxo *Utxo) {
	s := *u
	defer func() {
		*u = s
	}()

	// First, iterate through all stored utxos.  If an unconfirmed utxo
	// (not present in a block) has the same outpoint as this utxo,
	// update the block height and hash.
	for i := range s {
		if bytes.Equal(s[i].Out.Hash[:], utxo.Out.Hash[:]) && s[i].Out.Index == utxo.Out.Index {
			// Fill relevant block information.
			copy(s[i].BlockHash[:], utxo.BlockHash[:])
			s[i].Height = utxo.Height
			return
		}
	}

	// After iterating through all UTXOs, it was not a duplicate or
	// change UTXO appearing in a block.  Append a new Utxo to the end.
	s = append(s, utxo)
}

// Rollback removes all utxos from and after the block specified
// by a block height and hash.
//
// Correct results rely on u being sorted by block height in
// increasing order.
func (u *UtxoStore) Rollback(height int32, hash *btcwire.ShaHash) (modified bool) {
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

// Remove removes all utxos from toRemove from a UtxoStore.  The order
// of utxos in the resulting UtxoStore is unspecified.
func (u *UtxoStore) Remove(toRemove []*Utxo) (modified bool) {
	s := *u

	m := make(map[*Utxo]bool)
	for _, utxo := range s {
		m[utxo] = true
	}

	for _, candidate := range toRemove {
		if _, ok := m[candidate]; ok {
			modified = true
		}
		delete(m, candidate)
	}

	if !modified {
		return
	}

	s = make([]*Utxo, len(m))
	i := 0
	for utxo := range m {
		s[i] = utxo
		i++
	}

	*u = s
	return
}

// ReadFrom satisifies the io.ReaderFrom interface.  A Utxo is read
// from r with the format:
//
//  AddrHash (20 bytes)
//  Out (36 bytes)
//  Subscript (varies)
//  Amt (8 bytes, little endian)
//  Height (4 bytes, little endian)
//  BlockHash (32 bytes)
func (u *Utxo) ReadFrom(r io.Reader) (n int64, err error) {
	datas := []interface{}{
		&u.AddrHash,
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
//  AddrHash (20 bytes)
//  Out (36 bytes)
//  Subscript (varies)
//  Amt (8 bytes, little endian)
//  Height (4 bytes, little endian)
//  BlockHash (32 bytes)
func (u *Utxo) WriteTo(w io.Writer) (n int64, err error) {
	datas := []interface{}{
		&u.AddrHash,
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
//  Length (4 byte, little endian)
//  ScriptBytes (Length bytes)
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
//  Length (4 byte, little endian)
//  ScriptBytes (Length bytes)
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
//  Version (4 bytes, little endian)
//  [(TxHeader (1 byte), Tx (varies in size))...]
func (txs *TxStore) ReadFrom(r io.Reader) (int64, error) {
	var read int64

	// Read the file version.
	versionBytes := make([]byte, 4) // bytes for a uint32
	n, err := r.Read(versionBytes)
	if err != nil {
		return int64(n), err
	}
	vers := binary.LittleEndian.Uint32(versionBytes)
	read += int64(n)

	store := []Tx{}
	defer func() {
		*txs = store
	}()
	for {
		// Read header
		var header byte
		n, err := binaryRead(r, binary.LittleEndian, &header)
		if err != nil {
			// io.EOF is not an error here.
			if err == io.EOF {
				err = nil
			}
			return read + n, err
		}
		read += n

		var tx Tx
		// Read tx.
		switch header {
		case recvTxHeader:
			t := new(RecvTx)
			n, err = t.ReadFromVersion(vers, r)
			if err != nil {
				return read + n, err
			}
			read += n
			tx = t

		case sendTxHeader:
			t := new(SendTx)
			n, err = t.ReadFromVersion(vers, r)
			if err != nil {
				return read + n, err
			}
			read += n
			tx = t

		default:
			return n, fmt.Errorf("unknown Tx header")
		}

		store = append(store, tx)
	}
}

// WriteTo satisifies the io.WriterTo interface.  A TxStore is written
// to w in the format:
//
//  Version (4 bytes, little endian)
//  [(TxHeader (1 byte), Tx (varies in size))...]
func (txs *TxStore) WriteTo(w io.Writer) (int64, error) {
	var written int64

	// Write file version.
	versionBytes := make([]byte, 4) // bytes for a uint32
	binary.LittleEndian.PutUint32(versionBytes, txVersCurrent)
	n, err := w.Write(versionBytes)
	if err != nil {
		return int64(n), err
	}
	written = int64(n)

	store := ([]Tx)(*txs)
	for _, tx := range store {
		// Write header for tx.
		var header byte
		switch tx.(type) {
		case *RecvTx:
			header = recvTxHeader

		case *SendTx:
			header = sendTxHeader

		default:
			return written, fmt.Errorf("unknown type in TxStore")
		}
		headerBytes := []byte{header}
		n, err := w.Write(headerBytes)
		if err != nil {
			return written + int64(n), err
		}
		written += int64(n)

		// Write tx.
		wt := tx.(io.WriterTo)
		n64, err := wt.WriteTo(w)
		if err != nil {
			return written + n64, err
		}
		written += n64
	}
	return written, nil
}

// InsertRecvTx inserts a RecvTx, checking for duplicates, and updating
// previous entries with the latest block information in tx.
func (txs *TxStore) InsertRecvTx(tx *RecvTx) {
	s := *txs
	defer func() {
		*txs = s
	}()

	// First, iterate through all stored tx history.  If a received tx
	// matches the one being added (equal txid and txout idx), update
	// it with the new block information.
	for i := range s {
		recvTx, ok := s[i].(*RecvTx)
		if !ok {
			// Can only check for equality if the types match.
			continue
		}

		// Found an identical received tx.
		if bytes.Equal(recvTx.TxID[:], tx.TxID[:]) &&
			recvTx.TxOutIdx == tx.TxOutIdx {

			// Fill relevant block information.
			copy(recvTx.BlockHash[:], tx.BlockHash[:])
			recvTx.BlockHeight = tx.BlockHeight
			recvTx.BlockIndex = tx.BlockIndex
			recvTx.BlockTime = tx.BlockTime
			return
		}
	}

	// No received tx entries with the same outpoint.  Append to the end.
	s = append(s, tx)
}

// Rollback removes all txs from and after the block specified by a
// block height and hash.
//
// Correct results rely on txs being sorted by block height in
// increasing order.
func (txs *TxStore) Rollback(height int32, hash *btcwire.ShaHash) (modified bool) {
	s := ([]Tx)(*txs)

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
		var txBlockHeight int32
		var txBlockHash *btcwire.ShaHash
		switch tx := s[i].(type) {
		case *RecvTx:
			if height > tx.BlockHeight {
				break
			}
			txBlockHeight = tx.BlockHeight
			txBlockHash = &tx.BlockHash

		case *SendTx:
			if height > tx.BlockHeight {
				break
			}
			txBlockHeight = tx.BlockHeight
			txBlockHash = &tx.BlockHash
		}
		if height == txBlockHeight && *hash == *txBlockHash {
			endlen = i
		}
	}
	return
}

func (tx *RecvTx) ReadFromVersion(vers uint32, r io.Reader) (n int64, err error) {
	if vers >= txVersCurrent {
		// Use current version.
		return tx.ReadFrom(r)
	}

	// Old file version did not save the txout index.

	datas := []interface{}{
		&tx.TxID,
		// tx index not read.
		&tx.TimeReceived,
		&tx.BlockHeight,
		&tx.BlockHash,
		&tx.BlockIndex,
		&tx.BlockTime,
		&tx.Amount,
		&tx.ReceiverHash,
	}
	var read int64
	for _, data := range datas {
		switch e := data.(type) {
		case io.ReaderFrom:
			read, err = e.ReadFrom(r)
		default:
			read, err = binaryRead(r, binary.LittleEndian, data)
		}

		if err != nil {
			return n + read, err
		}
		n += read
	}
	return n, nil
}

// ReadFrom satisifies the io.ReaderFrom interface.  A RecTx is read
// in from r with the format:
//
//  TxID (32 bytes)
//  TxOutIdx (4 bytes, little endian)
//  TimeReceived (8 bytes, little endian)
//  BlockHeight (4 bytes, little endian)
//  BlockHash (32 bytes)
//  BlockIndex (4 bytes, little endian)
//  BlockTime (8 bytes, little endian)
//  Amt (8 bytes, little endian)
//  ReceiverAddr (varies)
func (tx *RecvTx) ReadFrom(r io.Reader) (n int64, err error) {
	datas := []interface{}{
		&tx.TxID,
		&tx.TxOutIdx,
		&tx.TimeReceived,
		&tx.BlockHeight,
		&tx.BlockHash,
		&tx.BlockIndex,
		&tx.BlockTime,
		&tx.Amount,
		&tx.ReceiverHash,
	}
	var read int64
	for _, data := range datas {
		switch e := data.(type) {
		case io.ReaderFrom:
			read, err = e.ReadFrom(r)
		default:
			read, err = binaryRead(r, binary.LittleEndian, data)
		}

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
//  TxID (32 bytes)
//  TxOutIdx (4 bytes, little endian)
//  TimeReceived (8 bytes, little endian)
//  BlockHeight (4 bytes, little endian)
//  BlockHash (32 bytes)
//  BlockIndex (4 bytes, little endian)
//  BlockTime (8 bytes, little endian)
//  Amt (8 bytes, little endian)
//  ReceiverAddr (varies)
func (tx *RecvTx) WriteTo(w io.Writer) (n int64, err error) {
	datas := []interface{}{
		&tx.TxID,
		&tx.TxOutIdx,
		&tx.TimeReceived,
		&tx.BlockHeight,
		&tx.BlockHash,
		&tx.BlockIndex,
		&tx.BlockTime,
		&tx.Amount,
		&tx.ReceiverHash,
	}
	var written int64
	for _, data := range datas {
		switch e := data.(type) {
		case io.WriterTo:
			written, err = e.WriteTo(w)
		default:
			written, err = binaryWrite(w, binary.LittleEndian, data)
		}

		if err != nil {
			return n + written, err
		}
		n += written
	}
	return n, nil
}

// TxInfo returns a slice of maps that may be marshaled as a JSON array
// of JSON objects for a listtransactions RPC reply.
func (tx *RecvTx) TxInfo(account string, curheight int32,
	net btcwire.BitcoinNet) []map[string]interface{} {

	address := "Unknown"
	addr, err := btcutil.NewAddressPubKeyHash(tx.ReceiverHash, net)
	if err == nil {
		address = addr.String()
	}

	txInfo := map[string]interface{}{
		"category":     "receive",
		"account":      account,
		"address":      address,
		"amount":       float64(tx.Amount) / float64(btcutil.SatoshiPerBitcoin),
		"txid":         tx.TxID.String(),
		"timereceived": tx.TimeReceived,
	}

	if tx.BlockHeight != -1 {
		txInfo["blockhash"] = tx.BlockHash.String()
		txInfo["blockindex"] = tx.BlockIndex
		txInfo["blocktime"] = tx.BlockTime
		txInfo["confirmations"] = curheight - tx.BlockHeight + 1
	} else {
		txInfo["confirmations"] = 0
	}

	return []map[string]interface{}{txInfo}
}

// GetBlockHeight returns the current blockheight of the transaction,
// implementing the Tx interface.
func (tx *RecvTx) GetBlockHeight() int32 {
	return tx.BlockHeight
}

// GetBlockHash return the current blockhash of thet transaction, implementing
// the Tx interface.
func (tx *RecvTx) GetBlockHash() *btcwire.ShaHash {
	return &tx.BlockHash
}

// GetBlockTime returns the current block time of the transaction, implementing
// the Tx interface.
func (tx *RecvTx) GetBlockTime() int64 {
	return tx.BlockTime
}

// GetTime returns the current ID of the transaction, implementing the Tx
// interface.
func (tx *RecvTx) GetTime() int64 {
	return tx.TimeReceived
}

// GetTxID returns the current ID of the transaction, implementing the Tx
// interface.
func (tx *RecvTx) GetTxID() *btcwire.ShaHash {
	return &tx.TxID
}

// Copy returns a deep copy of the structure, implementing the Tx interface..
func (tx *RecvTx) Copy() Tx {
	copyTx := *tx

	return &copyTx
}

func (tx *SendTx) ReadFromVersion(vers uint32, r io.Reader) (n int64, err error) {
	var read int64

	datas := []interface{}{
		&tx.TxID,
		&tx.Time,
		&tx.BlockHeight,
		&tx.BlockHash,
		&tx.BlockIndex,
		&tx.BlockTime,
		&tx.Fee,
		&tx.Receivers,
	}
	for _, data := range datas {
		switch e := data.(type) {
		case ReaderFromVersion:
			read, err = e.ReadFromVersion(vers, r)

		case io.ReaderFrom:
			read, err = e.ReadFrom(r)

		default:
			read, err = binaryRead(r, binary.LittleEndian, data)
		}

		if err != nil {
			return n + read, err
		}
		n += read
	}

	return n, nil
}

// ReadFrom satisifies the io.WriterTo interface.  A SendTx is read
// from r with the format:
//
//  TxID (32 bytes)
//  Time (8 bytes, little endian)
//  BlockHeight (4 bytes, little endian)
//  BlockHash (32 bytes)
//  BlockIndex (4 bytes, little endian)
//  BlockTime (8 bytes, little endian)
//  Fee (8 bytes, little endian)
//  Receivers (varies)
func (tx *SendTx) ReadFrom(r io.Reader) (n int64, err error) {
	return tx.ReadFromVersion(txVersCurrent, r)
}

// WriteTo satisifies the io.WriterTo interface.  A SendTx is written to
// w in the format:
//
//  TxID (32 bytes)
//  Time (8 bytes, little endian)
//  BlockHeight (4 bytes, little endian)
//  BlockHash (32 bytes)
//  BlockIndex (4 bytes, little endian)
//  BlockTime (8 bytes, little endian)
//  Fee (8 bytes, little endian)
//  Receivers (varies)
func (tx *SendTx) WriteTo(w io.Writer) (n int64, err error) {
	var written int64

	datas := []interface{}{
		&tx.TxID,
		&tx.Time,
		&tx.BlockHeight,
		&tx.BlockHash,
		&tx.BlockIndex,
		&tx.BlockTime,
		&tx.Fee,
		&tx.Receivers,
	}
	for _, data := range datas {
		switch e := data.(type) {
		case io.WriterTo:
			written, err = e.WriteTo(w)
		default:
			written, err = binaryWrite(w, binary.LittleEndian, data)
		}

		if err != nil {
			return n + written, err
		}
		n += written
	}

	return n, nil
}

// TxInfo returns a slice of maps that may be marshaled as a JSON array
// of JSON objects for a listtransactions RPC reply.
func (tx *SendTx) TxInfo(account string, curheight int32,
	net btcwire.BitcoinNet) []map[string]interface{} {

	reply := make([]map[string]interface{}, len(tx.Receivers))

	var confirmations int32
	if tx.BlockHeight != -1 {
		confirmations = curheight - tx.BlockHeight + 1
	}

	// error is ignored since the length will always be correct.
	txID, _ := btcwire.NewShaHash(tx.TxID[:])
	txIDStr := txID.String()

	// error is ignored since the length will always be correct.
	blockHash, _ := btcwire.NewShaHash(tx.BlockHash[:])
	blockHashStr := blockHash.String()

	for i, pair := range tx.Receivers {
		address := "Unknown"
		addr, err := btcutil.NewAddressPubKeyHash(pair.PubkeyHash, net)
		if err == nil {
			address = addr.String()
		}
		info := map[string]interface{}{
			"account":       account,
			"address":       address,
			"category":      "send",
			"amount":        float64(-pair.Amount) / float64(btcutil.SatoshiPerBitcoin),
			"fee":           float64(tx.Fee) / float64(btcutil.SatoshiPerBitcoin),
			"confirmations": confirmations,
			"txid":          txIDStr,
			"time":          tx.Time,
			"timereceived":  tx.Time,
		}
		if tx.BlockHeight != -1 {
			info["blockhash"] = blockHashStr
			info["blockindex"] = tx.BlockIndex
			info["blocktime"] = tx.BlockTime
		}
		reply[i] = info
	}

	return reply
}

// GetBlockHeight returns the current blockheight of the transaction,
// implementing the Tx interface.
func (tx *SendTx) GetBlockHeight() int32 {
	return tx.BlockHeight
}

// GetBlockHash return the current blockhash of thet transaction, implementing
// the Tx interface.
func (tx *SendTx) GetBlockHash() *btcwire.ShaHash {
	return &tx.BlockHash
}

// GetBlockTime returns the current block time of the transaction, implementing
// the Tx interface.
func (tx *SendTx) GetBlockTime() int64 {
	return tx.BlockTime
}

// GetTime returns the current ID of the transaction, implementing the Tx
// interface.
func (tx *SendTx) GetTime() int64 {
	return tx.Time
}

// GetTxID returns the current ID of the transaction, implementing the Tx
// interface.
func (tx *SendTx) GetTxID() *btcwire.ShaHash {
	return &tx.TxID
}

// Copy returns a deep copy of the structure, implementing the Tx interface..
func (tx *SendTx) Copy() Tx {
	copyTx := *tx

	return &copyTx
}
