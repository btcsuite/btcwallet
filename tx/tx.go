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
	"container/list"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
)

var (
	// ErrInvalidFormat represents an error where the expected
	// format of serialized data was not matched.
	ErrInvalidFormat = errors.New("invalid format")

	// ErrBadLength represents an error when writing a slice
	// where the length does not match the expected.
	ErrBadLength = errors.New("bad length")

	// ErrUnsupportedVersion represents an error where a serialized
	// object is marked with a version that is no longer supported
	// during deserialization.
	ErrUnsupportedVersion = errors.New("version no longer supported")

	// ErrInconsistantStore represents an error for when an inconsistancy
	// is detected during inserting or returning transaction records.
	ErrInconsistantStore = errors.New("inconsistant transaction store")
)

// Record is a common interface shared by SignedTx and RecvTxOut transaction
// store records.
type Record interface {
	Block() *BlockDetails
	Height() int32
	Time() time.Time
	Tx() *btcutil.Tx
	TxSha() *btcwire.ShaHash
	TxInfo(string, int32, btcwire.BitcoinNet) []map[string]interface{}
}

type txRecord interface {
	Block() *BlockDetails
	Height() int32
	Time() time.Time
	TxSha() *btcwire.ShaHash
	record(store *Store) Record
	blockTx() blockTx
	setBlock(*BlockDetails)
	readFrom(io.Reader) (int64, error)
	writeTo(io.Writer) (int64, error)
}

func sortedInsert(l *list.List, tx txRecord) {
	for e := l.Back(); e != nil; e = e.Prev() {
		v := e.Value.(txRecord)
		if !v.Time().After(tx.Time()) { // equal or before
			l.InsertAfter(tx, e)
			return
		}
	}

	// No list elements, or all previous elements come after the date of tx.
	l.PushFront(tx)
}

type blockTx struct {
	txSha  btcwire.ShaHash
	height int32
}

func (btx *blockTx) readFrom(r io.Reader) (int64, error) {
	// Read txsha
	n, err := io.ReadFull(r, btx.txSha[:])
	n64 := int64(n)
	if err != nil {
		return n64, err
	}

	// Read height
	heightBytes := make([]byte, 4)
	n, err = io.ReadFull(r, heightBytes)
	n64 += int64(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return n64, err
	}
	btx.height = int32(binary.LittleEndian.Uint32(heightBytes))

	return n64, nil
}

func (btx *blockTx) writeTo(w io.Writer) (int64, error) {
	// Write txsha
	n, err := w.Write(btx.txSha[:])
	n64 := int64(n)
	if err != nil {
		return n64, err
	}

	// Write height
	heightBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(heightBytes, uint32(btx.height))
	n, err = w.Write(heightBytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}

	return n64, nil
}

type blockOutPoint struct {
	op     btcwire.OutPoint
	height int32
}

// Store implements a transaction store for storing and managing wallet
// transactions.
type Store struct {
	txs     map[blockTx]*btcutil.Tx // all backing transactions referenced by records
	sorted  *list.List              // ordered (by date) list of all wallet tx records
	signed  map[blockTx]*signedTx
	recv    map[blockOutPoint]*recvTxOut
	unspent map[btcwire.OutPoint]*recvTxOut
}

// NewStore allocates and initializes a new transaction store.
func NewStore() *Store {
	store := Store{
		txs:     make(map[blockTx]*btcutil.Tx),
		sorted:  list.New(),
		signed:  make(map[blockTx]*signedTx),
		recv:    make(map[blockOutPoint]*recvTxOut),
		unspent: make(map[btcwire.OutPoint]*recvTxOut),
	}
	return &store
}

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

	// versCurrent is the current tx file version.
	versCurrent = versCombined
)

// Serializing a Store results in writing three basic groups of
// data: backing txs (which are needed for the other two groups),
// received transaction outputs (both spent and unspent), and
// signed (or sent) transactions which spend previous outputs.
// These are the byte headers prepending each type.
const (
	backingTxHeader byte = iota
	recvTxOutHeader
	signedTxHeader
)

// ReadFrom satisifies the io.ReaderFrom interface by deserializing a
// transaction from an io.Reader.
func (s *Store) ReadFrom(r io.Reader) (int64, error) {
	// Read current file version.
	uint32Bytes := make([]byte, 4)
	n, err := io.ReadFull(r, uint32Bytes)
	n64 := int64(n)
	if err != nil {
		return n64, err
	}
	vers := binary.LittleEndian.Uint32(uint32Bytes)

	// Reading files with versions before versCombined is unsupported.
	if vers < versCombined {
		return n64, ErrUnsupportedVersion
	}

	// Reset store.
	s.txs = make(map[blockTx]*btcutil.Tx)
	s.sorted = list.New()
	s.signed = make(map[blockTx]*signedTx)
	s.recv = make(map[blockOutPoint]*recvTxOut)
	s.unspent = make(map[btcwire.OutPoint]*recvTxOut)

	// Read backing transactions and records.
	for {
		// Read byte header.  If this errors with io.EOF, we're done.
		header := make([]byte, 1)
		n, err = io.ReadFull(r, header)
		n64 += int64(n)
		if err == io.EOF {
			return n64, nil
		}

		switch header[0] {
		case backingTxHeader:
			// Read block height.
			n, err = io.ReadFull(r, uint32Bytes)
			n64 += int64(n)
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			if err != nil {
				return n64, err
			}
			height := int32(binary.LittleEndian.Uint32(uint32Bytes))

			// Read serialized transaction.
			tx := new(msgTx)
			txN, err := tx.readFrom(r)
			n64 += txN
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			if err != nil {
				return n64, err
			}

			// Add backing tx to store.
			utx := btcutil.NewTx((*btcwire.MsgTx)(tx))
			s.txs[blockTx{*utx.Sha(), height}] = utx

		case recvTxOutHeader:
			// Read received transaction output record.
			rtx := new(recvTxOut)
			txN, err := rtx.readFrom(r)
			n64 += txN
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			if err != nil {
				return n64, err
			}

			// It is an error for the backing transaction to have
			// not already been read.
			if _, ok := s.txs[rtx.blockTx()]; !ok {
				return n64, ErrInconsistantStore
			}

			// Add entries to store.
			s.sorted.PushBack(rtx)
			k := blockOutPoint{rtx.outpoint, rtx.Height()}
			s.recv[k] = rtx
			if !rtx.Spent() {
				s.unspent[rtx.outpoint] = rtx
			}

		case signedTxHeader:
			// Read signed (sent) transaction record.
			stx := new(signedTx)
			txN, err := stx.readFrom(r)
			n64 += txN
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			if err != nil {
				return n64, err
			}

			// It is an error for the backing transaction to have
			// not already been read.
			if _, ok := s.txs[stx.blockTx()]; !ok {
				return n64, ErrInconsistantStore
			}

			// Add entries to store.
			s.sorted.PushBack(stx)
			s.signed[stx.blockTx()] = stx

		default:
			return n64, errors.New("bad magic byte")
		}
	}

	return n64, nil
}

// WriteTo satisifies the io.WriterTo interface by serializing a transaction
// store to an io.Writer.
func (s *Store) WriteTo(w io.Writer) (int64, error) {
	// Write current file version.
	uint32Bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(uint32Bytes, versCurrent)
	n, err := w.Write(uint32Bytes)
	n64 := int64(n)
	if err != nil {
		return n64, err
	}

	// Write all backing transactions.
	for btx, tx := range s.txs {
		// Write backing tx header.
		n, err = w.Write([]byte{backingTxHeader})
		n64 += int64(n)
		if err != nil {
			return n64, err
		}

		// Write block height.
		binary.LittleEndian.PutUint32(uint32Bytes, uint32(btx.height))
		n, err = w.Write(uint32Bytes)
		n64 += int64(n)
		if err != nil {
			return n64, err
		}

		// Write serialized transaction
		txN, err := (*msgTx)(tx.MsgTx()).writeTo(w)
		n64 += txN
		if err != nil {
			return n64, err
		}
	}

	// Write each record.  The byte header is dependant on the
	// underlying type.
	for e := s.sorted.Front(); e != nil; e = e.Next() {
		v := e.Value.(txRecord)
		switch v.(type) {
		case *recvTxOut:
			n, err = w.Write([]byte{recvTxOutHeader})
		case *signedTx:
			n, err = w.Write([]byte{signedTxHeader})
		}
		n64 += int64(n)
		if err != nil {
			return n64, err
		}

		recordN, err := v.writeTo(w)
		n64 += recordN
		if err != nil {
			return n64, err
		}
	}

	return n64, nil
}

// InsertSignedTx inserts a signed-by-wallet transaction record into the
// store, returning the record.  Duplicates and double spend correction is
// handled automatically.  Transactions may be added without block details,
// and later added again with block details once the tx has been mined.
func (s *Store) InsertSignedTx(tx *btcutil.Tx, created time.Time,
	block *BlockDetails) (*SignedTx, error) {

	// Partially create the signedTx.  Everything is set except the
	// total btc input, which is set below.
	st := &signedTx{
		txSha:   *tx.Sha(),
		created: created,
		block:   block,
	}

	err := s.insertTx(tx, st)
	if err != nil {
		return nil, ErrInconsistantStore
	}
	return st.record(s).(*SignedTx), nil
}

// Rollback removes block details for all transactions at or beyond a
// removed block at a given blockchain height.  Any updated
// transactions are considered unmined.  Now-invalid transactions are
// removed as new transactions creating double spends in the new better
// chain are added to the store.
func (s *Store) Rollback(height int32) {
	for e := s.sorted.Front(); e != nil; e = e.Next() {
		record := e.Value.(txRecord)
		block := record.Block()
		if block == nil {
			// Unmined, no block details to remove.
			continue
		}
		txSha := record.TxSha()
		if block.Height >= height {
			oldKey := blockTx{*txSha, block.Height}
			record.setBlock(nil)

			switch v := record.(type) {
			case *signedTx:
				k := oldKey
				delete(s.signed, k)
				k.height = -1
				s.signed[k] = v

			case *recvTxOut:
				k := blockOutPoint{v.outpoint, block.Height}
				delete(s.recv, k)
				k.height = -1
				s.recv[k] = v
			}

			if utx, ok := s.txs[oldKey]; ok {
				k := oldKey
				delete(s.txs, k)
				k.height = -1
				s.txs[k] = utx
			}
		}
	}
}

// UnminedSignedTxs returns the underlying transactions for all
// signed-by-wallet transactions which are not known to have been
// mined in a block.
func (s *Store) UnminedSignedTxs() []*btcutil.Tx {
	unmined := make([]*btcutil.Tx, 0, len(s.signed))
	for _, stx := range s.signed {
		if stx.block == nil {
			unmined = append(unmined, s.txs[stx.blockTx()])
		}
	}
	return unmined
}

// InsertRecvTxOut inserts a received transaction output record into the store,
// returning the record.  Duplicates and double spend correction is handled
// automatically.  Outputs may be added with block=nil, and then added again
// with non-nil BlockDetails to update the record and all other records
// using the transaction with the block.
func (s *Store) InsertRecvTxOut(tx *btcutil.Tx, outIdx uint32,
	change bool, received time.Time, block *BlockDetails) (*RecvTxOut, error) {

	rt := &recvTxOut{
		outpoint: *btcwire.NewOutPoint(tx.Sha(), outIdx),
		change:   change,
		received: received,
		block:    block,
	}
	err := s.insertTx(tx, rt)
	if err != nil {
		return nil, err
	}
	return rt.record(s).(*RecvTxOut), nil
}

func (s *Store) insertTx(utx *btcutil.Tx, record txRecord) error {
	if ds := s.findDoubleSpend(utx); ds != nil {
		switch {
		case ds.txSha == *utx.Sha(): // identical tx
			if ds.height != record.Height() {
				// Detect insert inconsistancies.  If matching
				// tx was found, but this record's block is unset,
				// a rollback was missed.
				block := record.Block()
				if block == nil {
					return ErrInconsistantStore
				}
				s.setTxBlock(utx.Sha(), block)
				return nil
			}

		default:
			// Double-spend or mutation.  Both are handled the same
			// (remove any now-invalid entries), and then insert the
			// new record.
			s.removeDoubleSpends(ds)
		}
	}

	s.insertUniqueTx(utx, record)
	return nil
}

func (s *Store) insertUniqueTx(utx *btcutil.Tx, record txRecord) {
	k := blockTx{*utx.Sha(), record.Height()}
	s.txs[k] = utx

	switch e := record.(type) {
	case *signedTx:
		if _, ok := s.signed[k]; ok {
			// Avoid adding a duplicate.
			return
		}

		// All the inputs should be currently unspent.  Tally the total
		// input from each, and mark as spent.
		for _, txin := range utx.MsgTx().TxIn {
			op := txin.PreviousOutpoint
			if rt, ok := s.unspent[op]; ok {
				tx := s.txs[rt.blockTx()]
				e.totalIn += tx.MsgTx().TxOut[op.Index].Value
				rt.spentBy = &k
				delete(s.unspent, txin.PreviousOutpoint)
			}
		}
		s.signed[k] = e

	case *recvTxOut:
		blockOP := blockOutPoint{e.outpoint, record.Height()}
		if _, ok := s.recv[blockOP]; ok {
			// Avoid adding a duplicate.
			return
		}

		s.recv[blockOP] = e
		s.unspent[e.outpoint] = e // all recv'd txouts are added unspent
	}

	sortedInsert(s.sorted, record)
}

// doubleSpend checks all inputs between transaction a and b, returning true
// if any two inputs share the same previous outpoint.
func doubleSpend(a, b *btcwire.MsgTx) bool {
	ain := make(map[btcwire.OutPoint]struct{})
	for i := range a.TxIn {
		ain[a.TxIn[i].PreviousOutpoint] = struct{}{}
	}
	for i := range b.TxIn {
		if _, ok := ain[b.TxIn[i].PreviousOutpoint]; ok {
			return true
		}
	}
	return false
}

func (s *Store) findDoubleSpend(tx *btcutil.Tx) *blockTx {
	// This MUST seach the ordered record list in in reverse order to
	// find the double spends of the most recent matching outpoint, as
	// spending the same outpoint is legal provided a previous transaction
	// output with an equivalent transaction sha is fully spent.
	for e := s.sorted.Back(); e != nil; e = e.Prev() {
		record := e.Value.(txRecord)
		storeTx := record.record(s).Tx()
		if doubleSpend(tx.MsgTx(), storeTx.MsgTx()) {
			btx := record.blockTx()
			return &btx
		}
	}
	return nil
}

func (s *Store) removeDoubleSpendsFromMaps(oldKey *blockTx, removed map[blockTx]struct{}) {
	// Lookup old backing tx.
	tx := s.txs[*oldKey]

	// Lookup a signed tx record.  If found, remove it and mark the map
	// removal.
	if _, ok := s.signed[*oldKey]; ok {
		delete(s.signed, *oldKey)
		removed[*oldKey] = struct{}{}
	}

	// For each old txout, if a received txout record exists, remove it.
	// If the txout has been spent, the spending tx is invalid as well, so
	// all entries for it are removed as well.
	for i := range tx.MsgTx().TxOut {
		blockOP := blockOutPoint{
			op:     *btcwire.NewOutPoint(&oldKey.txSha, uint32(i)),
			height: oldKey.height,
		}
		if rtx, ok := s.recv[blockOP]; ok {
			delete(s.recv, blockOP)
			delete(s.unspent, blockOP.op)
			removed[*oldKey] = struct{}{}

			if rtx.spentBy != nil {
				s.removeDoubleSpendsFromMaps(rtx.spentBy, removed)
			}
		}
	}

	// Remove old backing tx.
	delete(s.txs, *oldKey)
}

func (s *Store) removeDoubleSpends(oldKey *blockTx) {
	// Keep a set of block transactions for all removed entries.  This is
	// used to remove all dead records from the sorted linked list.
	removed := make(map[blockTx]struct{})

	// Remove entries from store maps.
	s.removeDoubleSpendsFromMaps(oldKey, removed)

	// Remove any record with a matching block transaction from the sorted
	// record linked list.
	var enext *list.Element
	for e := s.sorted.Front(); e != nil; e = enext {
		enext = e.Next()
		record := e.Value.(txRecord)
		if _, ok := removed[record.blockTx()]; ok {
			s.sorted.Remove(e)
		}
	}
}

func (s *Store) setTxBlock(txSha *btcwire.ShaHash, block *BlockDetails) {
	// Lookup unmined backing tx.
	prevKey := blockTx{*txSha, -1}
	tx := s.txs[prevKey]

	// Lookup a signed tx record.  If found, modify the record to
	// set the block and update the store key.
	if stx, ok := s.signed[prevKey]; ok {
		stx.setBlock(block)
		delete(s.signed, prevKey)
		s.signed[stx.blockTx()] = stx
	}

	// For each txout, if a recveived txout record exists, modify
	// the record to set the block and update the store key.
	for txOutIndex := range tx.MsgTx().TxOut {
		op := btcwire.NewOutPoint(txSha, uint32(txOutIndex))
		prevKey := blockOutPoint{*op, -1}
		if rtx, ok := s.recv[prevKey]; ok {
			rtx.setBlock(block)
			delete(s.recv, prevKey)
			newKey := blockOutPoint{*op, rtx.Height()}
			s.recv[newKey] = rtx
		}
	}

	// Switch out keys for the backing tx map.
	delete(s.txs, prevKey)
	newKey := blockTx{*txSha, block.Height}
	s.txs[newKey] = tx
}

// UnspentOutputs returns all unspent received transaction outputs.
// The order is undefined.
func (s *Store) UnspentOutputs() []*RecvTxOut {
	unspent := make([]*RecvTxOut, 0, len(s.unspent))
	for _, record := range s.unspent {
		unspent = append(unspent, record.record(s).(*RecvTxOut))
	}
	return unspent
}

// confirmed checks whether a transaction at height txHeight has met
// minConf confirmations for a blockchain at height chainHeight.
func confirmed(minConf int, txHeight, chainHeight int32) bool {
	if minConf == 0 {
		return true
	}
	if txHeight != -1 && int(chainHeight-txHeight+1) >= minConf {
		return true
	}
	return false
}

// Balance returns a wallet balance (total value of all unspent
// transaction outputs) given a minimum of minConf confirmations,
// calculated at a current chain height of curHeight.  The balance is
// returned in units of satoshis.
func (s *Store) Balance(minConf int, chainHeight int32) int64 {
	bal := int64(0)
	for _, rt := range s.unspent {
		if confirmed(minConf, rt.Height(), chainHeight) {
			tx := s.txs[rt.blockTx()]
			msgTx := tx.MsgTx()
			txOut := msgTx.TxOut[rt.outpoint.Index]
			bal += txOut.Value
		}
	}
	return bal
}

// SortedRecords returns a chronologically-ordered slice of Records.
func (s *Store) SortedRecords() []Record {
	records := make([]Record, 0, s.sorted.Len())
	for e := s.sorted.Front(); e != nil; e = e.Next() {
		record := e.Value.(txRecord)
		records = append(records, record.record(s))
	}
	return records
}

type msgTx btcwire.MsgTx

func (tx *msgTx) readFrom(r io.Reader) (int64, error) {
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

func (tx *msgTx) writeTo(w io.Writer) (int64, error) {
	// Write to a buffer and then copy to w so the total number
	// of bytes written can be returned to the caller.  Writing
	// to a bytes.Buffer never fails except for OOM, so omit the
	// serialization error check.
	buf := new(bytes.Buffer)
	(*btcwire.MsgTx)(tx).Serialize(buf)
	return io.Copy(w, buf)
}

type signedTx struct {
	txSha   btcwire.ShaHash
	created time.Time
	totalIn int64
	block   *BlockDetails // nil if unmined
}

func (st *signedTx) blockTx() blockTx {
	return blockTx{st.txSha, st.Height()}
}

func (st *signedTx) readFrom(r io.Reader) (int64, error) {
	// Fill in calculated fields with serialized data on success.
	var err error
	defer func() {
		if err != nil {
			return
		}
	}()

	// Read txSha
	n, err := io.ReadFull(r, st.txSha[:])
	n64 := int64(n)
	if err != nil {
		return n64, err
	}

	// Read creation time
	timeBytes := make([]byte, 8)
	n, err = io.ReadFull(r, timeBytes)
	n64 += int64(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return n64, err
	}
	st.created = time.Unix(int64(binary.LittleEndian.Uint64(timeBytes)), 0)

	// Read total BTC in
	totalInBytes := make([]byte, 8)
	n, err = io.ReadFull(r, totalInBytes)
	n64 += int64(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return n64, err
	}
	st.totalIn = int64(binary.LittleEndian.Uint64(totalInBytes))

	// Read flags
	flagByte := make([]byte, 1)
	n, err = io.ReadFull(r, flagByte)
	n64 += int64(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return n64, err
	}
	flags := flagByte[0]

	// Read block details if specified in flags
	if flags&(1<<0) != 0 {
		st.block = new(BlockDetails)
		n, err := st.block.readFrom(r)
		n64 += n
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			return n64, err
		}
	} else {
		st.block = nil
	}

	return n64, nil
}

func (st *signedTx) writeTo(w io.Writer) (int64, error) {
	// Write txSha
	n, err := w.Write(st.txSha[:])
	n64 := int64(n)
	if err != nil {
		return n64, err
	}

	// Write creation time
	timeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timeBytes, uint64(st.created.Unix()))
	n, err = w.Write(timeBytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}

	// Write total BTC in
	totalInBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(totalInBytes, uint64(st.totalIn))
	n, err = w.Write(totalInBytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}

	// Create and write flags
	var flags byte
	if st.block != nil {
		flags |= 1 << 0
	}
	n, err = w.Write([]byte{flags})
	n64 += int64(n)
	if err != nil {
		return n64, err
	}

	// Write block details if set
	if st.block != nil {
		n, err := st.block.writeTo(w)
		n64 += n
		if err != nil {
			return n64, err
		}
	}

	return n64, nil
}

func (st *signedTx) TxSha() *btcwire.ShaHash {
	return &st.txSha
}

func (st *signedTx) Time() time.Time {
	return st.created
}

func (st *signedTx) setBlock(details *BlockDetails) {
	st.block = details
}

func (st *signedTx) Block() *BlockDetails {
	return st.block
}

// Height returns the blockchain height of the transaction.  If the
// transaction is unmined, this returns -1.
func (st *signedTx) Height() int32 {
	height := int32(-1)
	if st.block != nil {
		height = st.block.Height
	}
	return height
}

// TotalSent returns the total number of satoshis spent by all transaction
// inputs.
func (st *signedTx) TotalSent() int64 {
	return st.totalIn
}

func (st *signedTx) record(s *Store) Record {
	tx := s.txs[st.blockTx()]

	totalOut := int64(0)
	for _, txOut := range tx.MsgTx().TxOut {
		totalOut += txOut.Value
	}

	record := &SignedTx{
		signedTx: *st,
		tx:       tx,
		fee:      st.totalIn - totalOut,
	}
	return record
}

// SignedTx is a type representing a transaction partially or fully signed
// by wallet keys.
type SignedTx struct {
	signedTx
	tx  *btcutil.Tx
	fee int64
}

// Fee returns the fee (total inputs - total outputs) of the transaction.
func (st *SignedTx) Fee() int64 {
	return st.fee
}

// Tx returns the underlying transaction managed by the store.
func (st *SignedTx) Tx() *btcutil.Tx {
	return st.tx
}

// TxInfo returns a slice of maps that may be marshaled as a JSON array
// of JSON objects for a listtransactions RPC reply.
func (st *SignedTx) TxInfo(account string, chainHeight int32, net btcwire.BitcoinNet) []map[string]interface{} {
	reply := make([]map[string]interface{}, len(st.tx.MsgTx().TxOut))

	var confirmations int32
	if st.block != nil {
		confirmations = chainHeight - st.block.Height + 1
	}

	for i, txout := range st.tx.MsgTx().TxOut {
		address := "Unknown"
		_, addrs, _, _ := btcscript.ExtractPkScriptAddrs(txout.PkScript, net)
		if len(addrs) == 1 {
			address = addrs[0].EncodeAddress()
		}
		info := map[string]interface{}{
			"account":       account,
			"address":       address,
			"category":      "send",
			"amount":        float64(-txout.Value) / float64(btcutil.SatoshiPerBitcoin),
			"fee":           float64(st.Fee()) / float64(btcutil.SatoshiPerBitcoin),
			"confirmations": float64(confirmations),
			"txid":          st.txSha.String(),
			"time":          float64(st.created.Unix()),
			"timereceived":  float64(st.created.Unix()),
		}
		if st.block != nil {
			info["blockhash"] = st.block.Hash.String()
			info["blockindex"] = float64(st.block.Index)
			info["blocktime"] = float64(st.block.Time.Unix())
		}
		reply[i] = info
	}

	return reply
}

// BlockDetails holds details about a transaction contained in a block.
type BlockDetails struct {
	Height int32
	Hash   btcwire.ShaHash
	Index  int32
	Time   time.Time
}

func (block *BlockDetails) readFrom(r io.Reader) (int64, error) {
	// Read height
	heightBytes := make([]byte, 4)
	n, err := io.ReadFull(r, heightBytes)
	n64 := int64(n)
	if err != nil {
		return n64, err
	}
	block.Height = int32(binary.LittleEndian.Uint32(heightBytes))

	// Read hash
	n, err = io.ReadFull(r, block.Hash[:])
	n64 += int64(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return n64, err
	}

	// Read index
	indexBytes := make([]byte, 4)
	n, err = io.ReadFull(r, indexBytes)
	n64 += int64(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return n64, err
	}
	block.Index = int32(binary.LittleEndian.Uint32(indexBytes))

	// Read unix time
	timeBytes := make([]byte, 8)
	n, err = io.ReadFull(r, timeBytes)
	n64 += int64(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return n64, err
	}
	block.Time = time.Unix(int64(binary.LittleEndian.Uint64(timeBytes)), 0)

	return n64, err
}

func (block *BlockDetails) writeTo(w io.Writer) (int64, error) {
	// Write height
	heightBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(heightBytes, uint32(block.Height))
	n, err := w.Write(heightBytes)
	n64 := int64(n)
	if err != nil {
		return n64, err
	}

	// Write hash
	n, err = w.Write(block.Hash[:])
	n64 += int64(n)
	if err != nil {
		return n64, err
	}

	// Write index
	indexBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(indexBytes, uint32(block.Index))
	n, err = w.Write(indexBytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}

	// Write unix time
	timeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timeBytes, uint64(block.Time.Unix()))
	n, err = w.Write(timeBytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}

	return n64, nil
}

type recvTxOut struct {
	outpoint btcwire.OutPoint
	change   bool
	locked   bool
	received time.Time
	block    *BlockDetails // nil if unmined
	spentBy  *blockTx      // nil if unspent
}

func (rt *recvTxOut) blockTx() blockTx {
	return blockTx{rt.outpoint.Hash, rt.Height()}
}

func (rt *recvTxOut) readFrom(r io.Reader) (int64, error) {
	// Read outpoint (Sha, index)
	n, err := io.ReadFull(r, rt.outpoint.Hash[:])
	n64 := int64(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return n64, err
	}
	indexBytes := make([]byte, 4)
	n, err = io.ReadFull(r, indexBytes)
	n64 += int64(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return n64, err
	}
	rt.outpoint.Index = binary.LittleEndian.Uint32(indexBytes)

	// Read time received
	timeReceivedBytes := make([]byte, 8)
	n, err = io.ReadFull(r, timeReceivedBytes)
	n64 += int64(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return n64, err
	}
	rt.received = time.Unix(int64(binary.LittleEndian.Uint64(timeReceivedBytes)), 0)

	// Create and read flags (change, is spent, block set)
	flagBytes := make([]byte, 1)
	n, err = io.ReadFull(r, flagBytes)
	n64 += int64(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return n64, err
	}
	flags := flagBytes[0]

	// Set change based on flags
	rt.change = flags&(1<<0) != 0
	rt.locked = flags&(1<<1) != 0

	// Read block details if specified in flags
	if flags&(1<<2) != 0 {
		rt.block = new(BlockDetails)
		n, err := rt.block.readFrom(r)
		n64 += n
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			return n64, err
		}
	} else {
		rt.block = nil
	}

	// Read spent by data if specified in flags
	if flags&(1<<3) != 0 {
		rt.spentBy = new(blockTx)
		n, err := rt.spentBy.readFrom(r)
		n64 += n
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			return n64, err
		}
	} else {
		rt.spentBy = nil
	}

	return n64, nil
}

func (rt *recvTxOut) writeTo(w io.Writer) (int64, error) {
	// Write outpoint (Sha, index)
	n, err := w.Write(rt.outpoint.Hash[:])
	n64 := int64(n)
	if err != nil {
		return n64, err
	}
	indexBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(indexBytes, rt.outpoint.Index)
	n, err = w.Write(indexBytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}

	// Write time received
	timeReceivedBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timeReceivedBytes, uint64(rt.received.Unix()))
	n, err = w.Write(timeReceivedBytes)
	n64 += int64(n)
	if err != nil {
		return n64, err
	}

	// Create and write flags (change, is spent, block set)
	var flags byte
	if rt.change {
		flags |= 1 << 0
	}
	if rt.locked {
		flags |= 1 << 1
	}
	if rt.block != nil {
		flags |= 1 << 2
	}
	if rt.spentBy != nil {
		flags |= 1 << 3
	}
	n, err = w.Write([]byte{flags})
	n64 += int64(n)
	if err != nil {
		return n64, err
	}

	// Write block details if set
	if rt.block != nil {
		n, err := rt.block.writeTo(w)
		n64 += n
		if err != nil {
			return n64, err
		}
	}

	// Write spent by data if set (Sha, block height)
	if rt.spentBy != nil {
		n, err := rt.spentBy.writeTo(w)
		n64 += n
		if err != nil {
			return n64, err
		}
	}

	return n64, nil
}

// TxSha returns the sha of the transaction containing this output.
func (rt *recvTxOut) TxSha() *btcwire.ShaHash {
	return &rt.outpoint.Hash
}

// OutPoint returns the outpoint to be included when creating transaction
// inputs referencing this output.
func (rt *recvTxOut) OutPoint() *btcwire.OutPoint {
	return &rt.outpoint
}

// Time returns the time the transaction containing this output was received.
func (rt *recvTxOut) Time() time.Time {
	return rt.received
}

// Change returns whether the received output was created for a change address.
func (rt *recvTxOut) Change() bool {
	return rt.change
}

// Spent returns whether the transaction output has been spent by a later
// transaction.
func (rt *recvTxOut) Spent() bool {
	return rt.spentBy != nil
}

// SpentBy returns the tx sha and blockchain height of the transaction
// spending an output.
func (rt *recvTxOut) SpentBy() (txSha *btcwire.ShaHash, height int32) {
	if rt.spentBy == nil {
		return nil, 0
	}
	return &rt.spentBy.txSha, rt.spentBy.height
}

// Locked returns the current lock state of an unspent transaction output.
func (rt *recvTxOut) Locked() bool {
	return rt.locked
}

// SetLocked locks or unlocks an unspent transaction output.
func (rt *recvTxOut) SetLocked(locked bool) {
	rt.locked = locked
}

// Block returns details of the block containing this transaction, or nil
// if the tx is unmined.
func (rt *recvTxOut) Block() *BlockDetails {
	return rt.block
}

// Height returns the blockchain height of the transaction containing
// this output.  If the transaction is unmined, this returns -1.
func (rt *recvTxOut) Height() int32 {
	height := int32(-1)
	if rt.block != nil {
		height = rt.block.Height
	}
	return height
}

func (rt *recvTxOut) setBlock(details *BlockDetails) {
	rt.block = details
}

func (rt *recvTxOut) record(s *Store) Record {
	record := &RecvTxOut{
		recvTxOut: *rt,
		tx:        s.txs[rt.blockTx()],
	}
	return record
}

// RecvTxOut is a type additional information for transaction outputs which
// are spendable by a wallet.
type RecvTxOut struct {
	recvTxOut
	tx *btcutil.Tx
}

// Addresses parses the pubkey script, extracting all addresses for a
// standard script.
func (rt *RecvTxOut) Addresses(net btcwire.BitcoinNet) (btcscript.ScriptClass,
	[]btcutil.Address, int, error) {

	tx := rt.tx.MsgTx()
	return btcscript.ExtractPkScriptAddrs(tx.TxOut[rt.outpoint.Index].PkScript, net)
}

// IsCoinbase returns whether the received transaction output is an output
// a coinbase transaction.
func (rt *RecvTxOut) IsCoinbase() bool {
	if rt.recvTxOut.block == nil {
		return false
	}
	return rt.recvTxOut.block.Index == 0
}

// PkScript returns the pubkey script of the output.
func (rt *RecvTxOut) PkScript() []byte {
	tx := rt.tx.MsgTx()
	return tx.TxOut[rt.outpoint.Index].PkScript
}

// Value returns the number of satoshis sent by the output.
func (rt *RecvTxOut) Value() int64 {
	tx := rt.tx.MsgTx()
	return tx.TxOut[rt.outpoint.Index].Value
}

// Tx returns the transaction which contains this output.
func (rt *RecvTxOut) Tx() *btcutil.Tx {
	return rt.tx
}

// TxInfo returns a slice of maps that may be marshaled as a JSON array
// of JSON objects for a listtransactions RPC reply.
func (rt *RecvTxOut) TxInfo(account string, chainHeight int32, net btcwire.BitcoinNet) []map[string]interface{} {
	tx := rt.tx.MsgTx()
	outidx := rt.outpoint.Index
	txout := tx.TxOut[outidx]

	address := "Unknown"
	_, addrs, _, _ := btcscript.ExtractPkScriptAddrs(txout.PkScript, net)
	if len(addrs) == 1 {
		address = addrs[0].EncodeAddress()
	}

	txInfo := map[string]interface{}{
		"account":      account,
		"category":     "receive",
		"address":      address,
		"amount":       float64(txout.Value) / float64(btcutil.SatoshiPerBitcoin),
		"txid":         rt.outpoint.Hash.String(),
		"timereceived": float64(rt.received.Unix()),
	}

	if rt.block != nil {
		txInfo["blockhash"] = rt.block.Hash.String()
		txInfo["blockindex"] = float64(rt.block.Index)
		txInfo["blocktime"] = float64(rt.block.Time.Unix())
		txInfo["confirmations"] = float64(chainHeight - rt.block.Height + 1)
	} else {
		txInfo["confirmations"] = float64(0)
	}

	return []map[string]interface{}{txInfo}
}
