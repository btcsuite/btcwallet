/*
 * Copyright (c) 2015 Conformal Systems LLC <info@conformal.com>
 * Copyright (c) 2015 The Decred developers
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

// db.go
package wstakemgr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/decred/dcrd/blockchain/stake"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrutil"
	"github.com/decred/dcrwallet/walletdb"
)

const (
	// LatestStakeMgrVersion is the most recent tx store version.
	LatestStakeMgrVersion = 1

	// Size of various types in bytes.
	boolSize  = 1
	int8Size  = 1
	int16Size = 2
	int32Size = 4
	int64Size = 8
	hashSize  = 32

	// Size of a serialized ssgenRecord.
	// hash + uint32 + hash + uint16 + uint64
	ssgenRecordSize = 32 + 4 + 32 + 2 + 8

	// Size of a serialized ssrtxRecord.
	// hash + uint32 + hash + uint64
	ssrtxRecordSize = 32 + 4 + 32 + 8
)

var (
	// sstxTicket2PKHPrefix is the PkScript byte prefix for an SStx
	// P2PKH ticket output. The entire prefix is 0xba76a914, but we
	// only use the first 3 bytes.
	sstxTicket2PKHPrefix = []byte{0xba, 0x76, 0xa9}

	// sstxTicket2SHPrefix is the PkScript byte prefix for an SStx
	// P2SH ticket output.
	sstxTicket2SHPrefix = []byte{0xba, 0xa9, 0x14}
)

// byteOrder refers to the endianness used to encode data.
var byteOrder = binary.LittleEndian

// maybeConvertDbError converts the passed error to a TxStoreError with an
// error code of ErrDatabase if it is not already a TxStoreError.  This is
// useful for potential errors returned from managed transaction an other parts
// of the walletdb database.
func maybeConvertDbError(err error) error {
	// When the error is already a TxStoreError, just return it.
	if _, ok := err.(StakeStoreError); ok {
		return err
	}

	return stakeStoreError(ErrDatabase, err.Error(), err)
}

// Key names for various database fields.
// sstxRecords
//     key: sstx tx hash
//     val: sstxRecord
// ssgenRecords
//     key: sstx tx hash
//     val: serialized slice of ssgenRecords
//
var (
	// Bucket names.
	mainBucketName         = []byte("main")
	sstxRecordsBucketName  = []byte("sstxrecords")
	ssgenRecordsBucketName = []byte("ssgenrecords")
	ssrtxRecordsBucketName = []byte("ssrtxrecords")
	metaBucketName         = []byte("meta")

	// Db related key names (main bucket).
	stakeStoreVersionName    = []byte("stakestorever")
	stakeStoreCreateDateName = []byte("stakestorecreated")
)

// int8ToBytes converts an 8 bit signed integer into a 1-byte slice.
func int8ToBytes(number int8) []byte {
	var w bytes.Buffer
	var buf [1]byte
	buf[0] = byte(number)
	w.Write(buf[:])

	return w.Bytes()
}

// int8FromBytes converts a 1 byte byte slice to a signed 8 bit integer.
func int8FromBytes(slice []byte) int8 {
	var number int8

	buf := bytes.NewBuffer(slice[:])
	binary.Read(buf, byteOrder, &number)

	return number
}

// uint32ToBytes converts a 32 bit unsigned integer into a 4-byte slice in
// little-endian order: 1 -> [1 0 0 0].
func uint32ToBytes(number uint32) []byte {
	buf := make([]byte, 4)
	byteOrder.PutUint32(buf, number)
	return buf
}

// deserializeSStxRecord deserializes the passed serialized tx record information.
func deserializeSStxRecord(serializedSStxRecord []byte) (*sstxRecord, error) {
	record := new(sstxRecord)

	curPos := 0

	// Read MsgTx size (as a uint64).
	msgTxLen := int(byteOrder.Uint64(
		serializedSStxRecord[curPos : curPos+int64Size]))
	curPos += int64Size

	// Pretend to read the pkScrLoc for the 0th output pkScript.
	curPos += int32Size

	// Pretend to read the intended votebits length (uint8).
	curPos += int8Size

	// Pretend to read the intended votebits (75 bytes).
	curPos += stake.MaxSingleBytePushLength

	// Prepare a buffer for the msgTx.
	buf := bytes.NewBuffer(serializedSStxRecord[curPos : curPos+msgTxLen])
	curPos += msgTxLen

	// Deserialize transaction.
	msgTx := new(wire.MsgTx)
	err := msgTx.Deserialize(buf)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}

	// Create and save the dcrutil.Tx of the read MsgTx and set its index.
	tx := dcrutil.NewTx((*wire.MsgTx)(msgTx))
	tx.SetIndex(dcrutil.TxIndexUnknown)
	tx.SetTree(dcrutil.TxTreeStake)
	record.tx = tx

	// Read received unix time (int64).
	received := int64(byteOrder.Uint64(
		serializedSStxRecord[curPos : curPos+int64Size]))
	curPos += int64Size
	record.ts = time.Unix(received, 0)

	return record, nil
}

// deserializeSStxTicketScriptHash deserializes and returns a 20 byte script
// hash for a ticket's 0th output.
func deserializeSStxTicketScriptHash(serializedSStxRecord []byte) ([]byte, error) {
	dataLen := len(serializedSStxRecord)
	curPos := 0

	// Skip transaction size.
	curPos += int64Size

	// Load the pkScript index.
	pkScrLoc := int(byteOrder.Uint32(
		serializedSStxRecord[curPos : curPos+int32Size]))
	curPos += int32Size

	// Skip intended votebits length (uint8).
	curPos += int8Size

	// Skip intended votebits (75 bytes).
	curPos += stake.MaxSingleBytePushLength

	// Figure out the actual location of the script.
	actualLoc := curPos + pkScrLoc
	if actualLoc+3 >= dataLen {
		return nil, stakeStoreError(ErrDatabase,
			"bad serialized sstx record size", nil)
	}

	// Pop off the script prefix, then pop off the 20 bytes
	// HASH160 pubkey or script hash.
	prefixBytes := serializedSStxRecord[actualLoc : actualLoc+3]
	scriptHash := make([]byte, 20, 20)
	switch {
	case bytes.Equal(prefixBytes, sstxTicket2PKHPrefix):
		scrHashLoc := actualLoc + 4
		if scrHashLoc+20 >= dataLen {
			return nil, stakeStoreError(ErrDatabase,
				"bad serialized sstx record size for pubkey hash", nil)
		}
		copy(scriptHash, serializedSStxRecord[scrHashLoc:scrHashLoc+20])
	case bytes.Equal(prefixBytes, sstxTicket2SHPrefix):
		scrHashLoc := actualLoc + 3
		if scrHashLoc+20 >= dataLen {
			return nil, stakeStoreError(ErrDatabase,
				"bad serialized sstx record size for script hash", nil)
		}
		copy(scriptHash, serializedSStxRecord[scrHashLoc:scrHashLoc+20])
	}

	return scriptHash, nil
}

// serializeSSTxRecord returns the serialization of the passed txrecord row.
func serializeSStxRecord(record *sstxRecord) ([]byte, error) {
	msgTx := record.tx.MsgTx()
	msgTxSize := int64(msgTx.SerializeSize())

	size := 0

	// tx tree is implicit (stake)

	// size of msgTx (recast to int64)
	size += int64Size

	// byte index of the ticket pk script
	size += int32Size

	// intended votebits length (uint8)
	size += int8Size

	// intended votebits (75 bytes)
	size += stake.MaxSingleBytePushLength

	// msgTx size is variable.
	size += int(msgTxSize)

	// timestamp (int64)
	size += int64Size

	buf := make([]byte, size)

	curPos := 0

	// Write msgTx size (as a uint64).
	byteOrder.PutUint64(buf[curPos:curPos+int64Size], uint64(msgTxSize))
	curPos += int64Size

	// Write the pkScript loc for the ticket output as a uint32.
	pkScrLoc := msgTx.PkScriptLocs()
	byteOrder.PutUint32(buf[curPos:curPos+int32Size], uint32(pkScrLoc[0]))
	curPos += int32Size

	// Skip the section for intended votebits length (uint8).
	curPos += int8Size

	// Skip the section for intended votebits (75 bytes).
	curPos += stake.MaxSingleBytePushLength

	// Serialize and write transaction.
	var b bytes.Buffer
	err := msgTx.Serialize(&b)
	if err != nil {
		return buf, err
	}
	copy(buf[curPos:curPos+int(msgTxSize)], b.Bytes())
	curPos += int(msgTxSize)

	// Write received unix time (int64).
	byteOrder.PutUint64(buf[curPos:curPos+int64Size], uint64(record.ts.Unix()))
	curPos += int64Size

	return buf, nil
}

// deserializeSSGenRecord deserializes the passed serialized tx
// record information.
func deserializeSSGenRecord(serializedSSGenRecord []byte) (*ssgenRecord,
	error) {

	// Cursory check to make sure that the size of the
	// record makes sense.
	if len(serializedSSGenRecord)%ssgenRecordSize != 0 {
		str := "serialized SSGen record was wrong size"
		return nil, stakeStoreError(ErrDatabase, str, nil)
	}

	record := new(ssgenRecord)

	curPos := 0

	// Insert the block hash into the record.
	copy(record.blockHash[:], serializedSSGenRecord[curPos:curPos+hashSize])
	curPos += hashSize

	// Insert the block height into the record.
	record.blockHeight = byteOrder.Uint32(
		serializedSSGenRecord[curPos : curPos+int32Size])
	curPos += int32Size

	// Insert the tx hash into the record.
	copy(record.txHash[:], serializedSSGenRecord[curPos:curPos+hashSize])
	curPos += hashSize

	// Insert the votebits into the record.
	record.voteBits = byteOrder.Uint16(
		serializedSSGenRecord[curPos : curPos+int16Size])
	curPos += int16Size

	// Insert the timestamp into the record.
	record.ts = time.Unix(
		int64(byteOrder.Uint64(
			serializedSSGenRecord[curPos:curPos+int64Size])),
		0)
	curPos += int64Size

	return record, nil
}

// deserializeSSGenRecords deserializes the passed serialized tx
// record information.
func deserializeSSGenRecords(serializedSSGenRecords []byte) ([]*ssgenRecord,
	error) {

	// Cursory check to make sure that the number of records
	// makes sense.
	if len(serializedSSGenRecords)%ssgenRecordSize != 0 {
		err := io.ErrUnexpectedEOF
		return nil, err
	}

	numRecords := len(serializedSSGenRecords) / ssgenRecordSize

	records := make([]*ssgenRecord, numRecords)

	// Loop through all the ssgen records, deserialize them, and
	// store them.
	for i := 0; i < numRecords; i++ {
		record, err := deserializeSSGenRecord(
			serializedSSGenRecords[i*ssgenRecordSize : (i+1)*ssgenRecordSize])

		if err != nil {
			str := "problem serializing ssgen record"
			return nil, stakeStoreError(ErrDatabase, str, err)
		}

		records[i] = record
	}

	return records, nil
}

// serializeSSGenRecord returns the serialization of a single SSGen
// record.
func serializeSSGenRecord(record *ssgenRecord) []byte {
	buf := make([]byte, ssgenRecordSize)

	curPos := 0

	// Write the block hash.
	copy(buf[curPos:curPos+hashSize], record.blockHash.Bytes())
	curPos += hashSize

	// Write the block height.
	byteOrder.PutUint32(buf[curPos:curPos+int32Size], record.blockHeight)
	curPos += int32Size

	// Write the tx hash.
	copy(buf[curPos:curPos+hashSize], record.txHash.Bytes())
	curPos += hashSize

	// Write the vote bits.
	byteOrder.PutUint16(buf[curPos:curPos+int16Size], record.voteBits)
	curPos += int16Size

	// Write the timestamp.
	byteOrder.PutUint64(buf[curPos:curPos+int64Size], uint64(record.ts.Unix()))
	curPos += int64Size

	return buf
}

// serializeSSGenRecords returns the serialization of the passed
// SSGen records slice.
func serializeSSGenRecords(records []*ssgenRecord) []byte {
	numRecords := len(records)

	buf := make([]byte, numRecords*ssgenRecordSize)

	// Serialize and write each record into the slice sequentially.
	for i := 0; i < numRecords; i++ {
		recordBytes := serializeSSGenRecord(records[i])

		copy(buf[i*ssgenRecordSize:(i+1)*ssgenRecordSize],
			recordBytes)
	}

	return buf
}

// deserializeSSRtxRecord deserializes the passed serialized SSRtx
// record information.
func deserializeSSRtxRecord(serializedSSRtxRecord []byte) (*ssrtxRecord,
	error) {

	// Cursory check to make sure that the size of the
	// record makes sense.
	if len(serializedSSRtxRecord)%ssrtxRecordSize != 0 {
		str := "serialized SSRtx record was wrong size"
		return nil, stakeStoreError(ErrDatabase, str, nil)
	}

	record := new(ssrtxRecord)

	curPos := 0

	// Insert the block hash into the record.
	copy(record.blockHash[:], serializedSSRtxRecord[curPos:curPos+hashSize])
	curPos += hashSize

	// Insert the block height into the record.
	record.blockHeight = byteOrder.Uint32(
		serializedSSRtxRecord[curPos : curPos+int32Size])
	curPos += int32Size

	// Insert the tx hash into the record.
	copy(record.txHash[:], serializedSSRtxRecord[curPos:curPos+hashSize])
	curPos += hashSize

	// Insert the timestamp into the record.
	record.ts = time.Unix(
		int64(byteOrder.Uint64(
			serializedSSRtxRecord[curPos:curPos+int64Size])),
		0)
	curPos += int64Size

	return record, nil
}

// deserializeSSRtxRecords deserializes the passed serialized SSRtx
// records information.
func deserializeSSRtxRecords(serializedSSRtxRecords []byte) ([]*ssrtxRecord,
	error) {

	// Cursory check to make sure that the number of records
	// makes sense.
	if len(serializedSSRtxRecords)%ssrtxRecordSize != 0 {
		err := io.ErrUnexpectedEOF
		return nil, err
	}

	numRecords := len(serializedSSRtxRecords) / ssrtxRecordSize

	records := make([]*ssrtxRecord, numRecords)

	// Loop through all the ssgen records, deserialize them, and
	// store them.
	for i := 0; i < numRecords; i++ {
		record, err := deserializeSSRtxRecord(
			serializedSSRtxRecords[i*ssrtxRecordSize : (i+1)*ssrtxRecordSize])

		if err != nil {
			str := "problem serializing ssrtx record"
			return nil, stakeStoreError(ErrDatabase, str, err)
		}

		records[i] = record
	}

	return records, nil
}

// serializeSSRtxRecord returns the serialization of the passed
// SSRtx record.
func serializeSSRtxRecord(record *ssrtxRecord) []byte {
	buf := make([]byte, ssrtxRecordSize)

	curPos := 0

	// Write the block hash.
	copy(buf[curPos:curPos+hashSize], record.blockHash.Bytes())
	curPos += hashSize

	// Write the block height.
	byteOrder.PutUint32(buf[curPos:curPos+int32Size], record.blockHeight)
	curPos += int32Size

	// Write the tx hash.
	copy(buf[curPos:curPos+hashSize], record.txHash.Bytes())
	curPos += hashSize

	// Write the timestamp.
	byteOrder.PutUint64(buf[curPos:curPos+int64Size], uint64(record.ts.Unix()))
	curPos += int64Size

	return buf
}

// serializeSSRtxRecords returns the serialization of the passed
// SSRtx records.
func serializeSSRtxRecords(records []*ssrtxRecord) []byte {
	numRecords := len(records)

	buf := make([]byte, numRecords*ssrtxRecordSize)

	// Serialize and write each record into the slice sequentially.
	for i := 0; i < numRecords; i++ {
		recordBytes := serializeSSRtxRecord(records[i])

		copy(buf[i*ssrtxRecordSize:(i+1)*ssrtxRecordSize],
			recordBytes)
	}

	return buf
}

// stakeStoreExists returns whether or not the stake store has already
// been created in the given database namespace.
func stakeStoreExists(namespace walletdb.Namespace) (bool, error) {
	var exists bool
	err := namespace.View(func(tx walletdb.Tx) error {
		mainBucket := tx.RootBucket().Bucket(mainBucketName)
		exists = mainBucket != nil
		return nil
	})
	if err != nil {
		str := fmt.Sprintf("failed to obtain database view: %v", err)
		return false, stakeStoreError(ErrDatabase, str, err)
	}
	return exists, nil
}

// fetchSStxRecord retrieves a tx record from the sstx records bucket
// with the given hash.
func fetchSStxRecord(tx walletdb.Tx, hash *chainhash.Hash) (*sstxRecord, error) {
	bucket := tx.RootBucket().Bucket(sstxRecordsBucketName)

	key := hash.Bytes()
	val := bucket.Get(key)
	if val == nil {
		str := fmt.Sprintf("missing sstx record for hash '%s'", hash.String())
		return nil, stakeStoreError(ErrSStxNotFound, str, nil)
	}

	return deserializeSStxRecord(val)
}

// fetchSStxRecordSStxTicketScriptHash retrieves a ticket 0th output script or
// pubkeyhash from the sstx records bucket with the given hash.
func fetchSStxRecordSStxTicketScriptHash(tx walletdb.Tx,
	hash *chainhash.Hash) ([]byte, error) {
	bucket := tx.RootBucket().Bucket(sstxRecordsBucketName)

	key := hash.Bytes()
	val := bucket.Get(key)
	if val == nil {
		str := fmt.Sprintf("missing sstx record for hash '%s'", hash.String())
		return nil, stakeStoreError(ErrSStxNotFound, str, nil)
	}

	return deserializeSStxTicketScriptHash(val)
}

// updateSStxRecord updates a sstx record in the sstx records bucket.
func updateSStxRecord(tx walletdb.Tx, record *sstxRecord) error {
	bucket := tx.RootBucket().Bucket(sstxRecordsBucketName)

	// Write the serialized txrecord keyed by the tx hash.
	serializedSStxRecord, err := serializeSStxRecord(record)
	if err != nil {
		str := fmt.Sprintf("failed to serialize sstxrecord '%s'", record.tx.Sha())
		return stakeStoreError(ErrDatabase, str, err)
	}
	err = bucket.Put(record.tx.Sha().Bytes(), serializedSStxRecord)
	if err != nil {
		str := fmt.Sprintf("failed to store sstxrecord '%s'", record.tx.Sha())
		return stakeStoreError(ErrDatabase, str, err)
	}
	return nil
}

// putSStxRecord inserts a given SStx record to the SStxrecords bucket.
func putSStxRecord(tx walletdb.Tx, record *sstxRecord) error {
	return updateSStxRecord(tx, record)
}

// fetchSSGenRecords retrieves SSGen records from the SSGenRecords bucket with
// the given hash.
func fetchSSGenRecords(tx walletdb.Tx, hash *chainhash.Hash) ([]*ssgenRecord,
	error) {
	bucket := tx.RootBucket().Bucket(ssgenRecordsBucketName)

	key := hash.Bytes()
	val := bucket.Get(key)
	if val == nil {
		str := fmt.Sprintf("missing ssgen records for hash '%s'", hash.String())
		return nil, stakeStoreError(ErrSSGensNotFound, str, nil)
	}

	return deserializeSSGenRecords(val)
}

// ssgenRecordExistsInRecords checks to see if a record already exists
// in a slice of ssgen records.
func ssgenRecordExistsInRecords(record *ssgenRecord,
	records []*ssgenRecord) bool {
	for _, r := range records {
		if r.txHash.IsEqual(&record.txHash) {
			return true
		}
	}

	return false
}

// updateSSGenRecord updates an SSGen record in the SSGen records bucket.
func updateSSGenRecord(tx walletdb.Tx, hash *chainhash.Hash,
	record *ssgenRecord) error {
	// Fetch the current content of the key.
	// Possible buggy behaviour: If deserialization fails,
	// we won't detect it here. We assume we're throwing
	// ErrSSGenNotFound.
	oldRecords, _ := fetchSSGenRecords(tx, hash)

	// Don't reinsert records we already have.
	if ssgenRecordExistsInRecords(record, oldRecords) {
		return nil
	}

	bucket := tx.RootBucket().Bucket(ssgenRecordsBucketName)

	var records []*ssgenRecord
	// Either create a slice if currently nothing exists for this
	// key in the db, or append the entry to the slice.
	if oldRecords == nil {
		records = make([]*ssgenRecord, 1)
		records[0] = record
	} else {
		records = append(oldRecords, record)
	}

	// Write the serialized SSGens keyed by the sstx hash.
	serializedSSGenRecords := serializeSSGenRecords(records)

	err := bucket.Put(hash.Bytes(), serializedSSGenRecords)
	if err != nil {
		str := fmt.Sprintf("failed to store ssgen records '%s'", hash)
		return stakeStoreError(ErrDatabase, str, err)
	}
	return nil
}

// putSSGenRecord inserts a given SSGen record to the SSGenrecords bucket.
func putSSGenRecord(tx walletdb.Tx, hash *chainhash.Hash,
	record *ssgenRecord) error {
	return updateSSGenRecord(tx, hash, record)
}

// fetchSSRtxRecords retrieves SSRtx records from the SSRtxRecords bucket with
// the given hash.
func fetchSSRtxRecords(tx walletdb.Tx, hash *chainhash.Hash) ([]*ssrtxRecord,
	error) {
	bucket := tx.RootBucket().Bucket(ssrtxRecordsBucketName)

	key := hash.Bytes()
	val := bucket.Get(key)
	if val == nil {
		str := fmt.Sprintf("missing ssrtx records for hash '%s'", hash.String())
		return nil, stakeStoreError(ErrSSRtxsNotFound, str, nil)
	}

	return deserializeSSRtxRecords(val)
}

// ssrtxRecordExistsInRecords checks to see if a record already exists
// in a slice of ssrtx records.
func ssrtxRecordExistsInRecords(record *ssrtxRecord,
	records []*ssrtxRecord) bool {
	for _, r := range records {
		if r.txHash.IsEqual(&record.txHash) {
			return true
		}
	}

	return false
}

// updateSSRtxRecord updates an SSRtx record in the SSRtx records bucket.
func updateSSRtxRecord(tx walletdb.Tx, hash *chainhash.Hash,
	record *ssrtxRecord) error {
	// Fetch the current content of the key.
	// Possible buggy behaviour: If deserialization fails,
	// we won't detect it here. We assume we're throwing
	// ErrSSRtxsNotFound.
	oldRecords, _ := fetchSSRtxRecords(tx, hash)

	// Don't reinsert records we already have.
	if ssrtxRecordExistsInRecords(record, oldRecords) {
		return nil
	}

	bucket := tx.RootBucket().Bucket(ssrtxRecordsBucketName)

	var records []*ssrtxRecord
	// Either create a slice if currently nothing exists for this
	// key in the db, or append the entry to the slice.
	if oldRecords == nil {
		records = make([]*ssrtxRecord, 1)
		records[0] = record
	} else {
		records = append(oldRecords, record)
	}

	// Write the serialized SSRtxs keyed by the sstx hash.
	serializedSSRtxsRecords := serializeSSRtxRecords(records)

	err := bucket.Put(hash.Bytes(), serializedSSRtxsRecords)
	if err != nil {
		str := fmt.Sprintf("failed to store ssrtx records '%s'", hash)
		return stakeStoreError(ErrDatabase, str, err)
	}
	return nil
}

// putSSRtxRecord inserts a given SSRtxs record to the SSRtxs records bucket.
func putSSRtxRecord(tx walletdb.Tx, hash *chainhash.Hash,
	record *ssrtxRecord) error {
	return updateSSRtxRecord(tx, hash, record)
}

// putMeta
func putMeta(tx walletdb.Tx, key []byte, n int32) error {
	bucket := tx.RootBucket().Bucket(metaBucketName)
	err := bucket.Put(key, uint32ToBytes(uint32(n)))
	if err != nil {
		str := fmt.Sprintf("failed to store meta key '%s'", key)
		return stakeStoreError(ErrDatabase, str, err)
	}
	return nil
}

// fetchMeta
func fetchMeta(tx walletdb.Tx, key []byte) (int32, error) {
	bucket := tx.RootBucket().Bucket(metaBucketName)

	val := bucket.Get(key)
	// Return 0 if the metadata is uninitialized
	if val == nil {
		return 0, nil
	}
	if val == nil {
		str := fmt.Sprintf("meta key not found %s", key)
		return 0, stakeStoreError(ErrDatabase, str, nil)
	}

	return int32(byteOrder.Uint32(val)), nil
}

// initialize creates the DB if it doesn't exist, and otherwise
// loads the database.
func initializeEmpty(namespace walletdb.Namespace) error {
	// Initialize the buckets and main db fields as needed.
	var version uint32
	var createDate uint64
	err := namespace.Update(func(tx walletdb.Tx) error {
		rootBucket := tx.RootBucket()
		mainBucket, err := rootBucket.CreateBucketIfNotExists(
			mainBucketName)
		if err != nil {
			str := "failed to create main bucket"
			return stakeStoreError(ErrDatabase, str, err)
		}

		_, err = rootBucket.CreateBucketIfNotExists(sstxRecordsBucketName)
		if err != nil {
			str := "failed to create sstx records bucket"
			return stakeStoreError(ErrDatabase, str, err)
		}

		_, err = rootBucket.CreateBucketIfNotExists(ssgenRecordsBucketName)
		if err != nil {
			str := "failed to create ssgen records bucket"
			return stakeStoreError(ErrDatabase, str, err)
		}

		_, err = rootBucket.CreateBucketIfNotExists(ssrtxRecordsBucketName)
		if err != nil {
			str := "failed to create ssrtx records bucket"
			return stakeStoreError(ErrDatabase, str, err)
		}

		_, err = rootBucket.CreateBucketIfNotExists(metaBucketName)
		if err != nil {
			str := "failed to create meta bucket"
			return stakeStoreError(ErrDatabase, str, err)
		}

		// Save the most recent tx store version if it isn't already
		// there, otherwise keep track of it for potential upgrades.
		verBytes := mainBucket.Get(stakeStoreVersionName)
		if verBytes == nil {
			version = LatestStakeMgrVersion

			var buf [4]byte
			byteOrder.PutUint32(buf[:], version)
			err := mainBucket.Put(stakeStoreVersionName, buf[:])
			if err != nil {
				str := "failed to store latest database version"
				return stakeStoreError(ErrDatabase, str, err)
			}
		} else {
			version = byteOrder.Uint32(verBytes)
		}

		createBytes := mainBucket.Get(stakeStoreCreateDateName)
		if createBytes == nil {
			createDate = uint64(time.Now().Unix())
			var buf [8]byte
			byteOrder.PutUint64(buf[:], createDate)
			err := mainBucket.Put(stakeStoreCreateDateName, buf[:])
			if err != nil {
				str := "failed to store database creation time"
				return stakeStoreError(ErrDatabase, str, err)
			}
		} else {
			createDate = byteOrder.Uint64(createBytes)
		}

		return nil
	})

	if err != nil {
		str := "failed to load database"
		return stakeStoreError(ErrDatabase, str, err)
	}

	return nil
}
