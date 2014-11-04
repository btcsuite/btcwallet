/*
 * Copyright (c) 2014 Conformal Systems LLC <info@conformal.com>
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
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcwallet/snacl"
	"github.com/btcsuite/btcwallet/walletdb"
)

// These constants define the serialized length for a given encrypted extended
// public or private key.
const (
	// We can calculate the encrypted extended key length this way:
	// snacl.Overhead == overhead for encrypting (16)
	// actual base58 extended key length = (111)
	// snacl.NonceSize == nonce size used for encryption (24)
	seriesKeyLength = snacl.Overhead + 111 + snacl.NonceSize
	// 4 bytes version + 1 byte active + 4 bytes nKeys + 4 bytes reqSigs
	seriesMinSerial = 4 + 1 + 4 + 4
	// 15 is the max number of keys in a voting pool, 1 each for
	// pubkey and privkey
	seriesMaxSerial = seriesMinSerial + 15*seriesKeyLength*2
	// version of serialized Series that we support
	seriesMaxVersion = 1
)

var (
	usedAddrsBucketName = []byte("usedaddrs")
	seriesBucketName    = []byte("series")
	// string representing a non-existent private key
	seriesNullPrivKey = [seriesKeyLength]byte{}
)

type dbSeriesRow struct {
	version           uint32
	active            bool
	reqSigs           uint32
	pubKeysEncrypted  [][]byte
	privKeysEncrypted [][]byte
}

// getUsedAddrBucketID returns the used addresses bucket ID for the given series
// and branch. It has the form seriesID:branch.
func getUsedAddrBucketID(seriesID uint32, branch Branch) []byte {
	var bucketID [9]byte
	binary.LittleEndian.PutUint32(bucketID[0:4], seriesID)
	bucketID[4] = ':'
	binary.LittleEndian.PutUint32(bucketID[5:9], uint32(branch))
	return bucketID[:]
}

// putUsedAddrHash adds an entry (key==index, value==encryptedHash) to the used
// addresses bucket of the given pool, series and branch.
func putUsedAddrHash(tx walletdb.Tx, poolID []byte, seriesID uint32, branch Branch,
	index Index, encryptedHash []byte) error {

	usedAddrs := tx.RootBucket().Bucket(poolID).Bucket(usedAddrsBucketName)
	bucket, err := usedAddrs.CreateBucketIfNotExists(getUsedAddrBucketID(seriesID, branch))
	if err != nil {
		return newError(ErrDatabase, "failed to store used address hash", err)
	}
	return bucket.Put(uint32ToBytes(uint32(index)), encryptedHash)
}

// getUsedAddrHash returns the addr hash with the given index from the used
// addresses bucket of the given pool, series and branch.
func getUsedAddrHash(tx walletdb.Tx, poolID []byte, seriesID uint32, branch Branch,
	index Index) []byte {

	usedAddrs := tx.RootBucket().Bucket(poolID).Bucket(usedAddrsBucketName)
	bucket := usedAddrs.Bucket(getUsedAddrBucketID(seriesID, branch))
	if bucket == nil {
		return nil
	}
	return bucket.Get(uint32ToBytes(uint32(index)))
}

// getMaxUsedIdx returns the highest used index from the used addresses bucket
// of the given pool, series and branch.
func getMaxUsedIdx(tx walletdb.Tx, poolID []byte, seriesID uint32, branch Branch) (Index, error) {
	maxIdx := Index(0)
	usedAddrs := tx.RootBucket().Bucket(poolID).Bucket(usedAddrsBucketName)
	bucket := usedAddrs.Bucket(getUsedAddrBucketID(seriesID, branch))
	if bucket == nil {
		return maxIdx, nil
	}
	// FIXME: This is far from optimal and should be optimized either by storing
	// a separate key in the DB with the highest used idx for every
	// series/branch or perhaps by doing a large gap linear forward search +
	// binary backwards search (e.g. check for 1000000, 2000000, ....  until it
	// doesn't exist, and then use a binary search to find the max using the
	// discovered bounds).
	err := bucket.ForEach(
		func(k, v []byte) error {
			idx := Index(bytesToUint32(k))
			if idx > maxIdx {
				maxIdx = idx
			}
			return nil
		})
	if err != nil {
		return Index(0), newError(ErrDatabase, "failed to get highest idx of used addresses", err)
	}
	return maxIdx, nil
}

// putPool stores a voting pool in the database, creating a bucket named
// after the voting pool id and two other buckets inside it to store series and
// used addresses for that pool.
func putPool(tx walletdb.Tx, poolID []byte) error {
	poolBucket, err := tx.RootBucket().CreateBucket(poolID)
	if err != nil {
		return newError(ErrDatabase, fmt.Sprintf("cannot create pool %v", poolID), err)
	}
	_, err = poolBucket.CreateBucket(seriesBucketName)
	if err != nil {
		return newError(ErrDatabase, fmt.Sprintf("cannot create series bucket for pool %v",
			poolID), err)
	}
	_, err = poolBucket.CreateBucket(usedAddrsBucketName)
	if err != nil {
		return newError(ErrDatabase, fmt.Sprintf("cannot create used addrs bucket for pool %v",
			poolID), err)
	}
	return nil
}

// loadAllSeries returns a map of all the series stored inside a voting pool
// bucket, keyed by id.
func loadAllSeries(tx walletdb.Tx, poolID []byte) (map[uint32]*dbSeriesRow, error) {
	bucket := tx.RootBucket().Bucket(poolID).Bucket(seriesBucketName)
	allSeries := make(map[uint32]*dbSeriesRow)
	err := bucket.ForEach(
		func(k, v []byte) error {
			seriesID := bytesToUint32(k)
			series, err := deserializeSeriesRow(v)
			if err != nil {
				return err
			}
			allSeries[seriesID] = series
			return nil
		})
	if err != nil {
		return nil, err
	}
	return allSeries, nil
}

// existsPool checks the existence of a bucket named after the given
// voting pool id.
func existsPool(tx walletdb.Tx, poolID []byte) bool {
	bucket := tx.RootBucket().Bucket(poolID)
	return bucket != nil
}

// putSeries stores the given series inside a voting pool bucket named after
// poolID. The voting pool bucket does not need to be created beforehand.
func putSeries(tx walletdb.Tx, poolID []byte, version, ID uint32, active bool, reqSigs uint32, pubKeysEncrypted, privKeysEncrypted [][]byte) error {
	row := &dbSeriesRow{
		version:           version,
		active:            active,
		reqSigs:           reqSigs,
		pubKeysEncrypted:  pubKeysEncrypted,
		privKeysEncrypted: privKeysEncrypted,
	}
	return putSeriesRow(tx, poolID, ID, row)
}

// putSeriesRow stores the given series row inside a voting pool bucket named
// after poolID. The voting pool bucket does not need to be created
// beforehand.
func putSeriesRow(tx walletdb.Tx, poolID []byte, ID uint32, row *dbSeriesRow) error {
	bucket, err := tx.RootBucket().CreateBucketIfNotExists(poolID)
	if err != nil {
		str := fmt.Sprintf("cannot create bucket %v", poolID)
		return newError(ErrDatabase, str, err)
	}
	bucket = bucket.Bucket(seriesBucketName)
	serialized, err := serializeSeriesRow(row)
	if err != nil {
		return err
	}
	err = bucket.Put(uint32ToBytes(ID), serialized)
	if err != nil {
		str := fmt.Sprintf("cannot put series %v into bucket %v", serialized, poolID)
		return newError(ErrDatabase, str, err)
	}
	return nil
}

// deserializeSeriesRow deserializes a series storage into a dbSeriesRow struct.
func deserializeSeriesRow(serializedSeries []byte) (*dbSeriesRow, error) {
	// The serialized series format is:
	// <version><active><reqSigs><nKeys><pubKey1><privKey1>...<pubkeyN><privKeyN>
	//
	// 4 bytes version + 1 byte active + 4 bytes reqSigs + 4 bytes nKeys
	// + seriesKeyLength * 2 * nKeys (1 for priv, 1 for pub)

	// Given the above, the length of the serialized series should be
	// at minimum the length of the constants.
	if len(serializedSeries) < seriesMinSerial {
		str := fmt.Sprintf("serialized series is too short: %v", serializedSeries)
		return nil, newError(ErrSeriesSerialization, str, nil)
	}

	// Maximum number of public keys is 15 and the same for public keys
	// this gives us an upper bound.
	if len(serializedSeries) > seriesMaxSerial {
		str := fmt.Sprintf("serialized series is too long: %v", serializedSeries)
		return nil, newError(ErrSeriesSerialization, str, nil)
	}

	// Keeps track of the position of the next set of bytes to deserialize.
	current := 0
	row := dbSeriesRow{}

	row.version = bytesToUint32(serializedSeries[current : current+4])
	if row.version > seriesMaxVersion {
		str := fmt.Sprintf("deserialization supports up to version %v not %v",
			seriesMaxVersion, row.version)
		return nil, newError(ErrSeriesVersion, str, nil)
	}
	current += 4

	row.active = serializedSeries[current] == 0x01
	current++

	row.reqSigs = bytesToUint32(serializedSeries[current : current+4])
	current += 4

	nKeys := bytesToUint32(serializedSeries[current : current+4])
	current += 4

	// Check to see if we have the right number of bytes to consume.
	if len(serializedSeries) < current+int(nKeys)*seriesKeyLength*2 {
		str := fmt.Sprintf("serialized series has not enough data: %v", serializedSeries)
		return nil, newError(ErrSeriesSerialization, str, nil)
	} else if len(serializedSeries) > current+int(nKeys)*seriesKeyLength*2 {
		str := fmt.Sprintf("serialized series has too much data: %v", serializedSeries)
		return nil, newError(ErrSeriesSerialization, str, nil)
	}

	// Deserialize the pubkey/privkey pairs.
	row.pubKeysEncrypted = make([][]byte, nKeys)
	row.privKeysEncrypted = make([][]byte, nKeys)
	for i := 0; i < int(nKeys); i++ {
		pubKeyStart := current + seriesKeyLength*i*2
		pubKeyEnd := current + seriesKeyLength*i*2 + seriesKeyLength
		privKeyEnd := current + seriesKeyLength*(i+1)*2
		row.pubKeysEncrypted[i] = serializedSeries[pubKeyStart:pubKeyEnd]
		privKeyEncrypted := serializedSeries[pubKeyEnd:privKeyEnd]
		if bytes.Equal(privKeyEncrypted, seriesNullPrivKey[:]) {
			row.privKeysEncrypted[i] = nil
		} else {
			row.privKeysEncrypted[i] = privKeyEncrypted
		}
	}

	return &row, nil
}

// serializeSeriesRow serializes a dbSeriesRow struct into storage format.
func serializeSeriesRow(row *dbSeriesRow) ([]byte, error) {
	// The serialized series format is:
	// <version><active><reqSigs><nKeys><pubKey1><privKey1>...<pubkeyN><privKeyN>
	//
	// 4 bytes version + 1 byte active + 4 bytes reqSigs + 4 bytes nKeys
	// + seriesKeyLength * 2 * nKeys (1 for priv, 1 for pub)
	serializedLen := 4 + 1 + 4 + 4 + (seriesKeyLength * 2 * len(row.pubKeysEncrypted))

	if len(row.privKeysEncrypted) != 0 &&
		len(row.pubKeysEncrypted) != len(row.privKeysEncrypted) {
		str := fmt.Sprintf("different # of pub (%v) and priv (%v) keys",
			len(row.pubKeysEncrypted), len(row.privKeysEncrypted))
		return nil, newError(ErrSeriesSerialization, str, nil)
	}

	if row.version > seriesMaxVersion {
		str := fmt.Sprintf("serialization supports up to version %v, not %v",
			seriesMaxVersion, row.version)
		return nil, newError(ErrSeriesVersion, str, nil)
	}

	serialized := make([]byte, 0, serializedLen)
	serialized = append(serialized, uint32ToBytes(row.version)...)
	if row.active {
		serialized = append(serialized, 0x01)
	} else {
		serialized = append(serialized, 0x00)
	}
	serialized = append(serialized, uint32ToBytes(row.reqSigs)...)
	nKeys := uint32(len(row.pubKeysEncrypted))
	serialized = append(serialized, uint32ToBytes(nKeys)...)

	var privKeyEncrypted []byte
	for i, pubKeyEncrypted := range row.pubKeysEncrypted {
		// check that the encrypted length is correct
		if len(pubKeyEncrypted) != seriesKeyLength {
			str := fmt.Sprintf("wrong length of Encrypted Public Key: %v",
				pubKeyEncrypted)
			return nil, newError(ErrSeriesSerialization, str, nil)
		}
		serialized = append(serialized, pubKeyEncrypted...)

		if len(row.privKeysEncrypted) == 0 {
			privKeyEncrypted = seriesNullPrivKey[:]
		} else {
			privKeyEncrypted = row.privKeysEncrypted[i]
		}

		if privKeyEncrypted == nil {
			serialized = append(serialized, seriesNullPrivKey[:]...)
		} else if len(privKeyEncrypted) != seriesKeyLength {
			str := fmt.Sprintf("wrong length of Encrypted Private Key: %v",
				len(privKeyEncrypted))
			return nil, newError(ErrSeriesSerialization, str, nil)
		} else {
			serialized = append(serialized, privKeyEncrypted...)
		}
	}
	return serialized, nil
}

// uint32ToBytes converts a 32 bit unsigned integer into a 4-byte slice in
// little-endian order: 1 -> [1 0 0 0].
func uint32ToBytes(number uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, number)
	return buf
}

// bytesToUint32 converts a 4-byte slice in little-endian order into a 32 bit
// unsigned integer: [1 0 0 0] -> 1.
func bytesToUint32(encoded []byte) uint32 {
	return binary.LittleEndian.Uint32(encoded)
}
