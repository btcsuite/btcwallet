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

	"github.com/conformal/btcwallet/snacl"
	"github.com/conformal/btcwallet/waddrmgr"
	"github.com/conformal/btcwallet/walletdb"
)

// These constants define the serialized length for a given encrypted extended
//  public or private key.
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

// putPool stores a voting pool in the database, creating a bucket named
// after the voting pool id.
func putPool(tx walletdb.Tx, votingPoolID []byte) error {
	_, err := tx.RootBucket().CreateBucket(votingPoolID)
	if err != nil {
		str := fmt.Sprintf("cannot create voting pool %v", votingPoolID)
		return managerError(waddrmgr.ErrDatabase, str, err)
	}
	return nil
}

// loadAllSeries returns a map of all the series stored inside a voting pool
// bucket, keyed by id.
func loadAllSeries(tx walletdb.Tx, votingPoolID []byte) (map[uint32]*dbSeriesRow, error) {
	bucket := tx.RootBucket().Bucket(votingPoolID)
	allSeries := make(map[uint32]*dbSeriesRow)
	err := bucket.ForEach(
		func(k, v []byte) error {
			seriesID := bytesToUint32(k)
			series, err := deserializeSeriesRow(v)
			if err != nil {
				str := fmt.Sprintf("cannot deserialize series %v", v)
				return managerError(waddrmgr.ErrSeriesStorage, str, err)
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
func existsPool(tx walletdb.Tx, votingPoolID []byte) bool {
	bucket := tx.RootBucket().Bucket(votingPoolID)
	return bucket != nil
}

// putSeries stores the given series inside a voting pool bucket named after
// votingPoolID. The voting pool bucket does not need to be created beforehand.
func putSeries(tx walletdb.Tx, votingPoolID []byte, version, ID uint32, active bool, reqSigs uint32, pubKeysEncrypted, privKeysEncrypted [][]byte) error {
	row := &dbSeriesRow{
		version:           version,
		active:            active,
		reqSigs:           reqSigs,
		pubKeysEncrypted:  pubKeysEncrypted,
		privKeysEncrypted: privKeysEncrypted,
	}
	return putSeriesRow(tx, votingPoolID, ID, row)
}

// putSeriesRow stores the given series row inside a voting pool bucket named
// after votingPoolID. The voting pool bucket does not need to be created
// beforehand.
func putSeriesRow(tx walletdb.Tx, votingPoolID []byte, ID uint32, row *dbSeriesRow) error {
	bucket, err := tx.RootBucket().CreateBucketIfNotExists(votingPoolID)
	if err != nil {
		str := fmt.Sprintf("cannot create bucket %v", votingPoolID)
		return managerError(waddrmgr.ErrDatabase, str, err)
	}
	serialized, err := serializeSeriesRow(row)
	if err != nil {
		str := fmt.Sprintf("cannot serialize series %v", row)
		return managerError(waddrmgr.ErrSeriesStorage, str, err)
	}
	err = bucket.Put(uint32ToBytes(ID), serialized)
	if err != nil {
		str := fmt.Sprintf("cannot put series %v into bucket %v", serialized, votingPoolID)
		return managerError(waddrmgr.ErrSeriesStorage, str, err)
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
		str := fmt.Sprintf("serialized series is too short: %v",
			serializedSeries)
		return nil, managerError(waddrmgr.ErrSeriesStorage, str, nil)
	}

	// Maximum number of public keys is 15 and the same for public keys
	// this gives us an upper bound.
	if len(serializedSeries) > seriesMaxSerial {
		str := fmt.Sprintf("serialized series is too long: %v",
			serializedSeries)
		return nil, managerError(waddrmgr.ErrSeriesStorage, str, nil)
	}

	// Keeps track of the position of the next set of bytes to deserialize.
	current := 0
	row := dbSeriesRow{}

	row.version = bytesToUint32(serializedSeries[current : current+4])
	if row.version > seriesMaxVersion {
		str := fmt.Sprintf("deserialization supports up to version %v not %v",
			seriesMaxVersion, row.version)
		return nil, managerError(waddrmgr.ErrSeriesVersion, str, nil)
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
		str := fmt.Sprintf("serialized series has not enough data: %v",
			serializedSeries)
		return nil, managerError(waddrmgr.ErrSeriesStorage, str, nil)
	} else if len(serializedSeries) > current+int(nKeys)*seriesKeyLength*2 {
		str := fmt.Sprintf("serialized series has too much data: %v",
			serializedSeries)
		return nil, managerError(waddrmgr.ErrSeriesStorage, str, nil)
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
		return nil, managerError(waddrmgr.ErrSeriesStorage, str, nil)
	}

	if row.version > seriesMaxVersion {
		str := fmt.Sprintf("serialization supports up to version %v, not %v",
			seriesMaxVersion, row.version)
		return nil, managerError(waddrmgr.ErrSeriesVersion, str, nil)
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
			return nil, managerError(waddrmgr.ErrSeriesStorage, str, nil)
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
			return nil, managerError(waddrmgr.ErrSeriesStorage, str, nil)
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
