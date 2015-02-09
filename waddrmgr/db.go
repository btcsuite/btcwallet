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

package waddrmgr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/fastsha256"
)

const (
	// LatestMgrVersion is the most recent manager version.
	LatestMgrVersion = 1
)

// maybeConvertDbError converts the passed error to a ManagerError with an
// error code of ErrDatabase if it is not already a ManagerError.  This is
// useful for potential errors returned from managed transaction an other parts
// of the walletdb database.
func maybeConvertDbError(err error) error {
	// When the error is already a ManagerError, just return it.
	if _, ok := err.(ManagerError); ok {
		return err
	}

	return managerError(ErrDatabase, err.Error(), err)
}

// syncStatus represents a address synchronization status stored in the
// database.
type syncStatus uint8

// These constants define the various supported sync status types.
//
// NOTE: These are currently unused but are being defined for the possibility of
// supporting sync status on a per-address basis.
const (
	ssNone    syncStatus = 0 // not iota as they need to be stable for db
	ssPartial syncStatus = 1
	ssFull    syncStatus = 2
)

// addressType represents a type of address stored in the database.
type addressType uint8

// These constants define the various supported address types.
const (
	adtChain  addressType = 0 // not iota as they need to be stable for db
	adtImport addressType = 1
	adtScript addressType = 2
)

// falseByte and trueByte are consts used to serialize boolean values.
const (
	falseByte byte = iota
	trueByte
)

// boolAsByte converts a bool to a byte.
func boolAsByte(b bool) byte {
	if b {
		return trueByte
	}
	return falseByte
}

// byteAsBool converts a byte to a bool.
func byteAsBool(b byte) bool {
	return b != 0
}

// accountType represents a type of address stored in the database.
type accountType uint8

// These constants define the various supported account types.
const (
	actBIP0044 accountType = 0 // not iota as they need to be stable for db
)

// dbAccountRow houses information stored about an account in the database.
type dbAccountRow struct {
	acctType accountType
	rawData  []byte // Varies based on account type field.
}

// dbBIP0044AccountRow houses additional information stored about a BIP0044
// account in the database.
type dbBIP0044AccountRow struct {
	dbAccountRow
	pubKeyEncrypted   []byte
	privKeyEncrypted  []byte
	nextExternalIndex uint32
	nextInternalIndex uint32
	name              string
}

// dbAddressRow houses common information stored about an address in the
// database.
type dbAddressRow struct {
	addrType     addressType
	account      uint32
	addTime      uint64
	syncStatus   syncStatus
	watchingOnly bool
	rawData      []byte // Varies based on address type field.
}

// dbChainAddressRow houses additional information stored about a chained
// address in the database.
type dbChainAddressRow struct {
	dbAddressRow
	branch uint32
	index  uint32
}

// dbImportedP2PKHAddressRow houses additional information stored about an imported
// P2PKH address in the database.
type dbImportedHash160AddressRow struct {
	dbAddressRow
	encryptedHash160 []byte
}

// dbImportedPubKeyAddressRow houses additional information stored about an imported
// public key address in the database.
type dbImportedPubKeyAddressRow struct {
	dbAddressRow
	encryptedPubKey  []byte
	encryptedPrivKey []byte
}

// dbImportedAddressRow houses additional information stored about a script
// address in the database.
type dbScriptAddressRow struct {
	dbAddressRow
	encryptedHash   []byte
	encryptedScript []byte
}

// Key names for various database fields.
var (
	// Bucket names.
	acctBucketName        = []byte("acct")
	addrBucketName        = []byte("addr")
	addrAcctIdxBucketName = []byte("addracctidx")
	mainBucketName        = []byte("main")
	syncBucketName        = []byte("sync")

	// Db related key names (main bucket).
	mgrVersionName    = []byte("mgrver")
	mgrCreateDateName = []byte("mgrcreated")

	// Crypto related key names (main bucket).
	masterPrivKeyName   = []byte("mpriv")
	masterPubKeyName    = []byte("mpub")
	cryptoPrivKeyName   = []byte("cpriv")
	cryptoPubKeyName    = []byte("cpub")
	cryptoScriptKeyName = []byte("cscript")
	watchingOnlyName    = []byte("watchonly")

	// Sync related key names (sync bucket).
	syncedToName     = []byte("syncedto")
	startBlockName   = []byte("startblock")
	recentBlocksName = []byte("recentblocks")

	// Account related key names (account bucket).
	acctNumAcctsName = []byte("numaccts")
)

// fetchMasterKeyParams loads the master key parameters needed to derive them
// (when given the correct user-supplied passphrase) from the database.  Either
// returned value can be nil, but in practice only the private key params will
// be nil for a watching-only database.
func fetchMasterKeyParams(tx walletdb.Tx) ([]byte, []byte, error) {
	bucket := tx.RootBucket().Bucket(mainBucketName)

	// Load the master public key parameters.  Required.
	val := bucket.Get(masterPubKeyName)
	if val == nil {
		str := "required master public key parameters not stored in " +
			"database"
		return nil, nil, managerError(ErrDatabase, str, nil)
	}
	pubParams := make([]byte, len(val))
	copy(pubParams, val)

	// Load the master private key parameters if they were stored.
	var privParams []byte
	val = bucket.Get(masterPrivKeyName)
	if val != nil {
		privParams = make([]byte, len(val))
		copy(privParams, val)
	}

	return pubParams, privParams, nil
}

// putMasterKeyParams stores the master key parameters needed to derive them
// to the database.  Either parameter can be nil in which case no value is
// written for the parameter.
func putMasterKeyParams(tx walletdb.Tx, pubParams, privParams []byte) error {
	bucket := tx.RootBucket().Bucket(mainBucketName)

	if privParams != nil {
		err := bucket.Put(masterPrivKeyName, privParams)
		if err != nil {
			str := "failed to store master private key parameters"
			return managerError(ErrDatabase, str, err)
		}
	}

	if pubParams != nil {
		err := bucket.Put(masterPubKeyName, pubParams)
		if err != nil {
			str := "failed to store master public key parameters"
			return managerError(ErrDatabase, str, err)
		}
	}

	return nil
}

// fetchCryptoKeys loads the encrypted crypto keys which are in turn used to
// protect the extended keys, imported keys, and scripts.  Any of the returned
// values can be nil, but in practice only the crypto private and script keys
// will be nil for a watching-only database.
func fetchCryptoKeys(tx walletdb.Tx) ([]byte, []byte, []byte, error) {
	bucket := tx.RootBucket().Bucket(mainBucketName)

	// Load the crypto public key parameters.  Required.
	val := bucket.Get(cryptoPubKeyName)
	if val == nil {
		str := "required encrypted crypto public not stored in database"
		return nil, nil, nil, managerError(ErrDatabase, str, nil)
	}
	pubKey := make([]byte, len(val))
	copy(pubKey, val)

	// Load the crypto private key parameters if they were stored.
	var privKey []byte
	val = bucket.Get(cryptoPrivKeyName)
	if val != nil {
		privKey = make([]byte, len(val))
		copy(privKey, val)
	}

	// Load the crypto script key parameters if they were stored.
	var scriptKey []byte
	val = bucket.Get(cryptoScriptKeyName)
	if val != nil {
		scriptKey = make([]byte, len(val))
		copy(scriptKey, val)
	}

	return pubKey, privKey, scriptKey, nil
}

// putCryptoKeys stores the encrypted crypto keys which are in turn used to
// protect the extended and imported keys.  Either parameter can be nil in which
// case no value is written for the parameter.
func putCryptoKeys(tx walletdb.Tx, pubKeyEncrypted, privKeyEncrypted, scriptKeyEncrypted []byte) error {
	bucket := tx.RootBucket().Bucket(mainBucketName)

	if pubKeyEncrypted != nil {
		err := bucket.Put(cryptoPubKeyName, pubKeyEncrypted)
		if err != nil {
			str := "failed to store encrypted crypto public key"
			return managerError(ErrDatabase, str, err)
		}
	}

	if privKeyEncrypted != nil {
		err := bucket.Put(cryptoPrivKeyName, privKeyEncrypted)
		if err != nil {
			str := "failed to store encrypted crypto private key"
			return managerError(ErrDatabase, str, err)
		}
	}

	if scriptKeyEncrypted != nil {
		err := bucket.Put(cryptoScriptKeyName, scriptKeyEncrypted)
		if err != nil {
			str := "failed to store encrypted crypto script key"
			return managerError(ErrDatabase, str, err)
		}
	}

	return nil
}

// fetchWatchingOnly loads the watching-only flag from the database.
func fetchWatchingOnly(tx walletdb.Tx) (bool, error) {
	bucket := tx.RootBucket().Bucket(mainBucketName)

	buf := bucket.Get(watchingOnlyName)
	if len(buf) != 1 {
		str := "malformed watching-only flag stored in database"
		return false, managerError(ErrDatabase, str, nil)
	}

	return buf[0] != 0, nil
}

// putWatchingOnly stores the watching-only flag to the database.
func putWatchingOnly(tx walletdb.Tx, watchingOnly bool) error {
	bucket := tx.RootBucket().Bucket(mainBucketName)

	var encoded byte
	if watchingOnly {
		encoded = 1
	}

	if err := bucket.Put(watchingOnlyName, []byte{encoded}); err != nil {
		str := "failed to store watching only flag"
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

// uint32ToBytes converts a 32 bit unsigned integer into a 4-byte slice in
// little-endian order: 1 -> [1 0 0 0].
func uint32ToBytes(number uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, number)
	return buf
}

// deserializeAccountRow deserializes the passed serialized account information.
// This is used as a common base for the various account types to deserialize
// the common parts.
func deserializeAccountRow(accountID []byte, serializedAccount []byte) (*dbAccountRow, error) {
	// The serialized account format is:
	//   <acctType><rdlen><rawdata>
	//
	// 1 byte acctType + 4 bytes raw data length + raw data

	// Given the above, the length of the entry must be at a minimum
	// the constant value sizes.
	if len(serializedAccount) < 5 {
		str := fmt.Sprintf("malformed serialized account for key %x",
			accountID)
		return nil, managerError(ErrDatabase, str, nil)
	}

	row := dbAccountRow{}
	row.acctType = accountType(serializedAccount[0])
	rdlen := binary.LittleEndian.Uint32(serializedAccount[1:5])
	row.rawData = make([]byte, rdlen)
	copy(row.rawData, serializedAccount[5:5+rdlen])

	return &row, nil
}

// serializeAccountRow returns the serialization of the passed account row.
func serializeAccountRow(row *dbAccountRow) []byte {
	// The serialized account format is:
	//   <acctType><rdlen><rawdata>
	//
	// 1 byte acctType + 4 bytes raw data length + raw data
	rdlen := len(row.rawData)
	buf := make([]byte, 5+rdlen)
	buf[0] = byte(row.acctType)
	binary.LittleEndian.PutUint32(buf[1:5], uint32(rdlen))
	copy(buf[5:5+rdlen], row.rawData)
	return buf
}

// deserializeBIP0044AccountRow deserializes the raw data from the passed
// account row as a BIP0044 account.
func deserializeBIP0044AccountRow(accountID []byte, row *dbAccountRow) (*dbBIP0044AccountRow, error) {
	// The serialized BIP0044 account raw data format is:
	//   <encpubkeylen><encpubkey><encprivkeylen><encprivkey><nextextidx>
	//   <nextintidx><namelen><name>
	//
	// 4 bytes encrypted pubkey len + encrypted pubkey + 4 bytes encrypted
	// privkey len + encrypted privkey + 4 bytes next external index +
	// 4 bytes next internal index + 4 bytes name len + name

	// Given the above, the length of the entry must be at a minimum
	// the constant value sizes.
	if len(row.rawData) < 20 {
		str := fmt.Sprintf("malformed serialized bip0044 account for "+
			"key %x", accountID)
		return nil, managerError(ErrDatabase, str, nil)
	}

	retRow := dbBIP0044AccountRow{
		dbAccountRow: *row,
	}

	pubLen := binary.LittleEndian.Uint32(row.rawData[0:4])
	retRow.pubKeyEncrypted = make([]byte, pubLen)
	copy(retRow.pubKeyEncrypted, row.rawData[4:4+pubLen])
	offset := 4 + pubLen
	privLen := binary.LittleEndian.Uint32(row.rawData[offset : offset+4])
	offset += 4
	retRow.privKeyEncrypted = make([]byte, privLen)
	copy(retRow.privKeyEncrypted, row.rawData[offset:offset+privLen])
	offset += privLen
	retRow.nextExternalIndex = binary.LittleEndian.Uint32(row.rawData[offset : offset+4])
	offset += 4
	retRow.nextInternalIndex = binary.LittleEndian.Uint32(row.rawData[offset : offset+4])
	offset += 4
	nameLen := binary.LittleEndian.Uint32(row.rawData[offset : offset+4])
	offset += 4
	retRow.name = string(row.rawData[offset : offset+nameLen])

	return &retRow, nil
}

// serializeBIP0044AccountRow returns the serialization of the raw data field
// for a BIP0044 account.
func serializeBIP0044AccountRow(encryptedPubKey,
	encryptedPrivKey []byte, nextExternalIndex, nextInternalIndex uint32,
	name string) []byte {
	// The serialized BIP0044 account raw data format is:
	//   <encpubkeylen><encpubkey><encprivkeylen><encprivkey><nextextidx>
	//   <nextintidx><namelen><name>
	//
	// 4 bytes encrypted pubkey len + encrypted pubkey + 4 bytes encrypted
	// privkey len + encrypted privkey + 4 bytes next external index +
	// 4 bytes next internal index + 4 bytes name len + name
	pubLen := uint32(len(encryptedPubKey))
	privLen := uint32(len(encryptedPrivKey))
	nameLen := uint32(len(name))
	rawData := make([]byte, 20+pubLen+privLen+nameLen)
	binary.LittleEndian.PutUint32(rawData[0:4], pubLen)
	copy(rawData[4:4+pubLen], encryptedPubKey)
	offset := 4 + pubLen
	binary.LittleEndian.PutUint32(rawData[offset:offset+4], privLen)
	offset += 4
	copy(rawData[offset:offset+privLen], encryptedPrivKey)
	offset += privLen
	binary.LittleEndian.PutUint32(rawData[offset:offset+4], nextExternalIndex)
	offset += 4
	binary.LittleEndian.PutUint32(rawData[offset:offset+4], nextInternalIndex)
	offset += 4
	binary.LittleEndian.PutUint32(rawData[offset:offset+4], nameLen)
	offset += 4
	copy(rawData[offset:offset+nameLen], name)
	return rawData
}

// fetchAccountInfo loads information about the passed account from the
// database.
func fetchAccountInfo(tx walletdb.Tx, account uint32) (interface{}, error) {
	bucket := tx.RootBucket().Bucket(acctBucketName)

	accountID := uint32ToBytes(account)
	serializedRow := bucket.Get(accountID)
	if serializedRow == nil {
		str := fmt.Sprintf("account %d not found", account)
		return nil, managerError(ErrAccountNotFound, str, nil)
	}

	row, err := deserializeAccountRow(accountID, serializedRow)
	if err != nil {
		return nil, err
	}

	switch row.acctType {
	case actBIP0044:
		return deserializeBIP0044AccountRow(accountID, row)
	}

	str := fmt.Sprintf("unsupported account type '%d'", row.acctType)
	return nil, managerError(ErrDatabase, str, nil)
}

// putAccountRow stores the provided account information to the database.  This
// is used a common base for storing the various account types.
func putAccountRow(tx walletdb.Tx, account uint32, row *dbAccountRow) error {
	bucket := tx.RootBucket().Bucket(acctBucketName)

	// Write the serialized value keyed by the account number.
	err := bucket.Put(uint32ToBytes(account), serializeAccountRow(row))
	if err != nil {
		str := fmt.Sprintf("failed to store account %d", account)
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

// putAccountInfo stores the provided account information to the database.
func putAccountInfo(tx walletdb.Tx, account uint32, encryptedPubKey,
	encryptedPrivKey []byte, nextExternalIndex, nextInternalIndex uint32,
	name string) error {

	rawData := serializeBIP0044AccountRow(encryptedPubKey, encryptedPrivKey,
		nextExternalIndex, nextInternalIndex, name)

	acctRow := dbAccountRow{
		acctType: actBIP0044,
		rawData:  rawData,
	}
	return putAccountRow(tx, account, &acctRow)
}

// fetchNumAccounts loads the number of accounts that have been created from
// the database.
func fetchNumAccounts(tx walletdb.Tx) (uint32, error) {
	bucket := tx.RootBucket().Bucket(acctBucketName)

	val := bucket.Get(acctNumAcctsName)
	if val == nil {
		str := "required num accounts not stored in database"
		return 0, managerError(ErrDatabase, str, nil)
	}

	return binary.LittleEndian.Uint32(val), nil
}

// putNumAccounts stores the number of accounts that have been created to the
// database.
func putNumAccounts(tx walletdb.Tx, numAccounts uint32) error {
	bucket := tx.RootBucket().Bucket(acctBucketName)

	var val [4]byte
	binary.LittleEndian.PutUint32(val[:], numAccounts)
	err := bucket.Put(acctNumAcctsName, val[:])
	if err != nil {
		str := "failed to store num accounts"
		return managerError(ErrDatabase, str, err)
	}

	return nil
}

// fetchAddressRow loads address information for the provided address id from
// the database.  This is used as a common base for the various address types
// to load the common information.

// deserializeAddressRow deserializes the passed serialized address information.
// This is used as a common base for the various address types to deserialize
// the common parts.
func deserializeAddressRow(addressID, serializedAddress []byte) (*dbAddressRow, error) {
	// The serialized address format is:
	//   <addrType><account><addedTime><syncStatus><watchingOnly><rawdata>
	//
	// 1 byte addrType + 4 bytes account + 8 bytes addTime + 1 byte
	// syncStatus + 1 byte watchingOnly + 4 bytes raw data length + raw data

	// Given the above, the length of the entry must be at a minimum
	// the constant value sizes.
	if len(serializedAddress) < 19 {
		str := fmt.Sprintf("malformed serialized address for key %s",
			addressID)
		return nil, managerError(ErrDatabase, str, nil)
	}

	row := dbAddressRow{}
	row.addrType = addressType(serializedAddress[0])
	row.account = binary.LittleEndian.Uint32(serializedAddress[1:5])
	row.addTime = binary.LittleEndian.Uint64(serializedAddress[5:13])
	row.syncStatus = syncStatus(serializedAddress[13])
	watchingOnly := byteAsBool(serializedAddress[14])
	row.watchingOnly = watchingOnly
	rdlen := binary.LittleEndian.Uint32(serializedAddress[15:19])
	row.rawData = make([]byte, rdlen)
	copy(row.rawData, serializedAddress[19:19+rdlen])

	return &row, nil
}

// serializeAddressRow returns the serialization of the passed address row.
func serializeAddressRow(row *dbAddressRow) []byte {
	// The serialized address format is:
	//   <addrType><account><addedTime><syncStatus><watchingOnly><rawdata>
	//   <rawdata>
	//
	// 1 byte addrType + 4 bytes account + 8 bytes addTime + 1 byte
	// syncStatus + 1 byte watchingOnly + 4 bytes raw data length + raw data
	rdlen := len(row.rawData)
	buf := make([]byte, 19+rdlen)
	buf[0] = byte(row.addrType)
	binary.LittleEndian.PutUint32(buf[1:5], row.account)
	binary.LittleEndian.PutUint64(buf[5:13], row.addTime)
	buf[13] = byte(row.syncStatus)
	buf[14] = boolAsByte(row.watchingOnly)
	binary.LittleEndian.PutUint32(buf[15:19], uint32(rdlen))
	copy(buf[19:19+rdlen], row.rawData)
	return buf
}

// deserializeChainedAddress deserializes the raw data from the passed address
// row as a chained address.
func deserializeChainedAddress(addressID []byte, row *dbAddressRow) (*dbChainAddressRow, error) {
	// The serialized chain address raw data format is:
	//   <branch><index>
	//
	// 4 bytes branch + 4 bytes address index
	if len(row.rawData) != 8 {
		str := fmt.Sprintf("malformed serialized chained address for "+
			"key %s", addressID)
		return nil, managerError(ErrDatabase, str, nil)
	}

	retRow := dbChainAddressRow{
		dbAddressRow: *row,
	}

	retRow.branch = binary.LittleEndian.Uint32(row.rawData[0:4])
	retRow.index = binary.LittleEndian.Uint32(row.rawData[4:8])

	return &retRow, nil
}

// serializeChainedAddress returns the serialization of the raw data field for
// a chained address.
func serializeChainedAddress(branch, index uint32) []byte {
	// The serialized chain address raw data format is:
	//   <branch><index>
	//
	// 4 bytes branch + 4 bytes address index
	rawData := make([]byte, 8)
	binary.LittleEndian.PutUint32(rawData[0:4], branch)
	binary.LittleEndian.PutUint32(rawData[4:8], index)
	return rawData
}

// deserializeImportedHash160AddressRow deserializes the raw data from the passed address
// row as an imported hash 160 address.
func deserializeImportedHash160AddressRow(addressID []byte, row *dbAddressRow) (*dbImportedHash160AddressRow, error) {
	// The serialized imported address raw data format is:
	//   <encpkhashlen><encpkhash>
	//
	// 4 bytes encrypted pkhash len + encrypted pkhash +

	// Given the above, the length of the entry must be at a minimum
	// the constant value sizes.
	if len(row.rawData) < 4 {
		str := fmt.Sprintf("malformed serialized imported address for "+
			"key %s", addressID)
		return nil, managerError(ErrDatabase, str, nil)
	}

	retRow := dbImportedHash160AddressRow{
		dbAddressRow: *row,
	}

	var offset uint32
	pkHashLen := binary.LittleEndian.Uint32(row.rawData[offset : offset+4])
	offset += 4
	retRow.encryptedHash160 = make([]byte, pkHashLen)
	copy(retRow.encryptedHash160, row.rawData[offset:offset+pkHashLen])

	return &retRow, nil
}

// serializeImportedHash160AddressRow returns the serialization of the raw data field for
// an imported hash 160 address.
func serializeImportedHash160AddressRow(encryptedHash160 []byte) []byte {
	// The serialized imported address raw data format is:
	//   <encpkhashlen><encpkhash>
	//
	// 4 bytes encrypted pkhash len + encrypted pkhash +

	pkHashLen := uint32(len(encryptedHash160))
	rawData := make([]byte, 8+pkHashLen)

	var offset uint32
	binary.LittleEndian.PutUint32(rawData[offset:offset+4], pkHashLen)
	offset += 4
	copy(rawData[offset:offset+pkHashLen], encryptedHash160)

	return rawData
}

// deserializeImportedPubKeyAddress deserializes the raw data from the passed address
// row as an imported pubkey address.
func deserializeImportedPubKeyAddress(addressID []byte, row *dbAddressRow) (*dbImportedPubKeyAddressRow, error) {
	// The serialized imported address raw data format is:
	//   <encpubkeylen><encpubkey><encprivkeylen><encprivkey>
	//
	// 4 bytes encrypted pubkey len + encrypted pubkey +
	// 4 bytes encrypted privkey len + encrypted privkey

	// Given the above, the length of the entry must be at a minimum
	// the constant value sizes.
	if len(row.rawData) < 8 {
		str := fmt.Sprintf("malformed serialized imported address for "+
			"key %s", addressID)
		return nil, managerError(ErrDatabase, str, nil)
	}

	retRow := dbImportedPubKeyAddressRow{
		dbAddressRow: *row,
	}

	var offset uint32
	pubLen := binary.LittleEndian.Uint32(row.rawData[offset : offset+4])
	offset += 4
	retRow.encryptedPubKey = make([]byte, pubLen)
	copy(retRow.encryptedPubKey, row.rawData[offset:offset+pubLen])
	offset += pubLen

	privLen := binary.LittleEndian.Uint32(row.rawData[offset : offset+4])
	offset += 4
	retRow.encryptedPrivKey = make([]byte, privLen)
	copy(retRow.encryptedPrivKey, row.rawData[offset:offset+privLen])

	return &retRow, nil
}

// serializeImportedPubKeyAddress returns the serialization of the raw data field for
// an imported address.
func serializeImportedPubKeyAddress(encryptedPKHash, encryptedPubKey, encryptedPrivKey []byte) []byte {
	// The serialized imported address raw data format is:
	//   <encpubkeylen><encpubkey><encprivkeylen><encprivkey>
	//
	// 4 bytes encrypted pubkey len + encrypted pubkey +
	// 4 bytes encrypted privkey len + encrypted privkey
	pubLen := uint32(len(encryptedPubKey))
	privLen := uint32(len(encryptedPrivKey))
	rawData := make([]byte, 8+pubLen+privLen)

	var offset uint32
	binary.LittleEndian.PutUint32(rawData[offset:offset+4], pubLen)
	offset += 4
	copy(rawData[offset:offset+pubLen], encryptedPubKey)
	offset += pubLen

	binary.LittleEndian.PutUint32(rawData[offset:offset+4], privLen)
	offset += 4
	copy(rawData[offset:offset+privLen], encryptedPrivKey)

	return rawData
}

// deserializeScriptAddress deserializes the raw data from the passed address
// row as a script address.
func deserializeScriptAddress(addressID []byte, row *dbAddressRow) (*dbScriptAddressRow, error) {
	// The serialized script address raw data format is:
	//   <encscripthashlen><encscripthash><encscriptlen><encscript>
	//
	// 4 bytes encrypted script hash len + encrypted script hash + 4 bytes
	// encrypted script len + encrypted script

	// Given the above, the length of the entry must be at a minimum
	// the constant value sizes.
	if len(row.rawData) < 8 {
		str := fmt.Sprintf("malformed serialized script address for "+
			"key %s", addressID)
		return nil, managerError(ErrDatabase, str, nil)
	}

	retRow := dbScriptAddressRow{
		dbAddressRow: *row,
	}

	hashLen := binary.LittleEndian.Uint32(row.rawData[0:4])
	retRow.encryptedHash = make([]byte, hashLen)
	copy(retRow.encryptedHash, row.rawData[4:4+hashLen])
	offset := 4 + hashLen
	scriptLen := binary.LittleEndian.Uint32(row.rawData[offset : offset+4])
	offset += 4
	retRow.encryptedScript = make([]byte, scriptLen)
	copy(retRow.encryptedScript, row.rawData[offset:offset+scriptLen])

	return &retRow, nil
}

// serializeScriptAddress returns the serialization of the raw data field for
// a script address.
func serializeScriptAddress(encryptedHash, encryptedScript []byte) []byte {
	// The serialized script address raw data format is:
	//   <encscripthashlen><encscripthash><encscriptlen><encscript>
	//
	// 4 bytes encrypted script hash len + encrypted script hash + 4 bytes
	// encrypted script len + encrypted script

	hashLen := uint32(len(encryptedHash))
	scriptLen := uint32(len(encryptedScript))
	rawData := make([]byte, 8+hashLen+scriptLen)
	binary.LittleEndian.PutUint32(rawData[0:4], hashLen)
	copy(rawData[4:4+hashLen], encryptedHash)
	offset := 4 + hashLen
	binary.LittleEndian.PutUint32(rawData[offset:offset+4], scriptLen)
	offset += 4
	copy(rawData[offset:offset+scriptLen], encryptedScript)
	return rawData
}

// fetchAddress loads address information for the provided address id from
// the database.  The returned value is one of the address rows for the specific
// address type.  The caller should use type assertions to ascertain the type.
func fetchAddress(tx walletdb.Tx, addressID []byte) (interface{}, error) {
	bucket := tx.RootBucket().Bucket(addrBucketName)

	addrHash := fastsha256.Sum256(addressID)
	serializedRow := bucket.Get(addrHash[:])
	if serializedRow == nil {
		str := "address not found"
		return nil, managerError(ErrAddressNotFound, str, nil)
	}

	row, err := deserializeAddressRow(addressID, serializedRow)
	if err != nil {
		return nil, err
	}

	switch row.addrType {
	case adtChain:
		return deserializeChainedAddress(addressID, row)
	case adtImport:
		if row.watchingOnly {
			return deserializeImportedHash160AddressRow(addressID, row)
		} else {
			return deserializeImportedPubKeyAddress(addressID, row)
		}
	case adtScript:
		return deserializeScriptAddress(addressID, row)
	}

	str := fmt.Sprintf("unsupported address type '%d'", row.addrType)
	return nil, managerError(ErrDatabase, str, nil)
}

// putAddress stores the provided address information to the database.  This
// is used a common base for storing the various address types.
func putAddress(tx walletdb.Tx, addressID []byte, row *dbAddressRow) error {
	bucket := tx.RootBucket().Bucket(addrBucketName)

	// Write the serialized value keyed by the hash of the address.  The
	// additional hash is used to conceal the actual address while still
	// allowed keyed lookups.
	addrHash := fastsha256.Sum256(addressID)
	err := bucket.Put(addrHash[:], serializeAddressRow(row))
	if err != nil {
		str := fmt.Sprintf("failed to store address %x", addressID)
		return managerError(ErrDatabase, str, err)
	}

	return nil
}

// putChainedAddress stores the provided chained address information to the
// database.
func putChainedAddress(tx walletdb.Tx, addressID []byte, account uint32,
	status syncStatus, watchingOnly bool, branch, index uint32) error {

	addrRow := dbAddressRow{
		addrType:     adtChain,
		account:      account,
		addTime:      uint64(time.Now().Unix()),
		syncStatus:   status,
		watchingOnly: watchingOnly,
		rawData:      serializeChainedAddress(branch, index),
	}
	if err := putAddress(tx, addressID, &addrRow); err != nil {
		return err
	}

	// Update the next index for the appropriate internal or external
	// branch.
	accountID := uint32ToBytes(account)
	bucket := tx.RootBucket().Bucket(acctBucketName)
	serializedAccount := bucket.Get(accountID)

	// Deserialize the account row.
	row, err := deserializeAccountRow(accountID, serializedAccount)

	if err != nil {
		return err
	}
	arow, err := deserializeBIP0044AccountRow(accountID, row)
	if err != nil {
		return err
	}

	// Increment the appropriate next index depending on whether the branch
	// is internal or external.
	nextExternalIndex := arow.nextExternalIndex
	nextInternalIndex := arow.nextInternalIndex
	if branch == internalBranch {
		nextInternalIndex = index + 1
	} else {
		nextExternalIndex = index + 1
	}

	// Reserialize the account with the updated index and store it.
	row.rawData = serializeBIP0044AccountRow(arow.pubKeyEncrypted,
		arow.privKeyEncrypted, nextExternalIndex, nextInternalIndex,
		arow.name)
	err = bucket.Put(accountID, serializeAccountRow(row))
	if err != nil {
		str := fmt.Sprintf("failed to update next index for "+
			"address %x, account %d", addressID, account)
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

// putImportedPubKeyAddress stores the provided imported address information to the
// database.
func putImportedPubKeyAddress(tx walletdb.Tx, addressID []byte, account uint32,
	status syncStatus, watchingOnly bool, encryptedPKHash, encryptedPubKey, encryptedPrivKey []byte) error {

	rawData := serializeImportedPubKeyAddress(encryptedPKHash, encryptedPubKey, encryptedPrivKey)
	addrRow := dbAddressRow{
		addrType:     adtImport,
		account:      account,
		addTime:      uint64(time.Now().Unix()),
		syncStatus:   status,
		watchingOnly: watchingOnly,
		rawData:      rawData,
	}
	return putAddress(tx, addressID, &addrRow)
}

// putImportedP2PKHAddress stores the provided imported address information to the
// database.
func putImportedP2PKHAddress(tx walletdb.Tx, addressID []byte, account uint32,
	status syncStatus, encryptedHash160 []byte) error {

	rawData := serializeImportedHash160AddressRow(encryptedHash160)
	addrRow := dbAddressRow{
		addrType:     adtImport,
		account:      account,
		addTime:      uint64(time.Now().Unix()),
		syncStatus:   status,
		watchingOnly: true,
		rawData:      rawData,
	}
	return putAddress(tx, addressID, &addrRow)
}

// putScriptAddress stores the provided script address information to the
// database.
func putScriptAddress(tx walletdb.Tx, addressID []byte, account uint32,
	status syncStatus, watchingOnly bool, encryptedHash, encryptedScript []byte) error {

	rawData := serializeScriptAddress(encryptedHash, encryptedScript)
	addrRow := dbAddressRow{
		addrType:     adtScript,
		account:      account,
		addTime:      uint64(time.Now().Unix()),
		syncStatus:   status,
		watchingOnly: watchingOnly,
		rawData:      rawData,
	}
	if err := putAddress(tx, addressID, &addrRow); err != nil {
		return err
	}

	return nil
}

// existsAddress returns whether or not the address id exists in the database.
func existsAddress(tx walletdb.Tx, addressID []byte) bool {
	bucket := tx.RootBucket().Bucket(addrBucketName)

	addrHash := fastsha256.Sum256(addressID)
	return bucket.Get(addrHash[:]) != nil
}

// fetchAllAddresses loads information about all addresses from the database.
// The returned value is a slice of address rows for each specific address type.
// The caller should use type assertions to ascertain the types.
func fetchAllAddresses(tx walletdb.Tx) ([]interface{}, error) {
	bucket := tx.RootBucket().Bucket(addrBucketName)

	var addrs []interface{}
	err := bucket.ForEach(func(k, v []byte) error {
		// Skip buckets.
		if v == nil {
			return nil
		}

		// Deserialize the address row first to determine the field
		// values.
		row, err := deserializeAddressRow(k, v)
		if err != nil {
			return err
		}

		var addrRow interface{}
		switch row.addrType {
		case adtChain:
			addrRow, err = deserializeChainedAddress(k, row)
		case adtImport:
			addrRow, err = deserializeImportedPubKeyAddress(k, row)
		case adtScript:
			addrRow, err = deserializeScriptAddress(k, row)
		default:
			str := fmt.Sprintf("unsupported address type '%d'",
				row.addrType)
			return managerError(ErrDatabase, str, nil)
		}
		if err != nil {
			return err
		}

		addrs = append(addrs, addrRow)
		return nil
	})
	if err != nil {
		return nil, maybeConvertDbError(err)
	}

	return addrs, nil
}

// deletePrivateKeys removes all private key material from the database.
//
// NOTE: Care should be taken when calling this function.  It is primarily
// intended for use in converting to a watching-only copy.  Removing the private
// keys from the main database without also marking it watching-only will result
// in an unusable database.  It will also make any imported scripts and private
// keys unrecoverable unless there is a backup copy available.
func deletePrivateKeys(tx walletdb.Tx) error {
	bucket := tx.RootBucket().Bucket(mainBucketName)

	// Delete the master private key params and the crypto private and
	// script keys.
	if err := bucket.Delete(masterPrivKeyName); err != nil {
		str := "failed to delete master private key parameters"
		return managerError(ErrDatabase, str, err)
	}
	if err := bucket.Delete(cryptoPrivKeyName); err != nil {
		str := "failed to delete crypto private key"
		return managerError(ErrDatabase, str, err)
	}
	if err := bucket.Delete(cryptoScriptKeyName); err != nil {
		str := "failed to delete crypto script key"
		return managerError(ErrDatabase, str, err)
	}

	// Delete the account extended private key for all accounts.
	bucket = tx.RootBucket().Bucket(acctBucketName)
	err := bucket.ForEach(func(k, v []byte) error {
		// Skip buckets.
		if v == nil || bytes.Equal(k, acctNumAcctsName) {
			return nil
		}

		// Deserialize the account row first to determine the type.
		row, err := deserializeAccountRow(k, v)
		if err != nil {
			return err
		}

		switch row.acctType {
		case actBIP0044:
			arow, err := deserializeBIP0044AccountRow(k, row)
			if err != nil {
				return err
			}

			// Reserialize the account without the private key and
			// store it.
			row.rawData = serializeBIP0044AccountRow(
				arow.pubKeyEncrypted, nil,
				arow.nextExternalIndex, arow.nextInternalIndex,
				arow.name)
			err = bucket.Put(k, serializeAccountRow(row))
			if err != nil {
				str := "failed to delete account private key"
				return managerError(ErrDatabase, str, err)
			}
		}

		return nil
	})
	if err != nil {
		return maybeConvertDbError(err)
	}

	// Delete the private key for all imported addresses.
	bucket = tx.RootBucket().Bucket(addrBucketName)
	err = bucket.ForEach(func(k, v []byte) error {
		// Skip buckets.
		if v == nil {
			return nil
		}

		// Deserialize the address row first to determine the field
		// values.
		row, err := deserializeAddressRow(k, v)
		if err != nil {
			return err
		}

		switch row.addrType {
		case adtImport:
			irow, err := deserializeImportedPubKeyAddress(k, row)
			if err != nil {
				return err
			}

			// Reserialize the imported address without the private
			// key and store it.
			row.rawData = serializeImportedPubKeyAddress(nil,
				irow.encryptedPubKey, nil)
			err = bucket.Put(k, serializeAddressRow(row))
			if err != nil {
				str := "failed to delete imported private key"
				return managerError(ErrDatabase, str, err)
			}

		case adtScript:
			srow, err := deserializeScriptAddress(k, row)
			if err != nil {
				return err
			}

			// Reserialize the script address without the script
			// and store it.
			row.rawData = serializeScriptAddress(srow.encryptedHash,
				nil)
			err = bucket.Put(k, serializeAddressRow(row))
			if err != nil {
				str := "failed to delete imported script"
				return managerError(ErrDatabase, str, err)
			}
		}

		return nil
	})
	if err != nil {
		return maybeConvertDbError(err)
	}

	return nil
}

// fetchSyncedTo loads the block stamp the manager is synced to from the
// database.
func fetchSyncedTo(tx walletdb.Tx) (*BlockStamp, error) {
	bucket := tx.RootBucket().Bucket(syncBucketName)

	// The serialized synced to format is:
	//   <blockheight><blockhash>
	//
	// 4 bytes block height + 32 bytes hash length
	buf := bucket.Get(syncedToName)
	if len(buf) != 36 {
		str := "malformed sync information stored in database"
		return nil, managerError(ErrDatabase, str, nil)
	}

	var bs BlockStamp
	bs.Height = int32(binary.LittleEndian.Uint32(buf[0:4]))
	copy(bs.Hash[:], buf[4:36])
	return &bs, nil
}

// putSyncedTo stores the provided synced to blockstamp to the database.
func putSyncedTo(tx walletdb.Tx, bs *BlockStamp) error {
	bucket := tx.RootBucket().Bucket(syncBucketName)

	// The serialized synced to format is:
	//   <blockheight><blockhash>
	//
	// 4 bytes block height + 32 bytes hash length
	buf := make([]byte, 36)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(bs.Height))
	copy(buf[4:36], bs.Hash[0:32])

	err := bucket.Put(syncedToName, buf)
	if err != nil {
		str := fmt.Sprintf("failed to store sync information %v", bs.Hash)
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

// fetchStartBlock loads the start block stamp for the manager from the
// database.
func fetchStartBlock(tx walletdb.Tx) (*BlockStamp, error) {
	bucket := tx.RootBucket().Bucket(syncBucketName)

	// The serialized start block format is:
	//   <blockheight><blockhash>
	//
	// 4 bytes block height + 32 bytes hash length
	buf := bucket.Get(startBlockName)
	if len(buf) != 36 {
		str := "malformed start block stored in database"
		return nil, managerError(ErrDatabase, str, nil)
	}

	var bs BlockStamp
	bs.Height = int32(binary.LittleEndian.Uint32(buf[0:4]))
	copy(bs.Hash[:], buf[4:36])
	return &bs, nil
}

// putStartBlock stores the provided start block stamp to the database.
func putStartBlock(tx walletdb.Tx, bs *BlockStamp) error {
	bucket := tx.RootBucket().Bucket(syncBucketName)

	// The serialized start block format is:
	//   <blockheight><blockhash>
	//
	// 4 bytes block height + 32 bytes hash length
	buf := make([]byte, 36)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(bs.Height))
	copy(buf[4:36], bs.Hash[0:32])

	err := bucket.Put(startBlockName, buf)
	if err != nil {
		str := fmt.Sprintf("failed to store start block %v", bs.Hash)
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

// fetchRecentBlocks returns the height of the most recent block height and
// hashes of the most recent blocks.
func fetchRecentBlocks(tx walletdb.Tx) (int32, []wire.ShaHash, error) {
	bucket := tx.RootBucket().Bucket(syncBucketName)

	// The serialized recent blocks format is:
	//   <blockheight><numhashes><blockhashes>
	//
	// 4 bytes recent block height + 4 bytes number of hashes + raw hashes
	// at 32 bytes each.

	// Given the above, the length of the entry must be at a minimum
	// the constant value sizes.
	buf := bucket.Get(recentBlocksName)
	if len(buf) < 8 {
		str := "malformed recent blocks stored in database"
		return 0, nil, managerError(ErrDatabase, str, nil)
	}

	recentHeight := int32(binary.LittleEndian.Uint32(buf[0:4]))
	numHashes := binary.LittleEndian.Uint32(buf[4:8])
	recentHashes := make([]wire.ShaHash, numHashes)
	offset := 8
	for i := uint32(0); i < numHashes; i++ {
		copy(recentHashes[i][:], buf[offset:offset+32])
		offset += 32
	}

	return recentHeight, recentHashes, nil
}

// putRecentBlocks stores the provided start block stamp to the database.
func putRecentBlocks(tx walletdb.Tx, recentHeight int32, recentHashes []wire.ShaHash) error {
	bucket := tx.RootBucket().Bucket(syncBucketName)

	// The serialized recent blocks format is:
	//   <blockheight><numhashes><blockhashes>
	//
	// 4 bytes recent block height + 4 bytes number of hashes + raw hashes
	// at 32 bytes each.
	numHashes := uint32(len(recentHashes))
	buf := make([]byte, 8+(numHashes*32))
	binary.LittleEndian.PutUint32(buf[0:4], uint32(recentHeight))
	binary.LittleEndian.PutUint32(buf[4:8], numHashes)
	offset := 8
	for i := uint32(0); i < numHashes; i++ {
		copy(buf[offset:offset+32], recentHashes[i][:])
		offset += 32
	}

	err := bucket.Put(recentBlocksName, buf)
	if err != nil {
		str := "failed to store recent blocks"
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

// managerExists returns whether or not the manager has already been created
// in the given database namespace.
func managerExists(namespace walletdb.Namespace) (bool, error) {
	var exists bool
	err := namespace.View(func(tx walletdb.Tx) error {
		mainBucket := tx.RootBucket().Bucket(mainBucketName)
		exists = mainBucket != nil
		return nil
	})
	if err != nil {
		str := fmt.Sprintf("failed to obtain database view: %v", err)
		return false, managerError(ErrDatabase, str, err)
	}
	return exists, nil
}

// upgradeManager opens the manager using the specified namespace or creates and
// initializes it if it does not already exist.  It also provides facilities to
// upgrade the data in the namespace to newer versions.
func upgradeManager(namespace walletdb.Namespace) error {
	// Initialize the buckets and main db fields as needed.
	var version uint32
	var createDate uint64
	err := namespace.Update(func(tx walletdb.Tx) error {
		rootBucket := tx.RootBucket()
		mainBucket, err := rootBucket.CreateBucketIfNotExists(
			mainBucketName)
		if err != nil {
			str := "failed to create main bucket"
			return managerError(ErrDatabase, str, err)
		}

		_, err = rootBucket.CreateBucketIfNotExists(addrBucketName)
		if err != nil {
			str := "failed to create address bucket"
			return managerError(ErrDatabase, str, err)
		}

		_, err = rootBucket.CreateBucketIfNotExists(acctBucketName)
		if err != nil {
			str := "failed to create account bucket"
			return managerError(ErrDatabase, str, err)
		}

		_, err = rootBucket.CreateBucketIfNotExists(addrAcctIdxBucketName)
		if err != nil {
			str := "failed to create address index bucket"
			return managerError(ErrDatabase, str, err)
		}

		_, err = rootBucket.CreateBucketIfNotExists(syncBucketName)
		if err != nil {
			str := "failed to create sync bucket"
			return managerError(ErrDatabase, str, err)
		}

		// Save the most recent database version if it isn't already
		// there, otherwise keep track of it for potential upgrades.
		verBytes := mainBucket.Get(mgrVersionName)
		if verBytes == nil {
			version = LatestMgrVersion

			var buf [4]byte
			binary.LittleEndian.PutUint32(buf[:], version)
			err := mainBucket.Put(mgrVersionName, buf[:])
			if err != nil {
				str := "failed to store latest database version"
				return managerError(ErrDatabase, str, err)
			}
		} else {
			version = binary.LittleEndian.Uint32(verBytes)
		}

		createBytes := mainBucket.Get(mgrCreateDateName)
		if createBytes == nil {
			createDate = uint64(time.Now().Unix())
			var buf [8]byte
			binary.LittleEndian.PutUint64(buf[:], createDate)
			err := mainBucket.Put(mgrCreateDateName, buf[:])
			if err != nil {
				str := "failed to store database creation time"
				return managerError(ErrDatabase, str, err)
			}
		} else {
			createDate = binary.LittleEndian.Uint64(createBytes)
		}

		return nil
	})
	if err != nil {
		str := "failed to update database"
		return managerError(ErrDatabase, str, err)
	}

	// Upgrade the manager as needed.
	if version < LatestMgrVersion {
		// No upgrades yet.
	}

	return nil
}
