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
	"io"
	"time"

	"github.com/conformal/bolt"
	"github.com/conformal/btcwire"
	"github.com/conformal/fastsha256"
)

const (
	// LatestDbVersion is the most recent database version.
	LatestDbVersion = 1
)

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
	addrType   addressType
	account    uint32
	addTime    uint64
	syncStatus syncStatus
	rawData    []byte // Varies based on address type field.
}

// dbChainAddressRow houses additional information stored about a chained
// address in the database.
type dbChainAddressRow struct {
	dbAddressRow
	branch uint32
	index  uint32
}

// dbImportedAddressRow houses additional information stored about an imported
// public key address in the database.
type dbImportedAddressRow struct {
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
	dbVersionName    = []byte("dbver")
	dbCreateDateName = []byte("dbcreated")

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

// managerTx represents a database transaction on which all database reads and
// writes occur.  Note that fetched bytes are only valid during the bolt
// transaction, however they are safe to use after a manager transation has
// been terminated.  This is why the code make copies of the data fetched from
// bolt buckets.
type managerTx bolt.Tx

// FetchMasterKeyParams loads the master key parameters needed to derive them
// (when given the correct user-supplied passphrase) from the database.  Either
// returned value can be nil, but in practice only the private key params will
// be nil for a watching-only database.
func (mtx *managerTx) FetchMasterKeyParams() ([]byte, []byte, error) {
	bucket := (*bolt.Tx)(mtx).Bucket(mainBucketName)

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

// PutMasterKeyParams stores the master key parameters needed to derive them
// to the database.  Either parameter can be nil in which case no value is
// written for the parameter.
func (mtx *managerTx) PutMasterKeyParams(pubParams, privParams []byte) error {
	bucket := (*bolt.Tx)(mtx).Bucket(mainBucketName)

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

// FetchCryptoKeys loads the encrypted crypto keys which are in turn used to
// protect the extended keys, imported keys, and scripts.  Any of the returned
// values can be nil, but in practice only the crypto private and script keys
// will be nil for a watching-only database.
func (mtx *managerTx) FetchCryptoKeys() ([]byte, []byte, []byte, error) {
	bucket := (*bolt.Tx)(mtx).Bucket(mainBucketName)

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

// PutCryptoKeys stores the encrypted crypto keys which are in turn used to
// protect the extended and imported keys.  Either parameter can be nil in which
// case no value is written for the parameter.
func (mtx *managerTx) PutCryptoKeys(pubKeyEncrypted, privKeyEncrypted, scriptKeyEncrypted []byte) error {
	bucket := (*bolt.Tx)(mtx).Bucket(mainBucketName)

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

// FetchWatchingOnly loads the watching-only flag from the database.
func (mtx *managerTx) FetchWatchingOnly() (bool, error) {
	bucket := (*bolt.Tx)(mtx).Bucket(mainBucketName)
	buf := bucket.Get(watchingOnlyName)
	if len(buf) != 1 {
		str := "malformed watching-only flag stored in database"
		return false, managerError(ErrDatabase, str, nil)
	}

	return buf[0] != 0, nil
}

// PutWatchingOnly stores the watching-only flag to the database.
func (mtx *managerTx) PutWatchingOnly(watchingOnly bool) error {
	bucket := (*bolt.Tx)(mtx).Bucket(mainBucketName)
	var encoded byte
	if watchingOnly {
		encoded = 1
	}

	if err := bucket.Put(watchingOnlyName, []byte{encoded}); err != nil {
		str := "failed to store wathcing only flag"
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

// accountKey returns the account key to use in the database for a given account
// number.
func accountKey(account uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, account)
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

// FetchAccountInfo loads information about the passed account from the
// database.
func (mtx *managerTx) FetchAccountInfo(account uint32) (interface{}, error) {
	bucket := (*bolt.Tx)(mtx).Bucket(acctBucketName)

	accountID := accountKey(account)
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
func (mtx *managerTx) putAccountRow(account uint32, row *dbAccountRow) error {
	bucket := (*bolt.Tx)(mtx).Bucket(acctBucketName)

	// Write the serialized value keyed by the account number.
	err := bucket.Put(accountKey(account), serializeAccountRow(row))
	if err != nil {
		str := fmt.Sprintf("failed to store account %d", account)
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

// PutAccountInfo stores the provided account information to the database.
func (mtx *managerTx) PutAccountInfo(account uint32, encryptedPubKey,
	encryptedPrivKey []byte, nextExternalIndex, nextInternalIndex uint32,
	name string) error {

	rawData := serializeBIP0044AccountRow(encryptedPubKey, encryptedPrivKey,
		nextExternalIndex, nextInternalIndex, name)

	acctRow := dbAccountRow{
		acctType: actBIP0044,
		rawData:  rawData,
	}
	return mtx.putAccountRow(account, &acctRow)
}

// FetchNumAccounts loads the number of accounts that have been created from
// the database.
func (mtx *managerTx) FetchNumAccounts() (uint32, error) {
	bucket := (*bolt.Tx)(mtx).Bucket(acctBucketName)

	val := bucket.Get(acctNumAcctsName)
	if val == nil {
		str := "required num accounts not stored in database"
		return 0, managerError(ErrDatabase, str, nil)
	}

	return binary.LittleEndian.Uint32(val), nil
}

// PutNumAccounts stores the number of accounts that have been created to the
// database.
func (mtx *managerTx) PutNumAccounts(numAccounts uint32) error {
	bucket := (*bolt.Tx)(mtx).Bucket(acctBucketName)

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
	//   <addrType><account><addedTime><syncStatus><rawdata>
	//
	// 1 byte addrType + 4 bytes account + 8 bytes addTime + 1 byte
	// syncStatus + 4 bytes raw data length + raw data

	// Given the above, the length of the entry must be at a minimum
	// the constant value sizes.
	if len(serializedAddress) < 18 {
		str := fmt.Sprintf("malformed serialized address for key %s",
			addressID)
		return nil, managerError(ErrDatabase, str, nil)
	}

	row := dbAddressRow{}
	row.addrType = addressType(serializedAddress[0])
	row.account = binary.LittleEndian.Uint32(serializedAddress[1:5])
	row.addTime = binary.LittleEndian.Uint64(serializedAddress[5:13])
	row.syncStatus = syncStatus(serializedAddress[13])
	rdlen := binary.LittleEndian.Uint32(serializedAddress[14:18])
	row.rawData = make([]byte, rdlen)
	copy(row.rawData, serializedAddress[18:18+rdlen])

	return &row, nil
}

// serializeAddressRow returns the serialization of the passed address row.
func serializeAddressRow(row *dbAddressRow) []byte {
	// The serialized address format is:
	//   <addrType><account><addedTime><syncStatus><commentlen><comment>
	//   <rawdata>
	//
	// 1 byte addrType + 4 bytes account + 8 bytes addTime + 1 byte
	// syncStatus + 4 bytes raw data length + raw data
	rdlen := len(row.rawData)
	buf := make([]byte, 18+rdlen)
	buf[0] = byte(row.addrType)
	binary.LittleEndian.PutUint32(buf[1:5], row.account)
	binary.LittleEndian.PutUint64(buf[5:13], row.addTime)
	buf[13] = byte(row.syncStatus)
	binary.LittleEndian.PutUint32(buf[14:18], uint32(rdlen))
	copy(buf[18:18+rdlen], row.rawData)
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

// deserializeImportedAddress deserializes the raw data from the passed address
// row as an imported address.
func deserializeImportedAddress(addressID []byte, row *dbAddressRow) (*dbImportedAddressRow, error) {
	// The serialized imported address raw data format is:
	//   <encpubkeylen><encpubkey><encprivkeylen><encprivkey>
	//
	// 4 bytes encrypted pubkey len + encrypted pubkey + 4 bytes encrypted
	// privkey len + encrypted privkey

	// Given the above, the length of the entry must be at a minimum
	// the constant value sizes.
	if len(row.rawData) < 8 {
		str := fmt.Sprintf("malformed serialized imported address for "+
			"key %s", addressID)
		return nil, managerError(ErrDatabase, str, nil)
	}

	retRow := dbImportedAddressRow{
		dbAddressRow: *row,
	}

	pubLen := binary.LittleEndian.Uint32(row.rawData[0:4])
	retRow.encryptedPubKey = make([]byte, pubLen)
	copy(retRow.encryptedPubKey, row.rawData[4:4+pubLen])
	offset := 4 + pubLen
	privLen := binary.LittleEndian.Uint32(row.rawData[offset : offset+4])
	offset += 4
	retRow.encryptedPrivKey = make([]byte, privLen)
	copy(retRow.encryptedPrivKey, row.rawData[offset:offset+privLen])

	return &retRow, nil
}

// serializeImportedAddress returns the serialization of the raw data field for
// an imported address.
func serializeImportedAddress(encryptedPubKey, encryptedPrivKey []byte) []byte {
	// The serialized imported address raw data format is:
	//   <encpubkeylen><encpubkey><encprivkeylen><encprivkey>
	//
	// 4 bytes encrypted pubkey len + encrypted pubkey + 4 bytes encrypted
	// privkey len + encrypted privkey
	pubLen := uint32(len(encryptedPubKey))
	privLen := uint32(len(encryptedPrivKey))
	rawData := make([]byte, 8+pubLen+privLen)
	binary.LittleEndian.PutUint32(rawData[0:4], pubLen)
	copy(rawData[4:4+pubLen], encryptedPubKey)
	offset := 4 + pubLen
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

// FetchAddress loads address information for the provided address id from
// the database.  The returned value is one of the address rows for the specific
// address type.  The caller should use type assertions to ascertain the type.
func (mtx *managerTx) FetchAddress(addressID []byte) (interface{}, error) {
	bucket := (*bolt.Tx)(mtx).Bucket(addrBucketName)

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
		return deserializeImportedAddress(addressID, row)
	case adtScript:
		return deserializeScriptAddress(addressID, row)
	}

	str := fmt.Sprintf("unsupported address type '%d'", row.addrType)
	return nil, managerError(ErrDatabase, str, nil)
}

// putAddress stores the provided address information to the database.  This
// is used a common base for storing the various address types.
func (mtx *managerTx) putAddress(addressID []byte, row *dbAddressRow) error {
	bucket := (*bolt.Tx)(mtx).Bucket(addrBucketName)

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

// PutChainedAddress stores the provided chained address information to the
// database.
func (mtx *managerTx) PutChainedAddress(addressID []byte, account uint32,
	status syncStatus, branch, index uint32) error {

	addrRow := dbAddressRow{
		addrType:   adtChain,
		account:    account,
		addTime:    uint64(time.Now().Unix()),
		syncStatus: status,
		rawData:    serializeChainedAddress(branch, index),
	}
	if err := mtx.putAddress(addressID, &addrRow); err != nil {
		return err
	}

	// Update the next index for the appropriate internal or external
	// branch.
	accountID := accountKey(account)
	bucket := (*bolt.Tx)(mtx).Bucket(acctBucketName)
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

// PutImportedAddress stores the provided imported address information to the
// database.
func (mtx *managerTx) PutImportedAddress(addressID []byte, account uint32,
	status syncStatus, encryptedPubKey, encryptedPrivKey []byte) error {

	rawData := serializeImportedAddress(encryptedPubKey, encryptedPrivKey)
	addrRow := dbAddressRow{
		addrType:   adtImport,
		account:    account,
		addTime:    uint64(time.Now().Unix()),
		syncStatus: status,
		rawData:    rawData,
	}
	return mtx.putAddress(addressID, &addrRow)
}

// PutScriptAddress stores the provided script address information to the
// database.
func (mtx *managerTx) PutScriptAddress(addressID []byte, account uint32,
	status syncStatus, encryptedHash, encryptedScript []byte) error {

	rawData := serializeScriptAddress(encryptedHash, encryptedScript)
	addrRow := dbAddressRow{
		addrType:   adtScript,
		account:    account,
		addTime:    uint64(time.Now().Unix()),
		syncStatus: status,
		rawData:    rawData,
	}
	if err := mtx.putAddress(addressID, &addrRow); err != nil {
		return err
	}

	return nil
}

// ExistsAddress returns whether or not the address id exists in the database.
func (mtx *managerTx) ExistsAddress(addressID []byte) bool {
	bucket := (*bolt.Tx)(mtx).Bucket(addrBucketName)

	addrHash := fastsha256.Sum256(addressID)
	return bucket.Get(addrHash[:]) != nil
}

// FetchAllAddresses loads information about all addresses from the database.
// The returned value is a slice of address rows for each specific address type.
// The caller should use type assertions to ascertain the types.
func (mtx *managerTx) FetchAllAddresses() ([]interface{}, error) {
	bucket := (*bolt.Tx)(mtx).Bucket(addrBucketName)

	var addrs []interface{}
	cursor := bucket.Cursor()
	for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
		// Skip buckets.
		if v == nil {
			continue
		}

		// Deserialize the address row first to determine the field
		// values.
		row, err := deserializeAddressRow(k, v)
		if err != nil {
			return nil, err
		}

		var addrRow interface{}
		switch row.addrType {
		case adtChain:
			addrRow, err = deserializeChainedAddress(k, row)
		case adtImport:
			addrRow, err = deserializeImportedAddress(k, row)
		case adtScript:
			addrRow, err = deserializeScriptAddress(k, row)
		default:
			str := fmt.Sprintf("unsupported address type '%d'",
				row.addrType)
			return nil, managerError(ErrDatabase, str, nil)
		}
		if err != nil {
			return nil, err
		}

		addrs = append(addrs, addrRow)
	}

	return addrs, nil
}

// DeletePrivateKeys removes all private key material from the database.
//
// NOTE: Care should be taken when calling this function.  It is primarily
// intended for use in converting to a watching-only copy.  Removing the private
// keys from the main database without also marking it watching-only will result
// in an unusable database.  It will also make any imported scripts and private
// keys unrecoverable unless there is a backup copy available.
func (mtx *managerTx) DeletePrivateKeys() error {
	bucket := (*bolt.Tx)(mtx).Bucket(mainBucketName)

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
	bucket = (*bolt.Tx)(mtx).Bucket(acctBucketName)
	cursor := bucket.Cursor()
	for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
		// Skip buckets.
		if v == nil || bytes.Equal(k, acctNumAcctsName) {
			continue
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
	}

	// Delete the private key for all imported addresses.
	bucket = (*bolt.Tx)(mtx).Bucket(addrBucketName)
	cursor = bucket.Cursor()
	for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
		// Skip buckets.
		if v == nil {
			continue
		}

		// Deserialize the address row first to determine the field
		// values.
		row, err := deserializeAddressRow(k, v)
		if err != nil {
			return err
		}

		switch row.addrType {
		case adtImport:
			irow, err := deserializeImportedAddress(k, row)
			if err != nil {
				return err
			}

			// Reserialize the imported address without the private
			// key and store it.
			row.rawData = serializeImportedAddress(
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
	}

	return nil
}

// FetchSyncedTo loads the block stamp the manager is synced to from the
// database.
func (mtx *managerTx) FetchSyncedTo() (*BlockStamp, error) {
	bucket := (*bolt.Tx)(mtx).Bucket(syncBucketName)

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

// PutSyncedTo stores the provided synced to blockstamp to the database.
func (mtx *managerTx) PutSyncedTo(bs *BlockStamp) error {
	bucket := (*bolt.Tx)(mtx).Bucket(syncBucketName)

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

// FetchStartBlock loads the start block stamp for the manager from the
// database.
func (mtx *managerTx) FetchStartBlock() (*BlockStamp, error) {
	bucket := (*bolt.Tx)(mtx).Bucket(syncBucketName)

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

// PutStartBlock stores the provided start block stamp to the database.
func (mtx *managerTx) PutStartBlock(bs *BlockStamp) error {
	bucket := (*bolt.Tx)(mtx).Bucket(syncBucketName)

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

// FetchRecentBlocks returns the height of the most recent block height and
// hashes of the most recent blocks.
func (mtx *managerTx) FetchRecentBlocks() (int32, []btcwire.ShaHash, error) {
	bucket := (*bolt.Tx)(mtx).Bucket(syncBucketName)

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
	recentHashes := make([]btcwire.ShaHash, numHashes)
	offset := 8
	for i := uint32(0); i < numHashes; i++ {
		copy(recentHashes[i][:], buf[offset:offset+32])
		offset += 32
	}

	return recentHeight, recentHashes, nil
}

// PutStartBlock stores the provided start block stamp to the database.
func (mtx *managerTx) PutRecentBlocks(recentHeight int32, recentHashes []btcwire.ShaHash) error {
	bucket := (*bolt.Tx)(mtx).Bucket(syncBucketName)

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

// managerDB provides transactional facilities to read and write the address
// manager data to a bolt database.
type managerDB struct {
	db      *bolt.DB
	version uint32
	created time.Time
}

// Close releases all database resources.  All transactions must be closed
// before closing the database.
func (db *managerDB) Close() error {
	if err := db.db.Close(); err != nil {
		str := "failed to close database"
		return managerError(ErrDatabase, str, err)
	}

	return nil
}

// View executes the passed function within the context of a managed read-only
// transaction. Any error that is returned from the passed function is returned
// from this function.
func (db *managerDB) View(fn func(tx *managerTx) error) error {
	err := db.db.View(func(tx *bolt.Tx) error {
		return fn((*managerTx)(tx))
	})
	if err != nil {
		// Ensure the returned error is a ManagerError.
		if _, ok := err.(ManagerError); !ok {
			str := "failed during database read transaction"
			return managerError(ErrDatabase, str, err)
		}
		return err
	}

	return nil
}

// Update executes the passed function within the context of a read-write
// managed transaction. The transaction is committed if no error is returned
// from the function. On the other hand, the entire transaction is rolled back
// if an error is returned.  Any error that is returned from the passed function
// or returned from the commit is returned from this function.
func (db *managerDB) Update(fn func(tx *managerTx) error) error {
	err := db.db.Update(func(tx *bolt.Tx) error {
		return fn((*managerTx)(tx))
	})
	if err != nil {
		// Ensure the returned error is a ManagerError.
		if _, ok := err.(ManagerError); !ok {
			str := "failed during database write transaction"
			return managerError(ErrDatabase, str, err)
		}
		return err
	}

	return nil
}

// CopyDB copies the entire database to the provided new database path.  A
// reader transaction is maintained during the copy so it is safe to continue
// using the database while a copy is in progress.
func (db *managerDB) CopyDB(newDbPath string) error {
	err := db.db.View(func(tx *bolt.Tx) error {
		if err := tx.CopyFile(newDbPath, 0600); err != nil {
			str := "failed to copy database"
			return managerError(ErrDatabase, str, err)
		}

		return nil
	})
	if err != nil {
		// Ensure the returned error is a ManagerError.
		if _, ok := err.(ManagerError); !ok {
			str := "failed during database copy"
			return managerError(ErrDatabase, str, err)
		}
		return err
	}

	return nil
}

// WriteTo writes the entire database to the provided writer.  A reader
// transaction is maintained during the copy so it is safe to continue using the
// database while a copy is in progress.
func (db *managerDB) WriteTo(w io.Writer) error {
	err := db.db.View(func(tx *bolt.Tx) error {
		if err := tx.Copy(w); err != nil {
			str := "failed to copy database"
			return managerError(ErrDatabase, str, err)
		}

		return nil
	})
	if err != nil {
		// Ensure the returned error is a ManagerError.
		if _, ok := err.(ManagerError); !ok {
			str := "failed during database copy"
			return managerError(ErrDatabase, str, err)
		}
		return err
	}

	return nil
}

// openOrCreateDB opens the database at the provided path or creates and
// initializes it if it does not already exist.  It also provides facilities to
// upgrade the database to newer versions.
func openOrCreateDB(dbPath string) (*managerDB, error) {
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		str := "failed to open database"
		return nil, managerError(ErrDatabase, str, err)
	}

	// Initialize the buckets and main db fields as needed.
	var version uint32
	var createDate uint64
	err = db.Update(func(tx *bolt.Tx) error {
		mainBucket, err := tx.CreateBucketIfNotExists(mainBucketName)
		if err != nil {
			str := "failed to create main bucket"
			return managerError(ErrDatabase, str, err)
		}

		_, err = tx.CreateBucketIfNotExists(addrBucketName)
		if err != nil {
			str := "failed to create address bucket"
			return managerError(ErrDatabase, str, err)
		}

		_, err = tx.CreateBucketIfNotExists(acctBucketName)
		if err != nil {
			str := "failed to create account bucket"
			return managerError(ErrDatabase, str, err)
		}

		_, err = tx.CreateBucketIfNotExists(addrAcctIdxBucketName)
		if err != nil {
			str := "failed to create address index bucket"
			return managerError(ErrDatabase, str, err)
		}

		_, err = tx.CreateBucketIfNotExists(syncBucketName)
		if err != nil {
			str := "failed to create sync bucket"
			return managerError(ErrDatabase, str, err)
		}

		// Save the most recent database version if it isn't already
		// there, otherwise keep track of it for potential upgrades.
		verBytes := mainBucket.Get(dbVersionName)
		if verBytes == nil {
			version = LatestDbVersion

			var buf [4]byte
			binary.LittleEndian.PutUint32(buf[:], version)
			err := mainBucket.Put(dbVersionName, buf[:])
			if err != nil {
				str := "failed to store latest database version"
				return managerError(ErrDatabase, str, err)
			}
		} else {
			version = binary.LittleEndian.Uint32(verBytes)
		}

		createBytes := mainBucket.Get(dbCreateDateName)
		if createBytes == nil {
			createDate = uint64(time.Now().Unix())
			var buf [8]byte
			binary.LittleEndian.PutUint64(buf[:], createDate)
			err := mainBucket.Put(dbCreateDateName, buf[:])
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
		return nil, managerError(ErrDatabase, str, err)
	}

	// Upgrade the database as needed.
	if version < LatestDbVersion {
		// No upgrades yet.
	}

	return &managerDB{
		db:      db,
		version: version,
		created: time.Unix(int64(createDate), 0),
	}, nil
}
