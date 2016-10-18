// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/jadeblaquiere/ctcd/chaincfg"
	"github.com/jadeblaquiere/ctcd/chaincfg/chainhash"
	"github.com/jadeblaquiere/ctcutil/hdkeychain"
	"github.com/jadeblaquiere/ctcwallet/walletdb"
	"github.com/btcsuite/fastsha256"
)

const (
	// LatestMgrVersion is the most recent manager version.
	LatestMgrVersion = 4
)

var (
	// latestMgrVersion is the most recent manager version as a variable so
	// the tests can change it to force errors.
	latestMgrVersion uint32 = LatestMgrVersion
)

// ObtainUserInputFunc is a function that reads a user input and returns it as
// a byte stream. It is used to accept data required during upgrades, for e.g.
// wallet seed and private passphrase.
type ObtainUserInputFunc func() ([]byte, error)

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
	// nullVall is null byte used as a flag value in a bucket entry
	nullVal = []byte{0}

	// Bucket names.
	acctBucketName = []byte("acct")
	addrBucketName = []byte("addr")

	// addrAcctIdxBucketName is used to index account addresses
	// Entries in this index may map:
	// * addr hash => account id
	// * account bucket -> addr hash => null
	// To fetch the account of an address, lookup the value using
	// the address hash.
	// To fetch all addresses of an account, fetch the account bucket, iterate
	// over the keys and fetch the address row from the addr bucket.
	// The index needs to be updated whenever an address is created e.g.
	// NewAddress
	addrAcctIdxBucketName = []byte("addracctidx")

	// acctNameIdxBucketName is used to create an index
	// mapping an account name string to the corresponding
	// account id.
	// The index needs to be updated whenever the account name
	// and id changes e.g. RenameAccount
	acctNameIdxBucketName = []byte("acctnameidx")

	// acctIDIdxBucketName is used to create an index
	// mapping an account id to the corresponding
	// account name string.
	// The index needs to be updated whenever the account name
	// and id changes e.g. RenameAccount
	acctIDIdxBucketName = []byte("acctididx")

	// meta is used to store meta-data about the address manager
	// e.g. last account number
	metaBucketName = []byte("meta")
	// lastAccountName is used to store the metadata - last account
	// in the manager
	lastAccountName = []byte("lastaccount")

	mainBucketName = []byte("main")
	syncBucketName = []byte("sync")

	// Db related key names (main bucket).
	mgrVersionName    = []byte("mgrver")
	mgrCreateDateName = []byte("mgrcreated")

	// Crypto related key names (main bucket).
	masterPrivKeyName   = []byte("mpriv")
	masterPubKeyName    = []byte("mpub")
	cryptoPrivKeyName   = []byte("cpriv")
	cryptoPubKeyName    = []byte("cpub")
	cryptoScriptKeyName = []byte("cscript")
	coinTypePrivKeyName = []byte("ctpriv")
	coinTypePubKeyName  = []byte("ctpub")
	watchingOnlyName    = []byte("watchonly")

	// Sync related key names (sync bucket).
	syncedToName     = []byte("syncedto")
	startBlockName   = []byte("startblock")
	recentBlocksName = []byte("recentblocks")

	// Account related key names (account bucket).
	acctNumAcctsName = []byte("numaccts")

	// Used addresses (used bucket)
	usedAddrBucketName = []byte("usedaddrs")
)

// uint32ToBytes converts a 32 bit unsigned integer into a 4-byte slice in
// little-endian order: 1 -> [1 0 0 0].
func uint32ToBytes(number uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, number)
	return buf
}

// uint64ToBytes converts a 64 bit unsigned integer into a 8-byte slice in
// little-endian order: 1 -> [1 0 0 0 0 0 0 0].
func uint64ToBytes(number uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, number)
	return buf
}

// stringToBytes converts a string into a variable length byte slice in
// little-endian order: "abc" -> [3 0 0 0 61 62 63]
func stringToBytes(s string) []byte {
	// The serialized format is:
	//   <size><string>
	//
	// 4 bytes string size + string
	size := len(s)
	buf := make([]byte, 4+size)
	copy(buf[0:4], uint32ToBytes(uint32(size)))
	copy(buf[4:4+size], s)
	return buf
}

// fetchManagerVersion fetches the current manager version from the database.
func fetchManagerVersion(tx walletdb.Tx) (uint32, error) {
	mainBucket := tx.RootBucket().Bucket(mainBucketName)
	verBytes := mainBucket.Get(mgrVersionName)
	if verBytes == nil {
		str := "required version number not stored in database"
		return 0, managerError(ErrDatabase, str, nil)
	}
	version := binary.LittleEndian.Uint32(verBytes)
	return version, nil
}

// putManagerVersion stores the provided version to the database.
func putManagerVersion(tx walletdb.Tx, version uint32) error {
	bucket := tx.RootBucket().Bucket(mainBucketName)

	verBytes := uint32ToBytes(version)
	err := bucket.Put(mgrVersionName, verBytes)
	if err != nil {
		str := "failed to store version"
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

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

// fetchCoinTypeKeys loads the encrypted cointype keys which are in turn used to
// derive the extended keys for all accounts.
func fetchCoinTypeKeys(tx walletdb.Tx) ([]byte, []byte, error) {
	bucket := tx.RootBucket().Bucket(mainBucketName)

	coinTypePubKeyEnc := bucket.Get(coinTypePubKeyName)
	if coinTypePubKeyEnc == nil {
		str := "required encrypted cointype public key not stored in database"
		return nil, nil, managerError(ErrDatabase, str, nil)
	}

	coinTypePrivKeyEnc := bucket.Get(coinTypePrivKeyName)
	if coinTypePrivKeyEnc == nil {
		str := "required encrypted cointype private key not stored in database"
		return nil, nil, managerError(ErrDatabase, str, nil)
	}
	return coinTypePubKeyEnc, coinTypePrivKeyEnc, nil
}

// putCoinTypeKeys stores the encrypted cointype keys which are in turn used to
// derive the extended keys for all accounts.  Either parameter can be nil in which
// case no value is written for the parameter.
func putCoinTypeKeys(tx walletdb.Tx, coinTypePubKeyEnc []byte, coinTypePrivKeyEnc []byte) error {
	bucket := tx.RootBucket().Bucket(mainBucketName)

	if coinTypePubKeyEnc != nil {
		err := bucket.Put(coinTypePubKeyName, coinTypePubKeyEnc)
		if err != nil {
			str := "failed to store encrypted cointype public key"
			return managerError(ErrDatabase, str, err)
		}
	}

	if coinTypePrivKeyEnc != nil {
		err := bucket.Put(coinTypePrivKeyName, coinTypePrivKeyEnc)
		if err != nil {
			str := "failed to store encrypted cointype private key"
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

// forEachAccount calls the given function with each account stored in
// the manager, breaking early on error.
func forEachAccount(tx walletdb.Tx, fn func(account uint32) error) error {
	bucket := tx.RootBucket().Bucket(acctBucketName)

	return bucket.ForEach(func(k, v []byte) error {
		// Skip buckets.
		if v == nil {
			return nil
		}
		return fn(binary.LittleEndian.Uint32(k))
	})
}

// fetchLastAccount retreives the last account from the database.
func fetchLastAccount(tx walletdb.Tx) (uint32, error) {
	bucket := tx.RootBucket().Bucket(metaBucketName)

	val := bucket.Get(lastAccountName)
	if len(val) != 4 {
		str := fmt.Sprintf("malformed metadata '%s' stored in database",
			lastAccountName)
		return 0, managerError(ErrDatabase, str, nil)
	}
	account := binary.LittleEndian.Uint32(val[0:4])
	return account, nil
}

// fetchAccountName retreives the account name given an account number from
// the database.
func fetchAccountName(tx walletdb.Tx, account uint32) (string, error) {
	bucket := tx.RootBucket().Bucket(acctIDIdxBucketName)

	val := bucket.Get(uint32ToBytes(account))
	if val == nil {
		str := fmt.Sprintf("account %d not found", account)
		return "", managerError(ErrAccountNotFound, str, nil)
	}
	offset := uint32(0)
	nameLen := binary.LittleEndian.Uint32(val[offset : offset+4])
	offset += 4
	acctName := string(val[offset : offset+nameLen])
	return acctName, nil
}

// fetchAccountByName retreives the account number given an account name
// from the database.
func fetchAccountByName(tx walletdb.Tx, name string) (uint32, error) {
	bucket := tx.RootBucket().Bucket(acctNameIdxBucketName)

	val := bucket.Get(stringToBytes(name))
	if val == nil {
		str := fmt.Sprintf("account name '%s' not found", name)
		return 0, managerError(ErrAccountNotFound, str, nil)
	}

	return binary.LittleEndian.Uint32(val), nil
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

// deleteAccountNameIndex deletes the given key from the account name index of the database.
func deleteAccountNameIndex(tx walletdb.Tx, name string) error {
	bucket := tx.RootBucket().Bucket(acctNameIdxBucketName)

	// Delete the account name key
	err := bucket.Delete(stringToBytes(name))
	if err != nil {
		str := fmt.Sprintf("failed to delete account name index key %s", name)
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

// deleteAccounIdIndex deletes the given key from the account id index of the database.
func deleteAccountIDIndex(tx walletdb.Tx, account uint32) error {
	bucket := tx.RootBucket().Bucket(acctIDIdxBucketName)

	// Delete the account id key
	err := bucket.Delete(uint32ToBytes(account))
	if err != nil {
		str := fmt.Sprintf("failed to delete account id index key %d", account)
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

// putAccountNameIndex stores the given key to the account name index of the database.
func putAccountNameIndex(tx walletdb.Tx, account uint32, name string) error {
	bucket := tx.RootBucket().Bucket(acctNameIdxBucketName)

	// Write the account number keyed by the account name.
	err := bucket.Put(stringToBytes(name), uint32ToBytes(account))
	if err != nil {
		str := fmt.Sprintf("failed to store account name index key %s", name)
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

// putAccountIDIndex stores the given key to the account id index of the database.
func putAccountIDIndex(tx walletdb.Tx, account uint32, name string) error {
	bucket := tx.RootBucket().Bucket(acctIDIdxBucketName)

	// Write the account number keyed by the account id.
	err := bucket.Put(uint32ToBytes(account), stringToBytes(name))
	if err != nil {
		str := fmt.Sprintf("failed to store account id index key %s", name)
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

// putAddrAccountIndex stores the given key to the address account index of the database.
func putAddrAccountIndex(tx walletdb.Tx, account uint32, addrHash []byte) error {
	bucket := tx.RootBucket().Bucket(addrAcctIdxBucketName)

	// Write account keyed by address hash
	err := bucket.Put(addrHash, uint32ToBytes(account))
	if err != nil {
		return nil
	}

	bucket, err = bucket.CreateBucketIfNotExists(uint32ToBytes(account))
	if err != nil {
		return err
	}
	// In account bucket, write a null value keyed by the address hash
	err = bucket.Put(addrHash, nullVal)
	if err != nil {
		str := fmt.Sprintf("failed to store address account index key %s", addrHash)
		return managerError(ErrDatabase, str, err)
	}
	return nil
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
	if err := putAccountRow(tx, account, &acctRow); err != nil {
		return err
	}
	// Update account id index
	if err := putAccountIDIndex(tx, account, name); err != nil {
		return err
	}
	// Update account name index
	if err := putAccountNameIndex(tx, account, name); err != nil {
		return err
	}

	return nil
}

// putLastAccount stores the provided metadata - last account - to the database.
func putLastAccount(tx walletdb.Tx, account uint32) error {
	bucket := tx.RootBucket().Bucket(metaBucketName)

	err := bucket.Put(lastAccountName, uint32ToBytes(account))
	if err != nil {
		str := fmt.Sprintf("failed to update metadata '%s'", lastAccountName)
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
func deserializeAddressRow(serializedAddress []byte) (*dbAddressRow, error) {
	// The serialized address format is:
	//   <addrType><account><addedTime><syncStatus><rawdata>
	//
	// 1 byte addrType + 4 bytes account + 8 bytes addTime + 1 byte
	// syncStatus + 4 bytes raw data length + raw data

	// Given the above, the length of the entry must be at a minimum
	// the constant value sizes.
	if len(serializedAddress) < 18 {
		str := "malformed serialized address"
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
func deserializeChainedAddress(row *dbAddressRow) (*dbChainAddressRow, error) {
	// The serialized chain address raw data format is:
	//   <branch><index>
	//
	// 4 bytes branch + 4 bytes address index
	if len(row.rawData) != 8 {
		str := "malformed serialized chained address"
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
func deserializeImportedAddress(row *dbAddressRow) (*dbImportedAddressRow, error) {
	// The serialized imported address raw data format is:
	//   <encpubkeylen><encpubkey><encprivkeylen><encprivkey>
	//
	// 4 bytes encrypted pubkey len + encrypted pubkey + 4 bytes encrypted
	// privkey len + encrypted privkey

	// Given the above, the length of the entry must be at a minimum
	// the constant value sizes.
	if len(row.rawData) < 8 {
		str := "malformed serialized imported address"
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
func deserializeScriptAddress(row *dbAddressRow) (*dbScriptAddressRow, error) {
	// The serialized script address raw data format is:
	//   <encscripthashlen><encscripthash><encscriptlen><encscript>
	//
	// 4 bytes encrypted script hash len + encrypted script hash + 4 bytes
	// encrypted script len + encrypted script

	// Given the above, the length of the entry must be at a minimum
	// the constant value sizes.
	if len(row.rawData) < 8 {
		str := "malformed serialized script address"
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

// fetchAddressByHash loads address information for the provided address hash
// from the database.  The returned value is one of the address rows for the
// specific address type.  The caller should use type assertions to ascertain
// the type.  The caller should prefix the error message with the address hash
// which caused the failure.
func fetchAddressByHash(tx walletdb.Tx, addrHash []byte) (interface{}, error) {
	bucket := tx.RootBucket().Bucket(addrBucketName)

	serializedRow := bucket.Get(addrHash[:])
	if serializedRow == nil {
		str := "address not found"
		return nil, managerError(ErrAddressNotFound, str, nil)
	}

	row, err := deserializeAddressRow(serializedRow)
	if err != nil {
		return nil, err
	}

	switch row.addrType {
	case adtChain:
		return deserializeChainedAddress(row)
	case adtImport:
		return deserializeImportedAddress(row)
	case adtScript:
		return deserializeScriptAddress(row)
	}

	str := fmt.Sprintf("unsupported address type '%d'", row.addrType)
	return nil, managerError(ErrDatabase, str, nil)
}

// fetchAddressUsed returns true if the provided address id was flagged as used.
func fetchAddressUsed(tx walletdb.Tx, addressID []byte) bool {
	bucket := tx.RootBucket().Bucket(usedAddrBucketName)

	addrHash := fastsha256.Sum256(addressID)
	return bucket.Get(addrHash[:]) != nil
}

// markAddressUsed flags the provided address id as used in the database.
func markAddressUsed(tx walletdb.Tx, addressID []byte) error {
	bucket := tx.RootBucket().Bucket(usedAddrBucketName)

	addrHash := fastsha256.Sum256(addressID)
	val := bucket.Get(addrHash[:])
	if val != nil {
		return nil
	}
	err := bucket.Put(addrHash[:], []byte{0})
	if err != nil {
		str := fmt.Sprintf("failed to mark address used %x", addressID)
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

// fetchAddress loads address information for the provided address id from the
// database.  The returned value is one of the address rows for the specific
// address type.  The caller should use type assertions to ascertain the type.
// The caller should prefix the error message with the address which caused the
// failure.
func fetchAddress(tx walletdb.Tx, addressID []byte) (interface{}, error) {
	addrHash := fastsha256.Sum256(addressID)
	return fetchAddressByHash(tx, addrHash[:])
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
	// Update address account index
	return putAddrAccountIndex(tx, row.account, addrHash[:])
}

// putChainedAddress stores the provided chained address information to the
// database.
func putChainedAddress(tx walletdb.Tx, addressID []byte, account uint32,
	status syncStatus, branch, index uint32) error {

	addrRow := dbAddressRow{
		addrType:   adtChain,
		account:    account,
		addTime:    uint64(time.Now().Unix()),
		syncStatus: status,
		rawData:    serializeChainedAddress(branch, index),
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

// putImportedAddress stores the provided imported address information to the
// database.
func putImportedAddress(tx walletdb.Tx, addressID []byte, account uint32,
	status syncStatus, encryptedPubKey, encryptedPrivKey []byte) error {

	rawData := serializeImportedAddress(encryptedPubKey, encryptedPrivKey)
	addrRow := dbAddressRow{
		addrType:   adtImport,
		account:    account,
		addTime:    uint64(time.Now().Unix()),
		syncStatus: status,
		rawData:    rawData,
	}
	return putAddress(tx, addressID, &addrRow)
}

// putScriptAddress stores the provided script address information to the
// database.
func putScriptAddress(tx walletdb.Tx, addressID []byte, account uint32,
	status syncStatus, encryptedHash, encryptedScript []byte) error {

	rawData := serializeScriptAddress(encryptedHash, encryptedScript)
	addrRow := dbAddressRow{
		addrType:   adtScript,
		account:    account,
		addTime:    uint64(time.Now().Unix()),
		syncStatus: status,
		rawData:    rawData,
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

// fetchAddrAccount returns the account to which the given address belongs to.
// It looks up the account using the addracctidx index which maps the address
// hash to its corresponding account id.
func fetchAddrAccount(tx walletdb.Tx, addressID []byte) (uint32, error) {
	bucket := tx.RootBucket().Bucket(addrAcctIdxBucketName)

	addrHash := fastsha256.Sum256(addressID)
	val := bucket.Get(addrHash[:])
	if val == nil {
		str := "address not found"
		return 0, managerError(ErrAddressNotFound, str, nil)
	}
	return binary.LittleEndian.Uint32(val), nil
}

// forEachAccountAddress calls the given function with each address of
// the given account stored in the manager, breaking early on error.
func forEachAccountAddress(tx walletdb.Tx, account uint32, fn func(rowInterface interface{}) error) error {
	bucket := tx.RootBucket().Bucket(addrAcctIdxBucketName).
		Bucket(uint32ToBytes(account))
	// if index bucket is missing the account, there hasn't been any address
	// entries yet
	if bucket == nil {
		return nil
	}

	err := bucket.ForEach(func(k, v []byte) error {
		// Skip buckets.
		if v == nil {
			return nil
		}
		addrRow, err := fetchAddressByHash(tx, k)
		if err != nil {
			if merr, ok := err.(*ManagerError); ok {
				desc := fmt.Sprintf("failed to fetch address hash '%s': %v",
					k, merr.Description)
				merr.Description = desc
				return merr
			}
			return err
		}

		return fn(addrRow)
	})
	if err != nil {
		return maybeConvertDbError(err)
	}
	return nil
}

// forEachActiveAddress calls the given function with each active address
// stored in the manager, breaking early on error.
func forEachActiveAddress(tx walletdb.Tx, fn func(rowInterface interface{}) error) error {
	bucket := tx.RootBucket().Bucket(addrBucketName)

	err := bucket.ForEach(func(k, v []byte) error {
		// Skip buckets.
		if v == nil {
			return nil
		}

		// Deserialize the address row first to determine the field
		// values.
		addrRow, err := fetchAddressByHash(tx, k)
		if merr, ok := err.(*ManagerError); ok {
			desc := fmt.Sprintf("failed to fetch address hash '%s': %v",
				k, merr.Description)
			merr.Description = desc
			return merr
		}
		if err != nil {
			return err
		}

		return fn(addrRow)
	})
	if err != nil {
		return maybeConvertDbError(err)
	}
	return nil
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
	if err := bucket.Delete(coinTypePrivKeyName); err != nil {
		str := "failed to delete cointype private key"
		return managerError(ErrDatabase, str, err)
	}

	// Delete the account extended private key for all accounts.
	bucket = tx.RootBucket().Bucket(acctBucketName)
	err := bucket.ForEach(func(k, v []byte) error {
		// Skip buckets.
		if v == nil {
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
		row, err := deserializeAddressRow(v)
		if err != nil {
			return err
		}

		switch row.addrType {
		case adtImport:
			irow, err := deserializeImportedAddress(row)
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
			srow, err := deserializeScriptAddress(row)
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
func fetchRecentBlocks(tx walletdb.Tx) (int32, []chainhash.Hash, error) {
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
	recentHashes := make([]chainhash.Hash, numHashes)
	offset := 8
	for i := uint32(0); i < numHashes; i++ {
		copy(recentHashes[i][:], buf[offset:offset+32])
		offset += 32
	}

	return recentHeight, recentHashes, nil
}

// putRecentBlocks stores the provided start block stamp to the database.
func putRecentBlocks(tx walletdb.Tx, recentHeight int32, recentHashes []chainhash.Hash) error {
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

// createManagerNS creates the initial namespace structure needed for all of the
// manager data.  This includes things such as all of the buckets as well as the
// version and creation date.
func createManagerNS(namespace walletdb.Namespace) error {
	err := namespace.Update(func(tx walletdb.Tx) error {
		rootBucket := tx.RootBucket()
		mainBucket, err := rootBucket.CreateBucket(mainBucketName)
		if err != nil {
			str := "failed to create main bucket"
			return managerError(ErrDatabase, str, err)
		}

		_, err = rootBucket.CreateBucket(addrBucketName)
		if err != nil {
			str := "failed to create address bucket"
			return managerError(ErrDatabase, str, err)
		}

		_, err = rootBucket.CreateBucket(acctBucketName)
		if err != nil {
			str := "failed to create account bucket"
			return managerError(ErrDatabase, str, err)
		}

		_, err = rootBucket.CreateBucket(addrAcctIdxBucketName)
		if err != nil {
			str := "failed to create address index bucket"
			return managerError(ErrDatabase, str, err)
		}

		_, err = rootBucket.CreateBucket(syncBucketName)
		if err != nil {
			str := "failed to create sync bucket"
			return managerError(ErrDatabase, str, err)
		}

		// usedAddrBucketName bucket was added after manager version 1 release
		_, err = rootBucket.CreateBucket(usedAddrBucketName)
		if err != nil {
			str := "failed to create used addresses bucket"
			return managerError(ErrDatabase, str, err)
		}

		_, err = rootBucket.CreateBucket(acctNameIdxBucketName)
		if err != nil {
			str := "failed to create an account name index bucket"
			return managerError(ErrDatabase, str, err)
		}

		_, err = rootBucket.CreateBucket(acctIDIdxBucketName)
		if err != nil {
			str := "failed to create an account id index bucket"
			return managerError(ErrDatabase, str, err)
		}

		_, err = rootBucket.CreateBucket(metaBucketName)
		if err != nil {
			str := "failed to create a meta bucket"
			return managerError(ErrDatabase, str, err)
		}

		if err := putLastAccount(tx, DefaultAccountNum); err != nil {
			return err
		}

		if err := putManagerVersion(tx, latestMgrVersion); err != nil {
			return err
		}

		createDate := uint64(time.Now().Unix())
		var dateBytes [8]byte
		binary.LittleEndian.PutUint64(dateBytes[:], createDate)
		err = mainBucket.Put(mgrCreateDateName, dateBytes[:])
		if err != nil {
			str := "failed to store database creation time"
			return managerError(ErrDatabase, str, err)
		}

		return nil
	})
	if err != nil {
		str := "failed to update database"
		return managerError(ErrDatabase, str, err)
	}

	return nil
}

// upgradeToVersion2 upgrades the database from version 1 to version 2
// 'usedAddrBucketName' a bucket for storing addrs flagged as marked is
// initialized and it will be updated on the next rescan.
func upgradeToVersion2(namespace walletdb.Namespace) error {
	err := namespace.Update(func(tx walletdb.Tx) error {
		currentMgrVersion := uint32(2)
		rootBucket := tx.RootBucket()

		_, err := rootBucket.CreateBucket(usedAddrBucketName)
		if err != nil {
			str := "failed to create used addresses bucket"
			return managerError(ErrDatabase, str, err)
		}

		if err := putManagerVersion(tx, currentMgrVersion); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return maybeConvertDbError(err)
	}
	return nil
}

// upgradeManager upgrades the data in the provided manager namespace to newer
// versions as neeeded.
func upgradeManager(namespace walletdb.Namespace, pubPassPhrase []byte, chainParams *chaincfg.Params, cbs *OpenCallbacks) error {
	var version uint32
	err := namespace.View(func(tx walletdb.Tx) error {
		var err error
		version, err = fetchManagerVersion(tx)
		return err
	})
	if err != nil {
		str := "failed to fetch version for update"
		return managerError(ErrDatabase, str, err)
	}

	// NOTE: There are currently no upgrades, but this is provided here as a
	// template for how to properly do upgrades.  Each function to upgrade
	// to the next version must include serializing the new version as a
	// part of the same transaction so any failures in upgrades to later
	// versions won't leave the database in an inconsistent state.  The
	// putManagerVersion function provides a convenient mechanism for that
	// purpose.
	//
	// Upgrade one version at a time so it is possible to upgrade across
	// an aribtary number of versions without needing to write a bunch of
	// additional code to go directly from version X to Y.
	// if version < 2 {
	// 	// Upgrade from version 1 to 2.
	//	if err := upgradeToVersion2(namespace); err != nil {
	//		return err
	//	}
	//
	//	// The manager is now at version 2.
	//	version = 2
	// }
	// if version < 3 {
	// 	// Upgrade from version 2 to 3.
	//	if err := upgradeToVersion3(namespace); err != nil {
	//		return err
	//	}
	//
	//	// The manager is now at version 3.
	//	version = 3
	// }

	if version < 2 {
		// Upgrade from version 1 to 2.
		if err := upgradeToVersion2(namespace); err != nil {
			return err
		}

		// The manager is now at version 2.
		version = 2
	}

	if version < 3 {
		if cbs == nil || cbs.ObtainSeed == nil || cbs.ObtainPrivatePass == nil {
			str := "failed to obtain seed and private passphrase required for upgrade"
			return managerError(ErrDatabase, str, err)
		}

		seed, err := cbs.ObtainSeed()
		if err != nil {
			return err
		}
		privPassPhrase, err := cbs.ObtainPrivatePass()
		if err != nil {
			return err
		}
		// Upgrade from version 2 to 3.
		if err := upgradeToVersion3(namespace, seed, privPassPhrase, pubPassPhrase, chainParams); err != nil {
			return err
		}

		// The manager is now at version 3.
		version = 3
	}

	if version < 4 {
		if err := upgradeToVersion4(namespace, pubPassPhrase); err != nil {
			return err
		}

		// The manager is now at version 4.
		version = 4
	}

	// Ensure the manager is upraded to the latest version.  This check is
	// to intentionally cause a failure if the manager version is updated
	// without writing code to handle the upgrade.
	if version < latestMgrVersion {
		str := fmt.Sprintf("the latest manager version is %d, but the "+
			"current version after upgrades is only %d",
			latestMgrVersion, version)
		return managerError(ErrUpgrade, str, nil)
	}

	return nil
}

// upgradeToVersion3 upgrades the database from version 2 to version 3
// The following buckets were introduced in version 3 to support account names:
// * acctNameIdxBucketName
// * acctIDIdxBucketName
// * metaBucketName
func upgradeToVersion3(namespace walletdb.Namespace, seed, privPassPhrase, pubPassPhrase []byte, chainParams *chaincfg.Params) error {
	err := namespace.Update(func(tx walletdb.Tx) error {
		currentMgrVersion := uint32(3)
		rootBucket := tx.RootBucket()

		woMgr, err := loadManager(namespace, pubPassPhrase, chainParams)
		if err != nil {
			return err
		}
		defer woMgr.Close()

		err = woMgr.Unlock(privPassPhrase)
		if err != nil {
			return err
		}

		// Derive the master extended key from the seed.
		root, err := hdkeychain.NewMaster(seed, chainParams)
		if err != nil {
			str := "failed to derive master extended key"
			return managerError(ErrKeyChain, str, err)
		}

		// Derive the cointype key according to BIP0044.
		coinTypeKeyPriv, err := deriveCoinTypeKey(root, chainParams.HDCoinType)
		if err != nil {
			str := "failed to derive cointype extended key"
			return managerError(ErrKeyChain, str, err)
		}

		cryptoKeyPub := woMgr.cryptoKeyPub
		cryptoKeyPriv := woMgr.cryptoKeyPriv
		// Encrypt the cointype keys with the associated crypto keys.
		coinTypeKeyPub, err := coinTypeKeyPriv.Neuter()
		if err != nil {
			str := "failed to convert cointype private key"
			return managerError(ErrKeyChain, str, err)
		}
		coinTypePubEnc, err := cryptoKeyPub.Encrypt([]byte(coinTypeKeyPub.String()))
		if err != nil {
			str := "failed to encrypt cointype public key"
			return managerError(ErrCrypto, str, err)
		}
		coinTypePrivEnc, err := cryptoKeyPriv.Encrypt([]byte(coinTypeKeyPriv.String()))
		if err != nil {
			str := "failed to encrypt cointype private key"
			return managerError(ErrCrypto, str, err)
		}

		// Save the encrypted cointype keys to the database.
		err = putCoinTypeKeys(tx, coinTypePubEnc, coinTypePrivEnc)
		if err != nil {
			return err
		}

		_, err = rootBucket.CreateBucket(acctNameIdxBucketName)
		if err != nil {
			str := "failed to create an account name index bucket"
			return managerError(ErrDatabase, str, err)
		}

		_, err = rootBucket.CreateBucket(acctIDIdxBucketName)
		if err != nil {
			str := "failed to create an account id index bucket"
			return managerError(ErrDatabase, str, err)
		}

		_, err = rootBucket.CreateBucket(metaBucketName)
		if err != nil {
			str := "failed to create a meta bucket"
			return managerError(ErrDatabase, str, err)
		}

		// Initialize metadata for all keys
		if err := putLastAccount(tx, DefaultAccountNum); err != nil {
			return err
		}

		// Update default account indexes
		if err := putAccountIDIndex(tx, DefaultAccountNum, defaultAccountName); err != nil {
			return err
		}
		if err := putAccountNameIndex(tx, DefaultAccountNum, defaultAccountName); err != nil {
			return err
		}
		// Update imported account indexes
		if err := putAccountIDIndex(tx, ImportedAddrAccount, ImportedAddrAccountName); err != nil {
			return err
		}
		if err := putAccountNameIndex(tx, ImportedAddrAccount, ImportedAddrAccountName); err != nil {
			return err
		}

		// Write current manager version
		if err := putManagerVersion(tx, currentMgrVersion); err != nil {
			return err
		}

		// Save "" alias for default account name for backward compat
		return putAccountNameIndex(tx, DefaultAccountNum, "")
	})
	if err != nil {
		return maybeConvertDbError(err)
	}
	return nil
}

// upgradeToVersion4 upgrades the database from version 3 to version 4.  The
// default account remains unchanged (even if it was modified by the user), but
// the empty string alias to the default account is removed.
func upgradeToVersion4(namespace walletdb.Namespace, pubPassPhrase []byte) error {
	err := namespace.Update(func(tx walletdb.Tx) error {
		// Write new manager version.
		err := putManagerVersion(tx, 4)
		if err != nil {
			return err
		}

		// Lookup the old account info to determine the real name of the
		// default account.  All other names will be removed.
		acctInfoIface, err := fetchAccountInfo(tx, DefaultAccountNum)
		if err != nil {
			return err
		}
		acctInfo, ok := acctInfoIface.(*dbBIP0044AccountRow)
		if !ok {
			str := fmt.Sprintf("unsupported account type %T", acctInfoIface)
			return managerError(ErrDatabase, str, nil)
		}

		var oldName string

		// Delete any other names for the default account.
		c := tx.RootBucket().Bucket(acctNameIdxBucketName).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			// Skip nested buckets.
			if v == nil {
				continue
			}

			// Skip account names which aren't for the default account.
			account := binary.LittleEndian.Uint32(v)
			if account != DefaultAccountNum {
				continue
			}

			if !bytes.Equal(k[4:], []byte(acctInfo.name)) {
				err := c.Delete()
				if err != nil {
					const str = "error deleting default account alias"
					return managerError(ErrUpgrade, str, err)
				}
				oldName = string(k[4:])
				break
			}
		}

		// The account number to name index may map to the wrong name,
		// so rewrite the entry with the true name from the account row
		// instead of leaving it set to an incorrect alias.
		err = putAccountIDIndex(tx, DefaultAccountNum, acctInfo.name)
		if err != nil {
			const str = "account number to name index could not be " +
				"rewritten with actual account name"
			return managerError(ErrUpgrade, str, err)
		}

		// Ensure that the true name for the default account maps
		// forwards and backwards to the default account number.
		name, err := fetchAccountName(tx, DefaultAccountNum)
		if err != nil {
			return err
		}
		if name != acctInfo.name {
			const str = "account name index does not map default account number to correct name"
			return managerError(ErrUpgrade, str, nil)
		}
		acct, err := fetchAccountByName(tx, acctInfo.name)
		if err != nil {
			return err
		}
		if acct != DefaultAccountNum {
			const str = "default account not accessible under correct name"
			return managerError(ErrUpgrade, str, nil)
		}

		// Ensure that looking up the default account by the old name
		// cannot succeed.
		_, err = fetchAccountByName(tx, oldName)
		if err == nil {
			const str = "default account exists under old name"
			return managerError(ErrUpgrade, str, nil)
		}
		merr, ok := err.(ManagerError)
		if !ok || merr.ErrorCode != ErrAccountNotFound {
			return err
		}

		return nil
	})
	if err != nil {
		return maybeConvertDbError(err)
	}
	return nil
}
