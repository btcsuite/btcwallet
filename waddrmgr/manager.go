// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"sync"

	"github.com/jadeblaquiere/ctcd/btcec"
	"github.com/jadeblaquiere/ctcd/chaincfg"
	"github.com/jadeblaquiere/ctcd/chaincfg/chainhash"
	"github.com/jadeblaquiere/ctcutil"
	"github.com/jadeblaquiere/ctcutil/hdkeychain"
	"github.com/jadeblaquiere/ctcwallet/internal/zero"
	"github.com/jadeblaquiere/ctcwallet/snacl"
	"github.com/jadeblaquiere/ctcwallet/walletdb"
)

const (
	// MaxAccountNum is the maximum allowed account number.  This value was
	// chosen because accounts are hardened children and therefore must
	// not exceed the hardened child range of extended keys and it provides
	// a reserved account at the top of the range for supporting imported
	// addresses.
	MaxAccountNum = hdkeychain.HardenedKeyStart - 2 // 2^31 - 2

	// MaxAddressesPerAccount is the maximum allowed number of addresses
	// per account number.  This value is based on the limitation of
	// the underlying hierarchical deterministic key derivation.
	MaxAddressesPerAccount = hdkeychain.HardenedKeyStart - 1

	// ImportedAddrAccount is the account number to use for all imported
	// addresses.  This is useful since normal accounts are derived from the
	// root hierarchical deterministic key and imported addresses do not
	// fit into that model.
	ImportedAddrAccount = MaxAccountNum + 1 // 2^31 - 1

	// ImportedAddrAccountName is the name of the imported account.
	ImportedAddrAccountName = "imported"

	// DefaultAccountNum is the number of the default account.
	DefaultAccountNum = 0

	// defaultAccountName is the initial name of the default account.  Note
	// that the default account may be renamed and is not a reserved name,
	// so the default account might not be named "default" and non-default
	// accounts may be named "default".
	//
	// Account numbers never change, so the DefaultAccountNum should be used
	// to refer to (and only to) the default account.
	defaultAccountName = "default"

	// The hierarchy described by BIP0043 is:
	//  m/<purpose>'/*
	// This is further extended by BIP0044 to:
	//  m/44'/<coin type>'/<account>'/<branch>/<address index>
	//
	// The branch is 0 for external addresses and 1 for internal addresses.

	// maxCoinType is the maximum allowed coin type used when structuring
	// the BIP0044 multi-account hierarchy.  This value is based on the
	// limitation of the underlying hierarchical deterministic key
	// derivation.
	maxCoinType = hdkeychain.HardenedKeyStart - 1

	// externalBranch is the child number to use when performing BIP0044
	// style hierarchical deterministic key derivation for the external
	// branch.
	externalBranch uint32 = 0

	// internalBranch is the child number to use when performing BIP0044
	// style hierarchical deterministic key derivation for the internal
	// branch.
	internalBranch uint32 = 1

	// saltSize is the number of bytes of the salt used when hashing
	// private passphrases.
	saltSize = 32
)

// isReservedAccountName returns true if the account name is reserved.  Reserved
// accounts may never be renamed, and other accounts may not be renamed to a
// reserved name.
func isReservedAccountName(name string) bool {
	return name == ImportedAddrAccountName
}

// isReservedAccountNum returns true if the account number is reserved.
// Reserved accounts may not be renamed.
func isReservedAccountNum(acct uint32) bool {
	return acct == ImportedAddrAccount
}

// ScryptOptions is used to hold the scrypt parameters needed when deriving new
// passphrase keys.
type ScryptOptions struct {
	N, R, P int
}

// OpenCallbacks houses caller-provided callbacks that may be called when
// opening an existing manager.  The open blocks on the execution of these
// functions.
type OpenCallbacks struct {
	// ObtainSeed is a callback function that is potentially invoked during
	// upgrades.  It is intended to be used to request the wallet seed
	// from the user (or any other mechanism the caller deems fit).
	ObtainSeed ObtainUserInputFunc
	// ObtainPrivatePass is a callback function that is potentially invoked
	// during upgrades.  It is intended to be used to request the wallet
	// private passphrase from the user (or any other mechanism the caller
	// deems fit).
	ObtainPrivatePass ObtainUserInputFunc
}

// DefaultScryptOptions is the default options used with scrypt.
var DefaultScryptOptions = ScryptOptions{
	N: 262144, // 2^18
	R: 8,
	P: 1,
}

// addrKey is used to uniquely identify an address even when those addresses
// would end up being the same bitcoin address (as is the case for pay-to-pubkey
// and pay-to-pubkey-hash style of addresses).
type addrKey string

// accountInfo houses the current state of the internal and external branches
// of an account along with the extended keys needed to derive new keys.  It
// also handles locking by keeping an encrypted version of the serialized
// private extended key so the unencrypted versions can be cleared from memory
// when the address manager is locked.
type accountInfo struct {
	acctName string

	// The account key is used to derive the branches which in turn derive
	// the internal and external addresses.
	// The accountKeyPriv will be nil when the address manager is locked.
	acctKeyEncrypted []byte
	acctKeyPriv      *hdkeychain.ExtendedKey
	acctKeyPub       *hdkeychain.ExtendedKey

	// The external branch is used for all addresses which are intended
	// for external use.
	nextExternalIndex uint32
	lastExternalAddr  ManagedAddress

	// The internal branch is used for all adddresses which are only
	// intended for internal wallet use such as change addresses.
	nextInternalIndex uint32
	lastInternalAddr  ManagedAddress
}

// AccountProperties contains properties associated with each account, such as
// the account name, number, and the nubmer of derived and imported keys.
type AccountProperties struct {
	AccountNumber    uint32
	AccountName      string
	ExternalKeyCount uint32
	InternalKeyCount uint32
	ImportedKeyCount uint32
}

// unlockDeriveInfo houses the information needed to derive a private key for a
// managed address when the address manager is unlocked.  See the deriveOnUnlock
// field in the Manager struct for more details on how this is used.
type unlockDeriveInfo struct {
	managedAddr *managedAddress
	branch      uint32
	index       uint32
}

// defaultNewSecretKey returns a new secret key.  See newSecretKey.
func defaultNewSecretKey(passphrase *[]byte, config *ScryptOptions) (*snacl.SecretKey, error) {
	return snacl.NewSecretKey(passphrase, config.N, config.R, config.P)
}

// newSecretKey is used as a way to replace the new secret key generation
// function used so tests can provide a version that fails for testing error
// paths.
var newSecretKey = defaultNewSecretKey

// EncryptorDecryptor provides an abstraction on top of snacl.CryptoKey so that
// our tests can use dependency injection to force the behaviour they need.
type EncryptorDecryptor interface {
	Encrypt(in []byte) ([]byte, error)
	Decrypt(in []byte) ([]byte, error)
	Bytes() []byte
	CopyBytes([]byte)
	Zero()
}

// cryptoKey extends snacl.CryptoKey to implement EncryptorDecryptor.
type cryptoKey struct {
	snacl.CryptoKey
}

// Bytes returns a copy of this crypto key's byte slice.
func (ck *cryptoKey) Bytes() []byte {
	return ck.CryptoKey[:]
}

// CopyBytes copies the bytes from the given slice into this CryptoKey.
func (ck *cryptoKey) CopyBytes(from []byte) {
	copy(ck.CryptoKey[:], from)
}

// defaultNewCryptoKey returns a new CryptoKey.  See newCryptoKey.
func defaultNewCryptoKey() (EncryptorDecryptor, error) {
	key, err := snacl.GenerateCryptoKey()
	if err != nil {
		return nil, err
	}
	return &cryptoKey{*key}, nil
}

// CryptoKeyType is used to differentiate between different kinds of
// crypto keys.
type CryptoKeyType byte

// Crypto key types.
const (
	// CKTPrivate specifies the key that is used for encryption of private
	// key material such as derived extended private keys and imported
	// private keys.
	CKTPrivate CryptoKeyType = iota

	// CKTScript specifies the key that is used for encryption of scripts.
	CKTScript

	// CKTPublic specifies the key that is used for encryption of public
	// key material such as dervied extended public keys and imported public
	// keys.
	CKTPublic
)

// newCryptoKey is used as a way to replace the new crypto key generation
// function used so tests can provide a version that fails for testing error
// paths.
var newCryptoKey = defaultNewCryptoKey

// Manager represents a concurrency safe crypto currency address manager and
// key store.
type Manager struct {
	mtx sync.RWMutex

	namespace    walletdb.Namespace
	chainParams  *chaincfg.Params
	addrs        map[addrKey]ManagedAddress
	syncState    syncState
	watchingOnly bool
	locked       bool
	closed       bool

	// acctInfo houses information about accounts including what is needed
	// to generate deterministic chained keys for each created account.
	acctInfo map[uint32]*accountInfo

	// masterKeyPub is the secret key used to secure the cryptoKeyPub key
	// and masterKeyPriv is the secret key used to secure the cryptoKeyPriv
	// key.  This approach is used because it makes changing the passwords
	// much simpler as it then becomes just changing these keys.  It also
	// provides future flexibility.
	//
	// NOTE: This is not the same thing as BIP0032 master node extended
	// key.
	//
	// The underlying master private key will be zeroed when the address
	// manager is locked.
	masterKeyPub  *snacl.SecretKey
	masterKeyPriv *snacl.SecretKey

	// cryptoKeyPub is the key used to encrypt public extended keys and
	// addresses.
	cryptoKeyPub EncryptorDecryptor

	// cryptoKeyPriv is the key used to encrypt private data such as the
	// master hierarchical deterministic extended key.
	//
	// This key will be zeroed when the address manager is locked.
	cryptoKeyPrivEncrypted []byte
	cryptoKeyPriv          EncryptorDecryptor

	// cryptoKeyScript is the key used to encrypt script data.
	//
	// This key will be zeroed when the address manager is locked.
	cryptoKeyScriptEncrypted []byte
	cryptoKeyScript          EncryptorDecryptor

	// deriveOnUnlock is a list of private keys which needs to be derived
	// on the next unlock.  This occurs when a public address is derived
	// while the address manager is locked since it does not have access to
	// the private extended key (hence nor the underlying private key) in
	// order to encrypt it.
	deriveOnUnlock []*unlockDeriveInfo

	// privPassphraseSalt and hashedPrivPassphrase allow for the secure
	// detection of a correct passphrase on manager unlock when the
	// manager is already unlocked.  The hash is zeroed each lock.
	privPassphraseSalt   [saltSize]byte
	hashedPrivPassphrase [sha512.Size]byte
}

// lock performs a best try effort to remove and zero all secret keys associated
// with the address manager.
//
// This function MUST be called with the manager lock held for writes.
func (m *Manager) lock() {
	// Clear all of the account private keys.
	for _, acctInfo := range m.acctInfo {
		if acctInfo.acctKeyPriv != nil {
			acctInfo.acctKeyPriv.Zero()
		}
		acctInfo.acctKeyPriv = nil
	}

	// Remove clear text private keys and scripts from all address entries.
	for _, ma := range m.addrs {
		switch addr := ma.(type) {
		case *managedAddress:
			addr.lock()
		case *scriptAddress:
			addr.lock()
		}
	}

	// Remove clear text private master and crypto keys from memory.
	m.cryptoKeyScript.Zero()
	m.cryptoKeyPriv.Zero()
	m.masterKeyPriv.Zero()

	// Zero the hashed passphrase.
	zero.Bytea64(&m.hashedPrivPassphrase)

	// NOTE: m.cryptoKeyPub is intentionally not cleared here as the address
	// manager needs to be able to continue to read and decrypt public data
	// which uses a separate derived key from the database even when it is
	// locked.

	m.locked = true
}

// zeroSensitivePublicData performs a best try effort to remove and zero all
// sensitive public data associated with the address manager such as
// hierarchical deterministic extended public keys and the crypto public keys.
func (m *Manager) zeroSensitivePublicData() {
	// Clear all of the account private keys.
	for _, acctInfo := range m.acctInfo {
		acctInfo.acctKeyPub.Zero()
		acctInfo.acctKeyPub = nil
	}

	// Remove clear text public master and crypto keys from memory.
	m.cryptoKeyPub.Zero()
	m.masterKeyPub.Zero()
}

// Close cleanly shuts down the manager.  It makes a best try effort to remove
// and zero all private key and sensitive public key material associated with
// the address manager from memory.
func (m *Manager) Close() error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Attempt to clear private key material from memory.
	if !m.watchingOnly && !m.locked {
		m.lock()
	}

	// Attempt to clear sensitive public key material from memory too.
	m.zeroSensitivePublicData()

	m.closed = true
	return nil
}

// keyToManaged returns a new managed address for the provided derived key and
// its derivation path which consists of the account, branch, and index.
//
// The passed derivedKey is zeroed after the new address is created.
//
// This function MUST be called with the manager lock held for writes.
func (m *Manager) keyToManaged(derivedKey *hdkeychain.ExtendedKey, account, branch, index uint32) (ManagedAddress, error) {
	// Create a new managed address based on the public or private key
	// depending on whether the passed key is private.  Also, zero the
	// key after creating the managed address from it.
	ma, err := newManagedAddressFromExtKey(m, account, derivedKey)
	defer derivedKey.Zero()
	if err != nil {
		return nil, err
	}
	if !derivedKey.IsPrivate() {
		// Add the managed address to the list of addresses that need
		// their private keys derived when the address manager is next
		// unlocked.
		info := unlockDeriveInfo{
			managedAddr: ma,
			branch:      branch,
			index:       index,
		}
		m.deriveOnUnlock = append(m.deriveOnUnlock, &info)
	}
	if branch == internalBranch {
		ma.internal = true
	}

	return ma, nil
}

// deriveKey returns either a public or private derived extended key based on
// the private flag for the given an account info, branch, and index.
func (m *Manager) deriveKey(acctInfo *accountInfo, branch, index uint32, private bool) (*hdkeychain.ExtendedKey, error) {
	// Choose the public or private extended key based on whether or not
	// the private flag was specified.  This, in turn, allows for public or
	// private child derivation.
	acctKey := acctInfo.acctKeyPub
	if private {
		acctKey = acctInfo.acctKeyPriv
	}

	// Derive and return the key.
	branchKey, err := acctKey.Child(branch)
	if err != nil {
		str := fmt.Sprintf("failed to derive extended key branch %d",
			branch)
		return nil, managerError(ErrKeyChain, str, err)
	}
	addressKey, err := branchKey.Child(index)
	branchKey.Zero() // Zero branch key after it's used.
	if err != nil {
		str := fmt.Sprintf("failed to derive child extended key -- "+
			"branch %d, child %d",
			branch, index)
		return nil, managerError(ErrKeyChain, str, err)
	}
	return addressKey, nil
}

// loadAccountInfo attempts to load and cache information about the given
// account from the database.   This includes what is necessary to derive new
// keys for it and track the state of the internal and external branches.
//
// This function MUST be called with the manager lock held for writes.
func (m *Manager) loadAccountInfo(account uint32) (*accountInfo, error) {
	// Return the account info from cache if it's available.
	if acctInfo, ok := m.acctInfo[account]; ok {
		return acctInfo, nil
	}

	// The account is either invalid or just wasn't cached, so attempt to
	// load the information from the database.
	var rowInterface interface{}
	err := m.namespace.View(func(tx walletdb.Tx) error {
		var err error
		rowInterface, err = fetchAccountInfo(tx, account)
		return err
	})
	if err != nil {
		return nil, maybeConvertDbError(err)
	}

	// Ensure the account type is a BIP0044 account.
	row, ok := rowInterface.(*dbBIP0044AccountRow)
	if !ok {
		str := fmt.Sprintf("unsupported account type %T", row)
		err = managerError(ErrDatabase, str, nil)
	}

	// Use the crypto public key to decrypt the account public extended key.
	serializedKeyPub, err := m.cryptoKeyPub.Decrypt(row.pubKeyEncrypted)
	if err != nil {
		str := fmt.Sprintf("failed to decrypt public key for account %d",
			account)
		return nil, managerError(ErrCrypto, str, err)
	}
	acctKeyPub, err := hdkeychain.NewKeyFromString(string(serializedKeyPub))
	if err != nil {
		str := fmt.Sprintf("failed to create extended public key for "+
			"account %d", account)
		return nil, managerError(ErrKeyChain, str, err)
	}

	// Create the new account info with the known information.  The rest
	// of the fields are filled out below.
	acctInfo := &accountInfo{
		acctName:          row.name,
		acctKeyEncrypted:  row.privKeyEncrypted,
		acctKeyPub:        acctKeyPub,
		nextExternalIndex: row.nextExternalIndex,
		nextInternalIndex: row.nextInternalIndex,
	}

	if !m.locked {
		// Use the crypto private key to decrypt the account private
		// extended keys.
		decrypted, err := m.cryptoKeyPriv.Decrypt(acctInfo.acctKeyEncrypted)
		if err != nil {
			str := fmt.Sprintf("failed to decrypt private key for "+
				"account %d", account)
			return nil, managerError(ErrCrypto, str, err)
		}

		acctKeyPriv, err := hdkeychain.NewKeyFromString(string(decrypted))
		if err != nil {
			str := fmt.Sprintf("failed to create extended private "+
				"key for account %d", account)
			return nil, managerError(ErrKeyChain, str, err)
		}
		acctInfo.acctKeyPriv = acctKeyPriv
	}

	// Derive and cache the managed address for the last external address.
	branch, index := externalBranch, row.nextExternalIndex
	if index > 0 {
		index--
	}
	lastExtKey, err := m.deriveKey(acctInfo, branch, index, !m.locked)
	if err != nil {
		return nil, err
	}
	lastExtAddr, err := m.keyToManaged(lastExtKey, account, branch, index)
	if err != nil {
		return nil, err
	}
	acctInfo.lastExternalAddr = lastExtAddr

	// Derive and cache the managed address for the last internal address.
	branch, index = internalBranch, row.nextInternalIndex
	if index > 0 {
		index--
	}
	lastIntKey, err := m.deriveKey(acctInfo, branch, index, !m.locked)
	if err != nil {
		return nil, err
	}
	lastIntAddr, err := m.keyToManaged(lastIntKey, account, branch, index)
	if err != nil {
		return nil, err
	}
	acctInfo.lastInternalAddr = lastIntAddr

	// Add it to the cache and return it when everything is successful.
	m.acctInfo[account] = acctInfo
	return acctInfo, nil
}

// AccountProperties returns properties associated with the account, such as the
// account number, name, and the number of derived and imported keys.
//
// TODO: Instead of opening a second read transaction after making a change, and
// then fetching the account properties with a new read tx, this can be made
// more performant by simply returning the new account properties during the
// change.
func (m *Manager) AccountProperties(account uint32) (*AccountProperties, error) {
	defer m.mtx.RUnlock()
	m.mtx.RLock()

	props := &AccountProperties{AccountNumber: account}

	// Until keys can be imported into any account, special handling is
	// required for the imported account.
	//
	// loadAccountInfo errors when using it on the imported account since
	// the accountInfo struct is filled with a BIP0044 account's extended
	// keys, and the imported accounts has none.
	//
	// Since only the imported account allows imports currently, the number
	// of imported keys for any other account is zero, and since the
	// imported account cannot contain non-imported keys, the external and
	// internal key counts for it are zero.
	if account != ImportedAddrAccount {
		acctInfo, err := m.loadAccountInfo(account)
		if err != nil {
			return nil, err
		}
		props.AccountName = acctInfo.acctName
		props.ExternalKeyCount = acctInfo.nextExternalIndex
		props.InternalKeyCount = acctInfo.nextInternalIndex
	} else {
		props.AccountName = ImportedAddrAccountName // reserved, nonchangable

		// Could be more efficient if this was tracked by the db.
		var importedKeyCount uint32
		err := m.namespace.View(func(tx walletdb.Tx) error {
			count := func(interface{}) error {
				importedKeyCount++
				return nil
			}
			return forEachAccountAddress(tx, ImportedAddrAccount,
				count)
		})
		if err != nil {
			return nil, err
		}
		props.ImportedKeyCount = importedKeyCount
	}

	return props, nil
}

// deriveKeyFromPath returns either a public or private derived extended key
// based on the private flag for the given an account, branch, and index.
//
// This function MUST be called with the manager lock held for writes.
func (m *Manager) deriveKeyFromPath(account, branch, index uint32, private bool) (*hdkeychain.ExtendedKey, error) {
	// Look up the account key information.
	acctInfo, err := m.loadAccountInfo(account)
	if err != nil {
		return nil, err
	}

	return m.deriveKey(acctInfo, branch, index, private)
}

// chainAddressRowToManaged returns a new managed address based on chained
// address data loaded from the database.
//
// This function MUST be called with the manager lock held for writes.
func (m *Manager) chainAddressRowToManaged(row *dbChainAddressRow) (ManagedAddress, error) {
	addressKey, err := m.deriveKeyFromPath(row.account, row.branch,
		row.index, !m.locked)
	if err != nil {
		return nil, err
	}

	return m.keyToManaged(addressKey, row.account, row.branch, row.index)
}

// importedAddressRowToManaged returns a new managed address based on imported
// address data loaded from the database.
func (m *Manager) importedAddressRowToManaged(row *dbImportedAddressRow) (ManagedAddress, error) {
	// Use the crypto public key to decrypt the imported public key.
	pubBytes, err := m.cryptoKeyPub.Decrypt(row.encryptedPubKey)
	if err != nil {
		str := "failed to decrypt public key for imported address"
		return nil, managerError(ErrCrypto, str, err)
	}

	pubKey, err := btcec.ParsePubKey(pubBytes, btcec.S256())
	if err != nil {
		str := "invalid public key for imported address"
		return nil, managerError(ErrCrypto, str, err)
	}

	compressed := len(pubBytes) == btcec.PubKeyBytesLenCompressed
	ma, err := newManagedAddressWithoutPrivKey(m, row.account, pubKey,
		compressed)
	if err != nil {
		return nil, err
	}
	ma.privKeyEncrypted = row.encryptedPrivKey
	ma.imported = true

	return ma, nil
}

// scriptAddressRowToManaged returns a new managed address based on script
// address data loaded from the database.
func (m *Manager) scriptAddressRowToManaged(row *dbScriptAddressRow) (ManagedAddress, error) {
	// Use the crypto public key to decrypt the imported script hash.
	scriptHash, err := m.cryptoKeyPub.Decrypt(row.encryptedHash)
	if err != nil {
		str := "failed to decrypt imported script hash"
		return nil, managerError(ErrCrypto, str, err)
	}

	return newScriptAddress(m, row.account, scriptHash, row.encryptedScript)
}

// rowInterfaceToManaged returns a new managed address based on the given
// address data loaded from the database.  It will automatically select the
// appropriate type.
//
// This function MUST be called with the manager lock held for writes.
func (m *Manager) rowInterfaceToManaged(rowInterface interface{}) (ManagedAddress, error) {
	switch row := rowInterface.(type) {
	case *dbChainAddressRow:
		return m.chainAddressRowToManaged(row)

	case *dbImportedAddressRow:
		return m.importedAddressRowToManaged(row)

	case *dbScriptAddressRow:
		return m.scriptAddressRowToManaged(row)
	}

	str := fmt.Sprintf("unsupported address type %T", rowInterface)
	return nil, managerError(ErrDatabase, str, nil)
}

// loadAndCacheAddress attempts to load the passed address from the database and
// caches the associated managed address.
//
// This function MUST be called with the manager lock held for writes.
func (m *Manager) loadAndCacheAddress(address btcutil.Address) (ManagedAddress, error) {
	// Attempt to load the raw address information from the database.
	var rowInterface interface{}
	err := m.namespace.View(func(tx walletdb.Tx) error {
		var err error
		rowInterface, err = fetchAddress(tx, address.ScriptAddress())
		return err
	})
	if err != nil {
		if merr, ok := err.(*ManagerError); ok {
			desc := fmt.Sprintf("failed to fetch address '%s': %v",
				address.ScriptAddress(), merr.Description)
			merr.Description = desc
			return nil, merr
		}
		return nil, maybeConvertDbError(err)
	}

	// Create a new managed address for the specific type of address based
	// on type.
	managedAddr, err := m.rowInterfaceToManaged(rowInterface)
	if err != nil {
		return nil, err
	}

	// Cache and return the new managed address.
	m.addrs[addrKey(managedAddr.Address().ScriptAddress())] = managedAddr
	return managedAddr, nil
}

// Address returns a managed address given the passed address if it is known
// to the address manager.  A managed address differs from the passed address
// in that it also potentially contains extra information needed to sign
// transactions such as the associated private key for pay-to-pubkey and
// pay-to-pubkey-hash addresses and the script associated with
// pay-to-script-hash addresses.
func (m *Manager) Address(address btcutil.Address) (ManagedAddress, error) {
	// ScriptAddress will only return a script hash if we're
	// accessing an address that is either PKH or SH. In
	// the event we're passed a PK address, convert the
	// PK to PKH address so that we can access it from
	// the addrs map and database.
	if pka, ok := address.(*btcutil.AddressPubKey); ok {
		address = pka.AddressPubKeyHash()
	}

	// Return the address from cache if it's available.
	//
	// NOTE: Not using a defer on the lock here since a write lock is
	// needed if the lookup fails.
	m.mtx.RLock()
	if ma, ok := m.addrs[addrKey(address.ScriptAddress())]; ok {
		m.mtx.RUnlock()
		return ma, nil
	}
	m.mtx.RUnlock()

	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Attempt to load the address from the database.
	return m.loadAndCacheAddress(address)
}

// AddrAccount returns the account to which the given address belongs.
func (m *Manager) AddrAccount(address btcutil.Address) (uint32, error) {
	var account uint32
	err := m.namespace.View(func(tx walletdb.Tx) error {
		var err error
		account, err = fetchAddrAccount(tx, address.ScriptAddress())
		return err
	})
	if err != nil {
		return 0, maybeConvertDbError(err)
	}
	return account, nil
}

// ChangePassphrase changes either the public or private passphrase to the
// provided value depending on the private flag.  In order to change the private
// password, the address manager must not be watching-only.  The new passphrase
// keys are derived using the scrypt parameters in the options, so changing the
// passphrase may be used to bump the computational difficulty needed to brute
// force the passphrase.
func (m *Manager) ChangePassphrase(oldPassphrase, newPassphrase []byte, private bool, config *ScryptOptions) error {
	// No private passphrase to change for a watching-only address manager.
	if private && m.watchingOnly {
		return managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Ensure the provided old passphrase is correct.  This check is done
	// using a copy of the appropriate master key depending on the private
	// flag to ensure the current state is not altered.  The temp key is
	// cleared when done to avoid leaving a copy in memory.
	var keyName string
	secretKey := snacl.SecretKey{Key: &snacl.CryptoKey{}}
	if private {
		keyName = "private"
		secretKey.Parameters = m.masterKeyPriv.Parameters
	} else {
		keyName = "public"
		secretKey.Parameters = m.masterKeyPub.Parameters
	}
	if err := secretKey.DeriveKey(&oldPassphrase); err != nil {
		if err == snacl.ErrInvalidPassword {
			str := fmt.Sprintf("invalid passphrase for %s master "+
				"key", keyName)
			return managerError(ErrWrongPassphrase, str, nil)
		}

		str := fmt.Sprintf("failed to derive %s master key", keyName)
		return managerError(ErrCrypto, str, err)
	}
	defer secretKey.Zero()

	// Generate a new master key from the passphrase which is used to secure
	// the actual secret keys.
	newMasterKey, err := newSecretKey(&newPassphrase, config)
	if err != nil {
		str := "failed to create new master private key"
		return managerError(ErrCrypto, str, err)
	}
	newKeyParams := newMasterKey.Marshal()

	if private {
		// Technically, the locked state could be checked here to only
		// do the decrypts when the address manager is locked as the
		// clear text keys are already available in memory when it is
		// unlocked, but this is not a hot path, decryption is quite
		// fast, and it's less cyclomatic complexity to simply decrypt
		// in either case.

		// Create a new salt that will be used for hashing the new
		// passphrase each unlock.
		var passphraseSalt [saltSize]byte
		_, err := rand.Read(passphraseSalt[:])
		if err != nil {
			str := "failed to read random source for passhprase salt"
			return managerError(ErrCrypto, str, err)
		}

		// Re-encrypt the crypto private key using the new master
		// private key.
		decPriv, err := secretKey.Decrypt(m.cryptoKeyPrivEncrypted)
		if err != nil {
			str := "failed to decrypt crypto private key"
			return managerError(ErrCrypto, str, err)
		}
		encPriv, err := newMasterKey.Encrypt(decPriv)
		zero.Bytes(decPriv)
		if err != nil {
			str := "failed to encrypt crypto private key"
			return managerError(ErrCrypto, str, err)
		}

		// Re-encrypt the crypto script key using the new master private
		// key.
		decScript, err := secretKey.Decrypt(m.cryptoKeyScriptEncrypted)
		if err != nil {
			str := "failed to decrypt crypto script key"
			return managerError(ErrCrypto, str, err)
		}
		encScript, err := newMasterKey.Encrypt(decScript)
		zero.Bytes(decScript)
		if err != nil {
			str := "failed to encrypt crypto script key"
			return managerError(ErrCrypto, str, err)
		}

		// When the manager is locked, ensure the new clear text master
		// key is cleared from memory now that it is no longer needed.
		// If unlocked, create the new passphrase hash with the new
		// passphrase and salt.
		var hashedPassphrase [sha512.Size]byte
		if m.locked {
			newMasterKey.Zero()
		} else {
			saltedPassphrase := append(passphraseSalt[:],
				newPassphrase...)
			hashedPassphrase = sha512.Sum512(saltedPassphrase)
			zero.Bytes(saltedPassphrase)
		}

		// Save the new keys and params to the the db in a single
		// transaction.
		err = m.namespace.Update(func(tx walletdb.Tx) error {
			err := putCryptoKeys(tx, nil, encPriv, encScript)
			if err != nil {
				return err
			}

			return putMasterKeyParams(tx, nil, newKeyParams)
		})
		if err != nil {
			return maybeConvertDbError(err)
		}

		// Now that the db has been successfully updated, clear the old
		// key and set the new one.
		copy(m.cryptoKeyPrivEncrypted[:], encPriv)
		copy(m.cryptoKeyScriptEncrypted[:], encScript)
		m.masterKeyPriv.Zero() // Clear the old key.
		m.masterKeyPriv = newMasterKey
		m.privPassphraseSalt = passphraseSalt
		m.hashedPrivPassphrase = hashedPassphrase
	} else {
		// Re-encrypt the crypto public key using the new master public
		// key.
		encryptedPub, err := newMasterKey.Encrypt(m.cryptoKeyPub.Bytes())
		if err != nil {
			str := "failed to encrypt crypto public key"
			return managerError(ErrCrypto, str, err)
		}

		// Save the new keys and params to the the db in a single
		// transaction.
		err = m.namespace.Update(func(tx walletdb.Tx) error {
			err := putCryptoKeys(tx, encryptedPub, nil, nil)
			if err != nil {
				return err
			}

			return putMasterKeyParams(tx, newKeyParams, nil)
		})
		if err != nil {
			return maybeConvertDbError(err)
		}

		// Now that the db has been successfully updated, clear the old
		// key and set the new one.
		m.masterKeyPub.Zero()
		m.masterKeyPub = newMasterKey
	}

	return nil
}

// ConvertToWatchingOnly converts the current address manager to a locked
// watching-only address manager.
//
// WARNING: This function removes private keys from the existing address manager
// which means they will no longer be available.  Typically the caller will make
// a copy of the existing wallet database and modify the copy since otherwise it
// would mean permanent loss of any imported private keys and scripts.
//
// Executing this function on a manager that is already watching-only will have
// no effect.
func (m *Manager) ConvertToWatchingOnly() error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Exit now if the manager is already watching-only.
	if m.watchingOnly {
		return nil
	}

	// Remove all private key material and mark the new database as watching
	// only.
	err := m.namespace.Update(func(tx walletdb.Tx) error {
		if err := deletePrivateKeys(tx); err != nil {
			return err
		}

		return putWatchingOnly(tx, true)
	})
	if err != nil {
		return maybeConvertDbError(err)
	}

	// Lock the manager to remove all clear text private key material from
	// memory if needed.
	if !m.locked {
		m.lock()
	}

	// This section clears and removes the encrypted private key material
	// that is ordinarily used to unlock the manager.  Since the the manager
	// is being converted to watching-only, the encrypted private key
	// material is no longer needed.

	// Clear and remove all of the encrypted acount private keys.
	for _, acctInfo := range m.acctInfo {
		zero.Bytes(acctInfo.acctKeyEncrypted)
		acctInfo.acctKeyEncrypted = nil
	}

	// Clear and remove encrypted private keys and encrypted scripts from
	// all address entries.
	for _, ma := range m.addrs {
		switch addr := ma.(type) {
		case *managedAddress:
			zero.Bytes(addr.privKeyEncrypted)
			addr.privKeyEncrypted = nil
		case *scriptAddress:
			zero.Bytes(addr.scriptEncrypted)
			addr.scriptEncrypted = nil
		}
	}

	// Clear and remove encrypted private and script crypto keys.
	zero.Bytes(m.cryptoKeyScriptEncrypted)
	m.cryptoKeyScriptEncrypted = nil
	m.cryptoKeyScript = nil
	zero.Bytes(m.cryptoKeyPrivEncrypted)
	m.cryptoKeyPrivEncrypted = nil
	m.cryptoKeyPriv = nil

	// The master private key is derived from a passphrase when the manager
	// is unlocked, so there is no encrypted version to zero.  However,
	// it is no longer needed, so nil it.
	m.masterKeyPriv = nil

	// Mark the manager watching-only.
	m.watchingOnly = true
	return nil

}

// existsAddress returns whether or not the passed address is known to the
// address manager.
//
// This function MUST be called with the manager lock held for reads.
func (m *Manager) existsAddress(addressID []byte) (bool, error) {
	// Check the in-memory map first since it's faster than a db access.
	if _, ok := m.addrs[addrKey(addressID)]; ok {
		return true, nil
	}

	// Check the database if not already found above.
	var exists bool
	err := m.namespace.View(func(tx walletdb.Tx) error {
		exists = existsAddress(tx, addressID)
		return nil
	})
	if err != nil {
		return false, maybeConvertDbError(err)
	}

	return exists, nil
}

// ImportPrivateKey imports a WIF private key into the address manager.  The
// imported address is created using either a compressed or uncompressed
// serialized public key, depending on the CompressPubKey bool of the WIF.
//
// All imported addresses will be part of the account defined by the
// ImportedAddrAccount constant.
//
// NOTE: When the address manager is watching-only, the private key itself will
// not be stored or available since it is private data.  Instead, only the
// public key will be stored.  This means it is paramount the private key is
// kept elsewhere as the watching-only address manager will NOT ever have access
// to it.
//
// This function will return an error if the address manager is locked and not
// watching-only, or not for the same network as the key trying to be imported.
// It will also return an error if the address already exists.  Any other errors
// returned are generally unexpected.
func (m *Manager) ImportPrivateKey(wif *btcutil.WIF, bs *BlockStamp) (ManagedPubKeyAddress, error) {
	// Ensure the address is intended for network the address manager is
	// associated with.
	if !wif.IsForNet(m.chainParams) {
		str := fmt.Sprintf("private key is not for the same network the "+
			"address manager is configured for (%s)",
			m.chainParams.Name)
		return nil, managerError(ErrWrongNet, str, nil)
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	// The manager must be unlocked to encrypt the imported private key.
	if m.locked && !m.watchingOnly {
		return nil, managerError(ErrLocked, errLocked, nil)
	}

	// Prevent duplicates.
	serializedPubKey := wif.SerializePubKey()
	pubKeyHash := btcutil.Hash160(serializedPubKey)
	alreadyExists, err := m.existsAddress(pubKeyHash)
	if err != nil {
		return nil, err
	}
	if alreadyExists {
		str := fmt.Sprintf("address for public key %x already exists",
			serializedPubKey)
		return nil, managerError(ErrDuplicateAddress, str, nil)
	}

	// Encrypt public key.
	encryptedPubKey, err := m.cryptoKeyPub.Encrypt(serializedPubKey)
	if err != nil {
		str := fmt.Sprintf("failed to encrypt public key for %x",
			serializedPubKey)
		return nil, managerError(ErrCrypto, str, err)
	}

	// Encrypt the private key when not a watching-only address manager.
	var encryptedPrivKey []byte
	if !m.watchingOnly {
		privKeyBytes := wif.PrivKey.Serialize()
		encryptedPrivKey, err = m.cryptoKeyPriv.Encrypt(privKeyBytes)
		zero.Bytes(privKeyBytes)
		if err != nil {
			str := fmt.Sprintf("failed to encrypt private key for %x",
				serializedPubKey)
			return nil, managerError(ErrCrypto, str, err)
		}
	}

	// The start block needs to be updated when the newly imported address
	// is before the current one.
	updateStartBlock := bs.Height < m.syncState.startBlock.Height

	// Save the new imported address to the db and update start block (if
	// needed) in a single transaction.
	err = m.namespace.Update(func(tx walletdb.Tx) error {
		err := putImportedAddress(tx, pubKeyHash, ImportedAddrAccount,
			ssNone, encryptedPubKey, encryptedPrivKey)
		if err != nil {
			return err
		}

		if updateStartBlock {
			return putStartBlock(tx, bs)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Now that the database has been updated, update the start block in
	// memory too if needed.
	if updateStartBlock {
		m.syncState.startBlock = *bs
	}

	// Create a new managed address based on the imported address.
	var managedAddr *managedAddress
	if !m.watchingOnly {
		managedAddr, err = newManagedAddress(m, ImportedAddrAccount,
			wif.PrivKey, wif.CompressPubKey)
	} else {
		pubKey := (*btcec.PublicKey)(&wif.PrivKey.PublicKey)
		managedAddr, err = newManagedAddressWithoutPrivKey(m,
			ImportedAddrAccount, pubKey, wif.CompressPubKey)
	}
	if err != nil {
		return nil, err
	}
	managedAddr.imported = true

	// Add the new managed address to the cache of recent addresses and
	// return it.
	m.addrs[addrKey(managedAddr.Address().ScriptAddress())] = managedAddr
	return managedAddr, nil
}

// ImportScript imports a user-provided script into the address manager.  The
// imported script will act as a pay-to-script-hash address.
//
// All imported script addresses will be part of the account defined by the
// ImportedAddrAccount constant.
//
// When the address manager is watching-only, the script itself will not be
// stored or available since it is considered private data.
//
// This function will return an error if the address manager is locked and not
// watching-only, or the address already exists.  Any other errors returned are
// generally unexpected.
func (m *Manager) ImportScript(script []byte, bs *BlockStamp) (ManagedScriptAddress, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// The manager must be unlocked to encrypt the imported script.
	if m.locked && !m.watchingOnly {
		return nil, managerError(ErrLocked, errLocked, nil)
	}

	// Prevent duplicates.
	scriptHash := btcutil.Hash160(script)
	alreadyExists, err := m.existsAddress(scriptHash)
	if err != nil {
		return nil, err
	}
	if alreadyExists {
		str := fmt.Sprintf("address for script hash %x already exists",
			scriptHash)
		return nil, managerError(ErrDuplicateAddress, str, nil)
	}

	// Encrypt the script hash using the crypto public key so it is
	// accessible when the address manager is locked or watching-only.
	encryptedHash, err := m.cryptoKeyPub.Encrypt(scriptHash)
	if err != nil {
		str := fmt.Sprintf("failed to encrypt script hash %x",
			scriptHash)
		return nil, managerError(ErrCrypto, str, err)
	}

	// Encrypt the script for storage in database using the crypto script
	// key when not a watching-only address manager.
	var encryptedScript []byte
	if !m.watchingOnly {
		encryptedScript, err = m.cryptoKeyScript.Encrypt(script)
		if err != nil {
			str := fmt.Sprintf("failed to encrypt script for %x",
				scriptHash)
			return nil, managerError(ErrCrypto, str, err)
		}
	}

	// The start block needs to be updated when the newly imported address
	// is before the current one.
	updateStartBlock := false
	if bs.Height < m.syncState.startBlock.Height {
		updateStartBlock = true
	}

	// Save the new imported address to the db and update start block (if
	// needed) in a single transaction.
	err = m.namespace.Update(func(tx walletdb.Tx) error {
		err := putScriptAddress(tx, scriptHash, ImportedAddrAccount,
			ssNone, encryptedHash, encryptedScript)
		if err != nil {
			return err
		}

		if updateStartBlock {
			return putStartBlock(tx, bs)
		}

		return nil
	})
	if err != nil {
		return nil, maybeConvertDbError(err)
	}

	// Now that the database has been updated, update the start block in
	// memory too if needed.
	if updateStartBlock {
		m.syncState.startBlock = *bs
	}

	// Create a new managed address based on the imported script.  Also,
	// when not a watching-only address manager, make a copy of the script
	// since it will be cleared on lock and the script the caller passed
	// should not be cleared out from under the caller.
	scriptAddr, err := newScriptAddress(m, ImportedAddrAccount, scriptHash,
		encryptedScript)
	if err != nil {
		return nil, err
	}
	if !m.watchingOnly {
		scriptAddr.scriptCT = make([]byte, len(script))
		copy(scriptAddr.scriptCT, script)
	}

	// Add the new managed address to the cache of recent addresses and
	// return it.
	m.addrs[addrKey(scriptHash)] = scriptAddr
	return scriptAddr, nil
}

// IsLocked returns whether or not the address managed is locked.  When it is
// unlocked, the decryption key needed to decrypt private keys used for signing
// is in memory.
func (m *Manager) IsLocked() bool {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return m.locked
}

// Lock performs a best try effort to remove and zero all secret keys associated
// with the address manager.
//
// This function will return an error if invoked on a watching-only address
// manager.
func (m *Manager) Lock() error {
	// A watching-only address manager can't be locked.
	if m.watchingOnly {
		return managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Error on attempt to lock an already locked manager.
	if m.locked {
		return managerError(ErrLocked, errLocked, nil)
	}

	m.lock()
	return nil
}

// lookupAccount loads account number stored in the manager for the given
// account name
//
// This function MUST be called with the manager lock held for reads.
func (m *Manager) lookupAccount(name string) (uint32, error) {
	var account uint32
	err := m.namespace.View(func(tx walletdb.Tx) error {
		var err error
		account, err = fetchAccountByName(tx, name)
		return err
	})
	return account, err
}

// LookupAccount loads account number stored in the manager for the given
// account name
func (m *Manager) LookupAccount(name string) (uint32, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return m.lookupAccount(name)
}

// Unlock derives the master private key from the specified passphrase.  An
// invalid passphrase will return an error.  Otherwise, the derived secret key
// is stored in memory until the address manager is locked.  Any failures that
// occur during this function will result in the address manager being locked,
// even if it was already unlocked prior to calling this function.
//
// This function will return an error if invoked on a watching-only address
// manager.
func (m *Manager) Unlock(passphrase []byte) error {
	// A watching-only address manager can't be unlocked.
	if m.watchingOnly {
		return managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Avoid actually unlocking if the manager is already unlocked
	// and the passphrases match.
	if !m.locked {
		saltedPassphrase := append(m.privPassphraseSalt[:],
			passphrase...)
		hashedPassphrase := sha512.Sum512(saltedPassphrase)
		zero.Bytes(saltedPassphrase)
		if hashedPassphrase != m.hashedPrivPassphrase {
			m.lock()
			str := "invalid passphrase for master private key"
			return managerError(ErrWrongPassphrase, str, nil)
		}
		return nil
	}

	// Derive the master private key using the provided passphrase.
	if err := m.masterKeyPriv.DeriveKey(&passphrase); err != nil {
		m.lock()
		if err == snacl.ErrInvalidPassword {
			str := "invalid passphrase for master private key"
			return managerError(ErrWrongPassphrase, str, nil)
		}

		str := "failed to derive master private key"
		return managerError(ErrCrypto, str, err)
	}

	// Use the master private key to decrypt the crypto private key.
	decryptedKey, err := m.masterKeyPriv.Decrypt(m.cryptoKeyPrivEncrypted)
	if err != nil {
		m.lock()
		str := "failed to decrypt crypto private key"
		return managerError(ErrCrypto, str, err)
	}
	m.cryptoKeyPriv.CopyBytes(decryptedKey)
	zero.Bytes(decryptedKey)

	// Use the crypto private key to decrypt all of the account private
	// extended keys.
	for account, acctInfo := range m.acctInfo {
		decrypted, err := m.cryptoKeyPriv.Decrypt(acctInfo.acctKeyEncrypted)
		if err != nil {
			m.lock()
			str := fmt.Sprintf("failed to decrypt account %d "+
				"private key", account)
			return managerError(ErrCrypto, str, err)
		}

		acctKeyPriv, err := hdkeychain.NewKeyFromString(string(decrypted))
		zero.Bytes(decrypted)
		if err != nil {
			m.lock()
			str := fmt.Sprintf("failed to regenerate account %d "+
				"extended key", account)
			return managerError(ErrKeyChain, str, err)
		}
		acctInfo.acctKeyPriv = acctKeyPriv
	}

	// Derive any private keys that are pending due to them being created
	// while the address manager was locked.
	for _, info := range m.deriveOnUnlock {
		addressKey, err := m.deriveKeyFromPath(info.managedAddr.account,
			info.branch, info.index, true)
		if err != nil {
			m.lock()
			return err
		}

		// It's ok to ignore the error here since it can only fail if
		// the extended key is not private, however it was just derived
		// as a private key.
		privKey, _ := addressKey.ECPrivKey()
		addressKey.Zero()

		privKeyBytes := privKey.Serialize()
		privKeyEncrypted, err := m.cryptoKeyPriv.Encrypt(privKeyBytes)
		zero.BigInt(privKey.D)
		if err != nil {
			m.lock()
			str := fmt.Sprintf("failed to encrypt private key for "+
				"address %s", info.managedAddr.Address())
			return managerError(ErrCrypto, str, err)
		}
		info.managedAddr.privKeyEncrypted = privKeyEncrypted
		info.managedAddr.privKeyCT = privKeyBytes

		// Avoid re-deriving this key on subsequent unlocks.
		m.deriveOnUnlock[0] = nil
		m.deriveOnUnlock = m.deriveOnUnlock[1:]
	}

	m.locked = false
	saltedPassphrase := append(m.privPassphraseSalt[:], passphrase...)
	m.hashedPrivPassphrase = sha512.Sum512(saltedPassphrase)
	zero.Bytes(saltedPassphrase)
	return nil
}

// fetchUsed returns true if the provided address id was flagged used.
func (m *Manager) fetchUsed(addressID []byte) (bool, error) {
	var used bool
	err := m.namespace.View(func(tx walletdb.Tx) error {
		used = fetchAddressUsed(tx, addressID)
		return nil
	})
	return used, err
}

// MarkUsed updates the used flag for the provided address.
func (m *Manager) MarkUsed(address btcutil.Address) error {
	addressID := address.ScriptAddress()
	err := m.namespace.Update(func(tx walletdb.Tx) error {
		return markAddressUsed(tx, addressID)
	})
	if err != nil {
		return maybeConvertDbError(err)
	}
	// Clear caches which might have stale entries for used addresses
	m.mtx.Lock()
	delete(m.addrs, addrKey(addressID))
	m.mtx.Unlock()
	return nil
}

// ChainParams returns the chain parameters for this address manager.
func (m *Manager) ChainParams() *chaincfg.Params {
	// NOTE: No need for mutex here since the net field does not change
	// after the manager instance is created.

	return m.chainParams
}

// nextAddresses returns the specified number of next chained address from the
// branch indicated by the internal flag.
//
// This function MUST be called with the manager lock held for writes.
func (m *Manager) nextAddresses(account uint32, numAddresses uint32, internal bool) ([]ManagedAddress, error) {
	// The next address can only be generated for accounts that have already
	// been created.
	acctInfo, err := m.loadAccountInfo(account)
	if err != nil {
		return nil, err
	}

	// Choose the account key to used based on whether the address manager
	// is locked.
	acctKey := acctInfo.acctKeyPub
	if !m.locked {
		acctKey = acctInfo.acctKeyPriv
	}

	// Choose the branch key and index depending on whether or not this
	// is an internal address.
	branchNum, nextIndex := externalBranch, acctInfo.nextExternalIndex
	if internal {
		branchNum = internalBranch
		nextIndex = acctInfo.nextInternalIndex
	}

	// Ensure the requested number of addresses doesn't exceed the maximum
	// allowed for this account.
	if numAddresses > MaxAddressesPerAccount || nextIndex+numAddresses >
		MaxAddressesPerAccount {
		str := fmt.Sprintf("%d new addresses would exceed the maximum "+
			"allowed number of addresses per account of %d",
			numAddresses, MaxAddressesPerAccount)
		return nil, managerError(ErrTooManyAddresses, str, nil)
	}

	// Derive the appropriate branch key and ensure it is zeroed when done.
	branchKey, err := acctKey.Child(branchNum)
	if err != nil {
		str := fmt.Sprintf("failed to derive extended key branch %d",
			branchNum)
		return nil, managerError(ErrKeyChain, str, err)
	}
	defer branchKey.Zero() // Ensure branch key is zeroed when done.

	// Create the requested number of addresses and keep track of the index
	// with each one.
	addressInfo := make([]*unlockDeriveInfo, 0, numAddresses)
	for i := uint32(0); i < numAddresses; i++ {
		// There is an extremely small chance that a particular child is
		// invalid, so use a loop to derive the next valid child.
		var nextKey *hdkeychain.ExtendedKey
		for {
			// Derive the next child in the external chain branch.
			key, err := branchKey.Child(nextIndex)
			if err != nil {
				// When this particular child is invalid, skip to the
				// next index.
				if err == hdkeychain.ErrInvalidChild {
					nextIndex++
					continue
				}

				str := fmt.Sprintf("failed to generate child %d",
					nextIndex)
				return nil, managerError(ErrKeyChain, str, err)
			}
			key.SetNet(m.chainParams)

			nextIndex++
			nextKey = key
			break
		}

		// Create a new managed address based on the public or private
		// key depending on whether the generated key is private.  Also,
		// zero the next key after creating the managed address from it.
		managedAddr, err := newManagedAddressFromExtKey(m, account, nextKey)
		nextKey.Zero()
		if err != nil {
			return nil, err
		}
		if internal {
			managedAddr.internal = true
		}
		info := unlockDeriveInfo{
			managedAddr: managedAddr,
			branch:      branchNum,
			index:       nextIndex - 1,
		}
		addressInfo = append(addressInfo, &info)
	}

	// Now that all addresses have been successfully generated, update the
	// database in a single transaction.
	err = m.namespace.Update(func(tx walletdb.Tx) error {
		for _, info := range addressInfo {
			ma := info.managedAddr
			addressID := ma.Address().ScriptAddress()
			err := putChainedAddress(tx, addressID, account, ssFull,
				info.branch, info.index)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return nil, maybeConvertDbError(err)
	}

	// Finally update the next address tracking and add the addresses to the
	// cache after the newly generated addresses have been successfully
	// added to the db.
	managedAddresses := make([]ManagedAddress, 0, len(addressInfo))
	for _, info := range addressInfo {
		ma := info.managedAddr
		m.addrs[addrKey(ma.Address().ScriptAddress())] = ma

		// Add the new managed address to the list of addresses that
		// need their private keys derived when the address manager is
		// next unlocked.
		if m.locked && !m.watchingOnly {
			m.deriveOnUnlock = append(m.deriveOnUnlock, info)
		}

		managedAddresses = append(managedAddresses, ma)
	}

	// Set the last address and next address for tracking.
	ma := addressInfo[len(addressInfo)-1].managedAddr
	if internal {
		acctInfo.nextInternalIndex = nextIndex
		acctInfo.lastInternalAddr = ma
	} else {
		acctInfo.nextExternalIndex = nextIndex
		acctInfo.lastExternalAddr = ma
	}

	return managedAddresses, nil
}

// NextExternalAddresses returns the specified number of next chained addresses
// that are intended for external use from the address manager.
func (m *Manager) NextExternalAddresses(account uint32, numAddresses uint32) ([]ManagedAddress, error) {
	// Enforce maximum account number.
	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return nil, err
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	return m.nextAddresses(account, numAddresses, false)
}

// NextInternalAddresses returns the specified number of next chained addresses
// that are intended for internal use such as change from the address manager.
func (m *Manager) NextInternalAddresses(account uint32, numAddresses uint32) ([]ManagedAddress, error) {
	// Enforce maximum account number.
	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return nil, err
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	return m.nextAddresses(account, numAddresses, true)
}

// LastExternalAddress returns the most recently requested chained external
// address from calling NextExternalAddress for the given account.  The first
// external address for the account will be returned if none have been
// previously requested.
//
// This function will return an error if the provided account number is greater
// than the MaxAccountNum constant or there is no account information for the
// passed account.  Any other errors returned are generally unexpected.
func (m *Manager) LastExternalAddress(account uint32) (ManagedAddress, error) {
	// Enforce maximum account number.
	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return nil, err
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Load account information for the passed account.  It is typically
	// cached, but if not it will be loaded from the database.
	acctInfo, err := m.loadAccountInfo(account)
	if err != nil {
		return nil, err
	}

	if acctInfo.nextExternalIndex > 0 {
		return acctInfo.lastExternalAddr, nil
	}

	return nil, managerError(ErrAddressNotFound, "no previous external address", nil)
}

// LastInternalAddress returns the most recently requested chained internal
// address from calling NextInternalAddress for the given account.  The first
// internal address for the account will be returned if none have been
// previously requested.
//
// This function will return an error if the provided account number is greater
// than the MaxAccountNum constant or there is no account information for the
// passed account.  Any other errors returned are generally unexpected.
func (m *Manager) LastInternalAddress(account uint32) (ManagedAddress, error) {
	// Enforce maximum account number.
	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return nil, err
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Load account information for the passed account.  It is typically
	// cached, but if not it will be loaded from the database.
	acctInfo, err := m.loadAccountInfo(account)
	if err != nil {
		return nil, err
	}

	if acctInfo.nextInternalIndex > 0 {
		return acctInfo.lastInternalAddr, nil
	}

	return nil, managerError(ErrAddressNotFound, "no previous internal address", nil)
}

// ValidateAccountName validates the given account name and returns an error, if any.
func ValidateAccountName(name string) error {
	if name == "" {
		str := "accounts may not be named the empty string"
		return managerError(ErrInvalidAccount, str, nil)
	}
	if isReservedAccountName(name) {
		str := "reserved account name"
		return managerError(ErrInvalidAccount, str, nil)
	}
	return nil
}

// NewAccount creates and returns a new account stored in the manager based
// on the given account name.  If an account with the same name already exists,
// ErrDuplicateAccount will be returned.  Since creating a new account requires
// access to the cointype keys (from which extended account keys are derived),
// it requires the manager to be unlocked.
func (m *Manager) NewAccount(name string) (uint32, error) {
	if m.watchingOnly {
		return 0, managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	if m.locked {
		return 0, managerError(ErrLocked, errLocked, nil)
	}

	// Validate account name
	if err := ValidateAccountName(name); err != nil {
		return 0, err
	}

	// Check that account with the same name does not exist
	_, err := m.lookupAccount(name)
	if err == nil {
		str := fmt.Sprintf("account with the same name already exists")
		return 0, managerError(ErrDuplicateAccount, str, err)
	}

	var account uint32
	var coinTypePrivEnc []byte

	// Fetch latest account, and create a new account in the same transaction
	err = m.namespace.Update(func(tx walletdb.Tx) error {
		var err error
		// Fetch the latest account number to generate the next account number
		account, err = fetchLastAccount(tx)
		if err != nil {
			return err
		}
		account++
		// Fetch the cointype key which will be used to derive the next account
		// extended keys
		_, coinTypePrivEnc, err = fetchCoinTypeKeys(tx)
		if err != nil {
			return err
		}

		// Decrypt the cointype key
		serializedKeyPriv, err := m.cryptoKeyPriv.Decrypt(coinTypePrivEnc)
		if err != nil {
			str := fmt.Sprintf("failed to decrypt cointype serialized private key")
			return managerError(ErrLocked, str, err)
		}
		coinTypeKeyPriv, err := hdkeychain.NewKeyFromString(string(serializedKeyPriv))
		zero.Bytes(serializedKeyPriv)
		if err != nil {
			str := fmt.Sprintf("failed to create cointype extended private key")
			return managerError(ErrKeyChain, str, err)
		}

		// Derive the account key using the cointype key
		acctKeyPriv, err := deriveAccountKey(coinTypeKeyPriv, account)
		coinTypeKeyPriv.Zero()
		if err != nil {
			str := "failed to convert private key for account"
			return managerError(ErrKeyChain, str, err)
		}
		acctKeyPub, err := acctKeyPriv.Neuter()
		if err != nil {
			str := "failed to convert public key for account"
			return managerError(ErrKeyChain, str, err)
		}
		// Encrypt the default account keys with the associated crypto keys.
		acctPubEnc, err := m.cryptoKeyPub.Encrypt([]byte(acctKeyPub.String()))
		if err != nil {
			str := "failed to  encrypt public key for account"
			return managerError(ErrCrypto, str, err)
		}
		acctPrivEnc, err := m.cryptoKeyPriv.Encrypt([]byte(acctKeyPriv.String()))
		if err != nil {
			str := "failed to encrypt private key for account"
			return managerError(ErrCrypto, str, err)
		}
		// We have the encrypted account extended keys, so save them to the
		// database
		err = putAccountInfo(tx, account, acctPubEnc, acctPrivEnc, 0, 0, name)
		if err != nil {
			return err
		}

		// Save last account metadata
		if err := putLastAccount(tx, account); err != nil {
			return err
		}
		return nil
	})
	return account, err
}

// RenameAccount renames an account stored in the manager based on the
// given account number with the given name.  If an account with the same name
// already exists, ErrDuplicateAccount will be returned.
func (m *Manager) RenameAccount(account uint32, name string) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Ensure that a reserved account is not being renamed.
	if isReservedAccountNum(account) {
		str := "reserved account cannot be renamed"
		return managerError(ErrInvalidAccount, str, nil)
	}

	// Check that account with the new name does not exist
	_, err := m.lookupAccount(name)
	if err == nil {
		str := fmt.Sprintf("account with the same name already exists")
		return managerError(ErrDuplicateAccount, str, err)
	}
	// Validate account name
	if err := ValidateAccountName(name); err != nil {
		return err
	}

	var rowInterface interface{}
	err = m.namespace.Update(func(tx walletdb.Tx) error {
		var err error
		rowInterface, err = fetchAccountInfo(tx, account)
		if err != nil {
			return err
		}
		// Ensure the account type is a BIP0044 account.
		row, ok := rowInterface.(*dbBIP0044AccountRow)
		if !ok {
			str := fmt.Sprintf("unsupported account type %T", row)
			err = managerError(ErrDatabase, str, nil)
		}
		// Remove the old name key from the accout id index
		if err = deleteAccountIDIndex(tx, account); err != nil {
			return err
		}
		// Remove the old name key from the account name index
		if err = deleteAccountNameIndex(tx, row.name); err != nil {
			return err
		}
		err = putAccountInfo(tx, account, row.pubKeyEncrypted,
			row.privKeyEncrypted, row.nextExternalIndex, row.nextInternalIndex, name)
		return err
	})

	// Update in-memory account info with new name if cached and the db
	// write was successful.
	if err == nil {
		if acctInfo, ok := m.acctInfo[account]; ok {
			acctInfo.acctName = name
		}
	}

	return err
}

// AccountName returns the account name for the given account number
// stored in the manager.
func (m *Manager) AccountName(account uint32) (string, error) {
	var acctName string
	err := m.namespace.View(func(tx walletdb.Tx) error {
		var err error
		acctName, err = fetchAccountName(tx, account)
		return err
	})
	if err != nil {
		return "", err
	}

	return acctName, nil
}

// ForEachAccount calls the given function with each account stored in the
// manager, breaking early on error.
func (m *Manager) ForEachAccount(fn func(account uint32) error) error {
	return m.namespace.View(func(tx walletdb.Tx) error {
		return forEachAccount(tx, fn)
	})
}

// LastAccount returns the last account stored in the manager.
func (m *Manager) LastAccount() (uint32, error) {
	var account uint32
	err := m.namespace.View(func(tx walletdb.Tx) error {
		var err error
		account, err = fetchLastAccount(tx)
		return err
	})
	return account, err
}

// ForEachAccountAddress calls the given function with each address of
// the given account stored in the manager, breaking early on error.
func (m *Manager) ForEachAccountAddress(account uint32, fn func(maddr ManagedAddress) error) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	addrFn := func(rowInterface interface{}) error {
		managedAddr, err := m.rowInterfaceToManaged(rowInterface)
		if err != nil {
			return err
		}
		return fn(managedAddr)
	}

	err := m.namespace.View(func(tx walletdb.Tx) error {
		return forEachAccountAddress(tx, account, addrFn)
	})
	if err != nil {
		return maybeConvertDbError(err)
	}
	return nil
}

// ForEachActiveAccountAddress calls the given function with each active
// address of the given account stored in the manager, breaking early on
// error.
// TODO(tuxcanfly): actually return only active addresses
func (m *Manager) ForEachActiveAccountAddress(account uint32, fn func(maddr ManagedAddress) error) error {
	return m.ForEachAccountAddress(account, fn)
}

// ForEachActiveAddress calls the given function with each active address
// stored in the manager, breaking early on error.
func (m *Manager) ForEachActiveAddress(fn func(addr btcutil.Address) error) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	addrFn := func(rowInterface interface{}) error {
		managedAddr, err := m.rowInterfaceToManaged(rowInterface)
		if err != nil {
			return err
		}
		return fn(managedAddr.Address())
	}

	err := m.namespace.View(func(tx walletdb.Tx) error {
		return forEachActiveAddress(tx, addrFn)
	})
	if err != nil {
		return maybeConvertDbError(err)
	}
	return nil
}

// selectCryptoKey selects the appropriate crypto key based on the key type. An
// error is returned when an invalid key type is specified or the requested key
// requires the manager to be unlocked when it isn't.
//
// This function MUST be called with the manager lock held for reads.
func (m *Manager) selectCryptoKey(keyType CryptoKeyType) (EncryptorDecryptor, error) {
	if keyType == CKTPrivate || keyType == CKTScript {
		// The manager must be unlocked to work with the private keys.
		if m.locked || m.watchingOnly {
			return nil, managerError(ErrLocked, errLocked, nil)
		}
	}

	var cryptoKey EncryptorDecryptor
	switch keyType {
	case CKTPrivate:
		cryptoKey = m.cryptoKeyPriv
	case CKTScript:
		cryptoKey = m.cryptoKeyScript
	case CKTPublic:
		cryptoKey = m.cryptoKeyPub
	default:
		return nil, managerError(ErrInvalidKeyType, "invalid key type",
			nil)
	}

	return cryptoKey, nil
}

// Encrypt in using the crypto key type specified by keyType.
func (m *Manager) Encrypt(keyType CryptoKeyType, in []byte) ([]byte, error) {
	// Encryption must be performed under the manager mutex since the
	// keys are cleared when the manager is locked.
	m.mtx.Lock()
	defer m.mtx.Unlock()

	cryptoKey, err := m.selectCryptoKey(keyType)
	if err != nil {
		return nil, err
	}

	encrypted, err := cryptoKey.Encrypt(in)
	if err != nil {
		return nil, managerError(ErrCrypto, "failed to encrypt", err)
	}
	return encrypted, nil
}

// Decrypt in using the crypto key type specified by keyType.
func (m *Manager) Decrypt(keyType CryptoKeyType, in []byte) ([]byte, error) {
	// Decryption must be performed under the manager mutex since the
	// keys are cleared when the manager is locked.
	m.mtx.Lock()
	defer m.mtx.Unlock()

	cryptoKey, err := m.selectCryptoKey(keyType)
	if err != nil {
		return nil, err
	}

	decrypted, err := cryptoKey.Decrypt(in)
	if err != nil {
		return nil, managerError(ErrCrypto, "failed to decrypt", err)
	}
	return decrypted, nil
}

// newManager returns a new locked address manager with the given parameters.
func newManager(namespace walletdb.Namespace, chainParams *chaincfg.Params,
	masterKeyPub *snacl.SecretKey, masterKeyPriv *snacl.SecretKey,
	cryptoKeyPub EncryptorDecryptor, cryptoKeyPrivEncrypted,
	cryptoKeyScriptEncrypted []byte, syncInfo *syncState,
	privPassphraseSalt [saltSize]byte) *Manager {

	return &Manager{
		namespace:                namespace,
		chainParams:              chainParams,
		addrs:                    make(map[addrKey]ManagedAddress),
		syncState:                *syncInfo,
		locked:                   true,
		acctInfo:                 make(map[uint32]*accountInfo),
		masterKeyPub:             masterKeyPub,
		masterKeyPriv:            masterKeyPriv,
		cryptoKeyPub:             cryptoKeyPub,
		cryptoKeyPrivEncrypted:   cryptoKeyPrivEncrypted,
		cryptoKeyPriv:            &cryptoKey{},
		cryptoKeyScriptEncrypted: cryptoKeyScriptEncrypted,
		cryptoKeyScript:          &cryptoKey{},
		privPassphraseSalt:       privPassphraseSalt,
	}
}

// deriveCoinTypeKey derives the cointype key which can be used to derive the
// extended key for an account according to the hierarchy described by BIP0044
// given the coin type key.
//
// In particular this is the hierarchical deterministic extended key path:
// m/44'/<coin type>'
func deriveCoinTypeKey(masterNode *hdkeychain.ExtendedKey,
	coinType uint32) (*hdkeychain.ExtendedKey, error) {
	// Enforce maximum coin type.
	if coinType > maxCoinType {
		err := managerError(ErrCoinTypeTooHigh, errCoinTypeTooHigh, nil)
		return nil, err
	}

	// The hierarchy described by BIP0043 is:
	//  m/<purpose>'/*
	// This is further extended by BIP0044 to:
	//  m/44'/<coin type>'/<account>'/<branch>/<address index>
	//
	// The branch is 0 for external addresses and 1 for internal addresses.

	// Derive the purpose key as a child of the master node.
	purpose, err := masterNode.Child(44 + hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, err
	}

	// Derive the coin type key as a child of the purpose key.
	coinTypeKey, err := purpose.Child(coinType + hdkeychain.HardenedKeyStart)
	if err != nil {
		return nil, err
	}

	return coinTypeKey, nil
}

// deriveAccountKey derives the extended key for an account according to the
// hierarchy described by BIP0044 given the master node.
//
// In particular this is the hierarchical deterministic extended key path:
//   m/44'/<coin type>'/<account>'
func deriveAccountKey(coinTypeKey *hdkeychain.ExtendedKey,
	account uint32) (*hdkeychain.ExtendedKey, error) {
	// Enforce maximum account number.
	if account > MaxAccountNum {
		err := managerError(ErrAccountNumTooHigh, errAcctTooHigh, nil)
		return nil, err
	}

	// Derive the account key as a child of the coin type key.
	return coinTypeKey.Child(account + hdkeychain.HardenedKeyStart)
}

// checkBranchKeys ensures deriving the extended keys for the internal and
// external branches given an account key does not result in an invalid child
// error which means the chosen seed is not usable.  This conforms to the
// hierarchy described by BIP0044 so long as the account key is already derived
// accordingly.
//
// In particular this is the hierarchical deterministic extended key path:
//   m/44'/<coin type>'/<account>'/<branch>
//
// The branch is 0 for external addresses and 1 for internal addresses.
func checkBranchKeys(acctKey *hdkeychain.ExtendedKey) error {
	// Derive the external branch as the first child of the account key.
	if _, err := acctKey.Child(externalBranch); err != nil {
		return err
	}

	// Derive the external branch as the second child of the account key.
	_, err := acctKey.Child(internalBranch)
	return err
}

// loadManager returns a new address manager that results from loading it from
// the passed opened database.  The public passphrase is required to decrypt the
// public keys.
func loadManager(namespace walletdb.Namespace, pubPassphrase []byte, chainParams *chaincfg.Params) (*Manager, error) {
	// Perform all database lookups in a read-only view.
	var watchingOnly bool
	var masterKeyPubParams, masterKeyPrivParams []byte
	var cryptoKeyPubEnc, cryptoKeyPrivEnc, cryptoKeyScriptEnc []byte
	var syncedTo, startBlock *BlockStamp
	var recentHeight int32
	var recentHashes []chainhash.Hash
	err := namespace.View(func(tx walletdb.Tx) error {
		// Load whether or not the manager is watching-only from the db.
		var err error
		watchingOnly, err = fetchWatchingOnly(tx)
		if err != nil {
			return err
		}

		// Load the master key params from the db.
		masterKeyPubParams, masterKeyPrivParams, err =
			fetchMasterKeyParams(tx)
		if err != nil {
			return err
		}

		// Load the crypto keys from the db.
		cryptoKeyPubEnc, cryptoKeyPrivEnc, cryptoKeyScriptEnc, err =
			fetchCryptoKeys(tx)
		if err != nil {
			return err
		}

		// Load the sync state from the db.
		syncedTo, err = fetchSyncedTo(tx)
		if err != nil {
			return err
		}
		startBlock, err = fetchStartBlock(tx)
		if err != nil {
			return err
		}

		recentHeight, recentHashes, err = fetchRecentBlocks(tx)
		return err
	})
	if err != nil {
		return nil, maybeConvertDbError(err)
	}

	// When not a watching-only manager, set the master private key params,
	// but don't derive it now since the manager starts off locked.
	var masterKeyPriv snacl.SecretKey
	if !watchingOnly {
		err := masterKeyPriv.Unmarshal(masterKeyPrivParams)
		if err != nil {
			str := "failed to unmarshal master private key"
			return nil, managerError(ErrCrypto, str, err)
		}
	}

	// Derive the master public key using the serialized params and provided
	// passphrase.
	var masterKeyPub snacl.SecretKey
	if err := masterKeyPub.Unmarshal(masterKeyPubParams); err != nil {
		str := "failed to unmarshal master public key"
		return nil, managerError(ErrCrypto, str, err)
	}
	if err := masterKeyPub.DeriveKey(&pubPassphrase); err != nil {
		str := "invalid passphrase for master public key"
		return nil, managerError(ErrWrongPassphrase, str, nil)
	}

	// Use the master public key to decrypt the crypto public key.
	cryptoKeyPub := &cryptoKey{snacl.CryptoKey{}}
	cryptoKeyPubCT, err := masterKeyPub.Decrypt(cryptoKeyPubEnc)
	if err != nil {
		str := "failed to decrypt crypto public key"
		return nil, managerError(ErrCrypto, str, err)
	}
	cryptoKeyPub.CopyBytes(cryptoKeyPubCT)
	zero.Bytes(cryptoKeyPubCT)

	// Create the sync state struct.
	syncInfo := newSyncState(startBlock, syncedTo, recentHeight, recentHashes)

	// Generate private passphrase salt.
	var privPassphraseSalt [saltSize]byte
	_, err = rand.Read(privPassphraseSalt[:])
	if err != nil {
		str := "failed to read random source for passphrase salt"
		return nil, managerError(ErrCrypto, str, err)
	}

	// Create new address manager with the given parameters.  Also, override
	// the defaults for the additional fields which are not specified in the
	// call to new with the values loaded from the database.
	mgr := newManager(namespace, chainParams, &masterKeyPub, &masterKeyPriv,
		cryptoKeyPub, cryptoKeyPrivEnc, cryptoKeyScriptEnc, syncInfo,
		privPassphraseSalt)
	mgr.watchingOnly = watchingOnly
	return mgr, nil
}

// Open loads an existing address manager from the given namespace.  The public
// passphrase is required to decrypt the public keys used to protect the public
// information such as addresses.  This is important since access to BIP0032
// extended keys means it is possible to generate all future addresses.
//
// If a config structure is passed to the function, that configuration
// will override the defaults.
//
// A ManagerError with an error code of ErrNoExist will be returned if the
// passed manager does not exist in the specified namespace.
func Open(namespace walletdb.Namespace, pubPassphrase []byte, chainParams *chaincfg.Params, cbs *OpenCallbacks) (*Manager, error) {
	// Return an error if the manager has NOT already been created in the
	// given database namespace.
	exists, err := managerExists(namespace)
	if err != nil {
		return nil, err
	}
	if !exists {
		str := "the specified address manager does not exist"
		return nil, managerError(ErrNoExist, str, nil)
	}

	// Upgrade the manager to the latest version as needed.
	if err := upgradeManager(namespace, pubPassphrase, chainParams, cbs); err != nil {
		return nil, err
	}

	return loadManager(namespace, pubPassphrase, chainParams)
}

// Create creates a new address manager in the given namespace.  The seed must
// conform to the standards described in hdkeychain.NewMaster and will be used
// to create the master root node from which all hierarchical deterministic
// addresses are derived.  This allows all chained addresses in the address
// manager to be recovered by using the same seed.
//
// All private and public keys and information are protected by secret keys
// derived from the provided private and public passphrases.  The public
// passphrase is required on subsequent opens of the address manager, and the
// private passphrase is required to unlock the address manager in order to gain
// access to any private keys and information.
//
// If a config structure is passed to the function, that configuration
// will override the defaults.
//
// A ManagerError with an error code of ErrAlreadyExists will be returned the
// address manager already exists in the specified namespace.
func Create(namespace walletdb.Namespace, seed, pubPassphrase, privPassphrase []byte, chainParams *chaincfg.Params, config *ScryptOptions) error {
	// Return an error if the manager has already been created in the given
	// database namespace.
	exists, err := managerExists(namespace)
	if err != nil {
		return err
	}
	if exists {
		return managerError(ErrAlreadyExists, errAlreadyExists, nil)
	}

	// Ensure the private passphrase is not empty.
	if len(privPassphrase) == 0 {
		str := "private passphrase may not be empty"
		return managerError(ErrEmptyPassphrase, str, nil)
	}

	// Perform the initial bucket creation and database namespace setup.
	if err := createManagerNS(namespace); err != nil {
		return err
	}

	if config == nil {
		config = &DefaultScryptOptions
	}

	// Generate the BIP0044 HD key structure to ensure the provided seed
	// can generate the required structure with no issues.

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
	defer coinTypeKeyPriv.Zero()

	// Derive the account key for the first account according to BIP0044.
	acctKeyPriv, err := deriveAccountKey(coinTypeKeyPriv, 0)
	if err != nil {
		// The seed is unusable if the any of the children in the
		// required hierarchy can't be derived due to invalid child.
		if err == hdkeychain.ErrInvalidChild {
			str := "the provided seed is unusable"
			return managerError(ErrKeyChain, str,
				hdkeychain.ErrUnusableSeed)
		}

		return err
	}

	// Ensure the branch keys can be derived for the provided seed according
	// to BIP0044.
	if err := checkBranchKeys(acctKeyPriv); err != nil {
		// The seed is unusable if the any of the children in the
		// required hierarchy can't be derived due to invalid child.
		if err == hdkeychain.ErrInvalidChild {
			str := "the provided seed is unusable"
			return managerError(ErrKeyChain, str,
				hdkeychain.ErrUnusableSeed)
		}

		return err
	}

	// The address manager needs the public extended key for the account.
	acctKeyPub, err := acctKeyPriv.Neuter()
	if err != nil {
		str := "failed to convert private key for account 0"
		return managerError(ErrKeyChain, str, err)
	}

	// Generate new master keys.  These master keys are used to protect the
	// crypto keys that will be generated next.
	masterKeyPub, err := newSecretKey(&pubPassphrase, config)
	if err != nil {
		str := "failed to master public key"
		return managerError(ErrCrypto, str, err)
	}
	masterKeyPriv, err := newSecretKey(&privPassphrase, config)
	if err != nil {
		str := "failed to master private key"
		return managerError(ErrCrypto, str, err)
	}
	defer masterKeyPriv.Zero()

	// Generate the private  passphrase salt.  This is used when hashing
	// passwords to detect whether an unlock can be avoided when the manager
	// is already unlocked.
	var privPassphraseSalt [saltSize]byte
	_, err = rand.Read(privPassphraseSalt[:])
	if err != nil {
		str := "failed to read random source for passphrase salt"
		return managerError(ErrCrypto, str, err)
	}

	// Generate new crypto public, private, and script keys.  These keys are
	// used to protect the actual public and private data such as addresses,
	// extended keys, and scripts.
	cryptoKeyPub, err := newCryptoKey()
	if err != nil {
		str := "failed to generate crypto public key"
		return managerError(ErrCrypto, str, err)
	}
	cryptoKeyPriv, err := newCryptoKey()
	if err != nil {
		str := "failed to generate crypto private key"
		return managerError(ErrCrypto, str, err)
	}
	defer cryptoKeyPriv.Zero()
	cryptoKeyScript, err := newCryptoKey()
	if err != nil {
		str := "failed to generate crypto script key"
		return managerError(ErrCrypto, str, err)
	}
	defer cryptoKeyScript.Zero()

	// Encrypt the crypto keys with the associated master keys.
	cryptoKeyPubEnc, err := masterKeyPub.Encrypt(cryptoKeyPub.Bytes())
	if err != nil {
		str := "failed to encrypt crypto public key"
		return managerError(ErrCrypto, str, err)
	}
	cryptoKeyPrivEnc, err := masterKeyPriv.Encrypt(cryptoKeyPriv.Bytes())
	if err != nil {
		str := "failed to encrypt crypto private key"
		return managerError(ErrCrypto, str, err)
	}
	cryptoKeyScriptEnc, err := masterKeyPriv.Encrypt(cryptoKeyScript.Bytes())
	if err != nil {
		str := "failed to encrypt crypto script key"
		return managerError(ErrCrypto, str, err)
	}

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

	// Encrypt the default account keys with the associated crypto keys.
	acctPubEnc, err := cryptoKeyPub.Encrypt([]byte(acctKeyPub.String()))
	if err != nil {
		str := "failed to  encrypt public key for account 0"
		return managerError(ErrCrypto, str, err)
	}
	acctPrivEnc, err := cryptoKeyPriv.Encrypt([]byte(acctKeyPriv.String()))
	if err != nil {
		str := "failed to encrypt private key for account 0"
		return managerError(ErrCrypto, str, err)
	}

	// Use the genesis block for the passed chain as the created at block
	// for the default.
	createdAt := &BlockStamp{Hash: *chainParams.GenesisHash, Height: 0}

	// Create the initial sync state.
	recentHashes := []chainhash.Hash{createdAt.Hash}
	recentHeight := createdAt.Height
	syncInfo := newSyncState(createdAt, createdAt, recentHeight, recentHashes)

	// Perform all database updates in a single transaction.
	err = namespace.Update(func(tx walletdb.Tx) error {
		// Save the master key params to the database.
		pubParams := masterKeyPub.Marshal()
		privParams := masterKeyPriv.Marshal()
		err = putMasterKeyParams(tx, pubParams, privParams)
		if err != nil {
			return err
		}

		// Save the encrypted crypto keys to the database.
		err = putCryptoKeys(tx, cryptoKeyPubEnc, cryptoKeyPrivEnc,
			cryptoKeyScriptEnc)
		if err != nil {
			return err
		}

		// Save the encrypted cointype keys to the database.
		err = putCoinTypeKeys(tx, coinTypePubEnc, coinTypePrivEnc)
		if err != nil {
			return err
		}

		// Save the fact this is not a watching-only address manager to
		// the database.
		err = putWatchingOnly(tx, false)
		if err != nil {
			return err
		}

		// Save the initial synced to state.
		err = putSyncedTo(tx, &syncInfo.syncedTo)
		if err != nil {
			return err
		}
		err = putStartBlock(tx, &syncInfo.startBlock)
		if err != nil {
			return err
		}

		// Save the initial recent blocks state.
		err = putRecentBlocks(tx, recentHeight, recentHashes)
		if err != nil {
			return err
		}

		// Save the information for the imported account to the database.
		err = putAccountInfo(tx, ImportedAddrAccount, nil,
			nil, 0, 0, ImportedAddrAccountName)
		if err != nil {
			return err
		}

		// Save the information for the default account to the database.
		err = putAccountInfo(tx, DefaultAccountNum, acctPubEnc,
			acctPrivEnc, 0, 0, defaultAccountName)
		return err
	})
	if err != nil {
		return maybeConvertDbError(err)
	}

	return nil
}
