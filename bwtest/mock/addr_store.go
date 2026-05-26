// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mock

import (
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/mock"
)

// AddrStore is a mock implementation of the waddrmgr.AddrStore interface.
type AddrStore struct {
	mock.Mock
}

// Birthday returns the birthday of the address store.
func (m *AddrStore) Birthday() time.Time {
	args := m.Called()
	return args.Get(0).(time.Time)
}

// SetSyncedTo marks the address manager to be in sync with the
// recently-seen block described by the blockstamp.
func (m *AddrStore) SetSyncedTo(ns walletdb.ReadWriteBucket,
	bs *waddrmgr.BlockStamp) error {

	args := m.Called(ns, bs)
	return args.Error(0)
}

// SetBirthdayBlock sets the birthday block, or earliest time a key could
// have been used, for the manager.
func (m *AddrStore) SetBirthdayBlock(ns walletdb.ReadWriteBucket,
	block waddrmgr.BlockStamp, verified bool) error {

	args := m.Called(ns, block, verified)
	return args.Error(0)
}

// SyncedTo returns details about the block height and hash that the
// address manager is synced through at the very least.
func (m *AddrStore) SyncedTo() waddrmgr.BlockStamp {
	args := m.Called()
	return args.Get(0).(waddrmgr.BlockStamp)
}

// BlockHash returns the block hash at a particular block height.
func (m *AddrStore) BlockHash(ns walletdb.ReadBucket,
	height int32) (*chainhash.Hash, error) {

	args := m.Called(ns, height)
	return args.Get(0).(*chainhash.Hash), args.Error(1)
}

// ActiveScopedKeyManagers returns a slice of all the active scoped key
// managers currently known by the root key manager.
func (m *AddrStore) ActiveScopedKeyManagers() []waddrmgr.AccountStore {
	args := m.Called()
	return args.Get(0).([]waddrmgr.AccountStore)
}

// FetchScopedKeyManager attempts to fetch an active scoped manager
// according to its registered scope.
func (m *AddrStore) FetchScopedKeyManager(
	scope waddrmgr.KeyScope) (waddrmgr.AccountStore, error) {

	args := m.Called(scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(waddrmgr.AccountStore), args.Error(1)
}

// Address returns a managed address given the passed address if it is
// known to the address manager.
func (m *AddrStore) Address(ns walletdb.ReadBucket,
	address btcutil.Address) (waddrmgr.ManagedAddress, error) {

	args := m.Called(ns, address)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(waddrmgr.ManagedAddress), args.Error(1)
}

// AddrAccount returns the account to which the given address belongs.
func (m *AddrStore) AddrAccount(ns walletdb.ReadBucket,
	address btcutil.Address) (waddrmgr.AccountStore, uint32, error) {

	args := m.Called(ns, address)

	return args.Get(0).(waddrmgr.AccountStore),
		args.Get(1).(uint32), args.Error(2)
}

// AddressDetails determines whether the wallet has access to the private
// keys required to sign for a given address, and returns other address
// details.
func (m *AddrStore) AddressDetails(ns walletdb.ReadBucket,
	addr btcutil.Address) (bool, string, waddrmgr.AddressType) {

	args := m.Called(ns, addr)
	return args.Bool(0), args.String(1), args.Get(2).(waddrmgr.AddressType)
}

// ForEachRelevantActiveAddress invokes the given closure on each active
// address relevant to the wallet.
func (m *AddrStore) ForEachRelevantActiveAddress(ns walletdb.ReadBucket,
	fn func(addr btcutil.Address) error) error {

	args := m.Called(ns, fn)
	return args.Error(0)
}

// Unlock derives the master private key from the specified passphrase.
func (m *AddrStore) Unlock(ns walletdb.ReadBucket,
	passphrase []byte) error {

	args := m.Called(ns, passphrase)
	return args.Error(0)
}

// Lock performs a best try effort to remove and zero all secret keys
// associated with the address manager.
func (m *AddrStore) Lock() error {
	args := m.Called()
	return args.Error(0)
}

// IsLocked returns whether or not the address managed is locked.
func (m *AddrStore) IsLocked() bool {
	args := m.Called()
	return args.Bool(0)
}

// ChangePassphrase changes either the public or private passphrase to
// the provided value depending on the private flag.
func (m *AddrStore) ChangePassphrase(ns walletdb.ReadWriteBucket,
	oldPass, newPass []byte, private bool,
	scryptOptions *waddrmgr.ScryptOptions) error {

	args := m.Called(ns, oldPass, newPass, private, scryptOptions)
	return args.Error(0)
}

// WatchOnly returns true if the root manager is in watch only mode, and
// false otherwise.
func (m *AddrStore) WatchOnly() bool {
	args := m.Called()
	return args.Bool(0)
}

// MarkUsed updates the used flag for the provided address.
func (m *AddrStore) MarkUsed(ns walletdb.ReadWriteBucket,
	address btcutil.Address) error {

	args := m.Called(ns, address)
	return args.Error(0)
}

// BirthdayBlock returns the birthday block of the address store.
func (m *AddrStore) BirthdayBlock(
	ns walletdb.ReadBucket) (waddrmgr.BlockStamp, bool, error) {

	args := m.Called(ns)
	return args.Get(0).(waddrmgr.BlockStamp), args.Bool(1), args.Error(2)
}

// IsWatchOnlyAccount determines if the account with the given key scope
// is set up as watch-only.
func (m *AddrStore) IsWatchOnlyAccount(ns walletdb.ReadBucket,
	keyScope waddrmgr.KeyScope, account uint32) (bool, error) {

	args := m.Called(ns, keyScope, account)
	return args.Bool(0), args.Error(1)
}

// NewScopedKeyManager creates a new scoped key manager from the root
// manager.
func (m *AddrStore) NewScopedKeyManager(ns walletdb.ReadWriteBucket,
	scope waddrmgr.KeyScope,
	addrSchema waddrmgr.ScopeAddrSchema) (waddrmgr.AccountStore, error) {

	args := m.Called(ns, scope, addrSchema)
	return args.Get(0).(waddrmgr.AccountStore), args.Error(1)
}

// SetBirthday sets the birthday of the address store.
func (m *AddrStore) SetBirthday(ns walletdb.ReadWriteBucket,
	birthday time.Time) error {

	args := m.Called(ns, birthday)
	return args.Error(0)
}

// ForEachAccountAddress calls the given function with each address of
// the given account stored in the manager, breaking early on error.
func (m *AddrStore) ForEachAccountAddress(ns walletdb.ReadBucket,
	account uint32, fn func(maddr waddrmgr.ManagedAddress) error) error {

	args := m.Called(ns, account, fn)
	return args.Error(0)
}

// LookupAccount returns the corresponding key scope and account number
// for the account with the given name.
func (m *AddrStore) LookupAccount(ns walletdb.ReadBucket,
	name string) (waddrmgr.KeyScope, uint32, error) {

	args := m.Called(ns, name)

	return args.Get(0).(waddrmgr.KeyScope),
		args.Get(1).(uint32), args.Error(2)
}

// ForEachActiveAddress calls the given function with each active address
// stored in the manager, breaking early on error.
func (m *AddrStore) ForEachActiveAddress(ns walletdb.ReadBucket,
	fn func(addr btcutil.Address) error) error {

	args := m.Called(ns, fn)
	return args.Error(0)
}

// ConvertToWatchingOnly converts the current address manager to a locked
// watching-only address manager.
func (m *AddrStore) ConvertToWatchingOnly(
	ns walletdb.ReadWriteBucket) error {

	args := m.Called(ns)
	return args.Error(0)
}

// ChainParams returns the chain parameters for this address manager.
func (m *AddrStore) ChainParams() *chaincfg.Params {
	args := m.Called()
	return args.Get(0).(*chaincfg.Params)
}

// Close cleanly shuts down the manager.
func (m *AddrStore) Close() {
	m.Called()
}

// EncryptedMasterHDPriv implements the waddrmgr.AddrStore interface.
func (m *AddrStore) EncryptedMasterHDPriv(
	ns walletdb.ReadBucket) ([]byte, error) {

	args := m.Called(ns)
	if raw, ok := args.Get(0).([]byte); ok {
		return raw, args.Error(1)
	}

	return nil, args.Error(1)
}

// Encrypt implements keyvault.Vault.
func (m *AddrStore) Encrypt(keyType waddrmgr.CryptoKeyType,
	plaintext []byte) ([]byte, error) {

	args := m.Called(keyType, plaintext)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]byte), args.Error(1)
}

// Decrypt implements keyvault.Vault.
func (m *AddrStore) Decrypt(keyType waddrmgr.CryptoKeyType,
	ciphertext []byte) ([]byte, error) {

	args := m.Called(keyType, ciphertext)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]byte), args.Error(1)
}
