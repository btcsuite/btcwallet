// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mock

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/mock"
)

// AccountStore is a mock implementation of the waddrmgr.AccountStore
// interface.
type AccountStore struct {
	mock.Mock
}

// A compile-time assertion to ensure that AccountStore implements the
// AccountStore interface.
var _ waddrmgr.AccountStore = (*AccountStore)(nil)

// Scope implements the waddrmgr.AccountStore interface.
func (m *AccountStore) Scope() waddrmgr.KeyScope {
	args := m.Called()
	return args.Get(0).(waddrmgr.KeyScope)
}

// AccountProperties implements the waddrmgr.AccountStore interface.
func (m *AccountStore) AccountProperties(ns walletdb.ReadBucket,
	account uint32) (*waddrmgr.AccountProperties, error) {

	args := m.Called(ns, account)
	return args.Get(0).(*waddrmgr.AccountProperties), args.Error(1)
}

// LastExternalAddress implements the waddrmgr.AccountStore interface.
func (m *AccountStore) LastExternalAddress(ns walletdb.ReadBucket,
	account uint32) (waddrmgr.ManagedAddress, error) {

	args := m.Called(ns, account)
	return args.Get(0).(waddrmgr.ManagedAddress), args.Error(1)
}

// LastInternalAddress implements the waddrmgr.AccountStore interface.
func (m *AccountStore) LastInternalAddress(ns walletdb.ReadBucket,
	account uint32) (waddrmgr.ManagedAddress, error) {

	args := m.Called(ns, account)
	return args.Get(0).(waddrmgr.ManagedAddress), args.Error(1)
}

// ForEachAccountAddress implements the waddrmgr.AccountStore interface.
func (m *AccountStore) ForEachAccountAddress(ns walletdb.ReadBucket,
	account uint32, fn func(maddr waddrmgr.ManagedAddress) error) error {

	args := m.Called(ns, account, fn)
	return args.Error(0)
}

// LookupAccount implements the waddrmgr.AccountStore interface.
func (m *AccountStore) LookupAccount(ns walletdb.ReadBucket,
	name string) (uint32, error) {

	args := m.Called(ns, name)
	return args.Get(0).(uint32), args.Error(1)
}

// AccountName implements the waddrmgr.AccountStore interface.
func (m *AccountStore) AccountName(ns walletdb.ReadBucket,
	account uint32) (string, error) {

	args := m.Called(ns, account)
	return args.String(0), args.Error(1)
}

// ExtendExternalAddresses implements the waddrmgr.AccountStore interface.
func (m *AccountStore) ExtendExternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, count uint32) error {

	args := m.Called(ns, account, count)
	return args.Error(0)
}

// ExtendInternalAddresses implements the waddrmgr.AccountStore interface.
func (m *AccountStore) ExtendInternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, count uint32) error {

	args := m.Called(ns, account, count)
	return args.Error(0)
}

// MarkUsed implements the waddrmgr.AccountStore interface.
func (m *AccountStore) MarkUsed(ns walletdb.ReadWriteBucket,
	address btcutil.Address) error {

	args := m.Called(ns, address)
	return args.Error(0)
}

// DeriveFromKeyPath implements the waddrmgr.AccountStore interface.
func (m *AccountStore) DeriveFromKeyPath(ns walletdb.ReadBucket,
	path waddrmgr.DerivationPath) (waddrmgr.ManagedAddress, error) {

	args := m.Called(ns, path)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(waddrmgr.ManagedAddress), args.Error(1)
}

// CanAddAccountDeprecated implements the waddrmgr.AccountStore interface.
func (m *AccountStore) CanAddAccountDeprecated() error {
	args := m.Called()
	return args.Error(0)
}

// NewAccount implements the waddrmgr.AccountStore interface.
func (m *AccountStore) NewAccount(ns walletdb.ReadWriteBucket,
	name string) (uint32, error) {

	args := m.Called(ns, name)
	return args.Get(0).(uint32), args.Error(1)
}

// AllocateDerivedAccountNumber implements waddrmgr.AccountStore.
func (m *AccountStore) AllocateDerivedAccountNumber(
	ns walletdb.ReadWriteBucket) (uint32, error) {

	args := m.Called(ns)
	return args.Get(0).(uint32), args.Error(1)
}

// PutDerivedAccountWithKeys implements waddrmgr.AccountStore.
func (m *AccountStore) PutDerivedAccountWithKeys(
	ns walletdb.ReadWriteBucket, account uint32, name string,
	plaintextPubKey []byte, encryptedPrivKey []byte) error {

	args := m.Called(
		ns, account, name, plaintextPubKey, encryptedPrivKey,
	)

	return args.Error(0)
}

// AllocateImportedAccountNumber implements waddrmgr.AccountStore.
func (m *AccountStore) AllocateImportedAccountNumber(
	ns walletdb.ReadWriteBucket) (uint32, error) {

	args := m.Called(ns)
	return args.Get(0).(uint32), args.Error(1)
}

// PutWatchOnlyAccountWithKeys implements waddrmgr.AccountStore.
func (m *AccountStore) PutWatchOnlyAccountWithKeys(
	ns walletdb.ReadWriteBucket, account uint32, name string,
	pubKey *hdkeychain.ExtendedKey, masterKeyFingerprint uint32,
	addrSchema *waddrmgr.ScopeAddrSchema) error {

	args := m.Called(
		ns, account, name, pubKey, masterKeyFingerprint, addrSchema,
	)

	return args.Error(0)
}

// LastAccount implements the waddrmgr.AccountStore interface.
func (m *AccountStore) LastAccount(ns walletdb.ReadBucket) (uint32, error) {
	args := m.Called(ns)
	return args.Get(0).(uint32), args.Error(1)
}

// RenameAccount implements the waddrmgr.AccountStore interface.
func (m *AccountStore) RenameAccount(ns walletdb.ReadWriteBucket,
	account uint32, name string) error {

	args := m.Called(ns, account, name)
	return args.Error(0)
}

// NextExternalAddresses implements the waddrmgr.AccountStore interface.
func (m *AccountStore) NextExternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, count uint32) ([]waddrmgr.ManagedAddress, error) {

	args := m.Called(ns, account, count)
	return args.Get(0).([]waddrmgr.ManagedAddress), args.Error(1)
}

// NextInternalAddresses implements the waddrmgr.AccountStore interface.
func (m *AccountStore) NextInternalAddresses(ns walletdb.ReadWriteBucket,
	account uint32, count uint32) ([]waddrmgr.ManagedAddress, error) {

	args := m.Called(ns, account, count)
	return args.Get(0).([]waddrmgr.ManagedAddress), args.Error(1)
}

// NewAddress implements the waddrmgr.AccountStore interface.
func (m *AccountStore) NewAddress(ns walletdb.ReadWriteBucket,
	account string, internal bool) (btcutil.Address, error) {

	args := m.Called(ns, account, internal)
	return args.Get(0).(btcutil.Address), args.Error(1)
}

// ImportPublicKey implements the waddrmgr.AccountStore interface.
func (m *AccountStore) ImportPublicKey(ns walletdb.ReadWriteBucket,
	pubKey *btcec.PublicKey,
	bs *waddrmgr.BlockStamp) (waddrmgr.ManagedAddress, error) {

	args := m.Called(ns, pubKey, bs)
	return args.Get(0).(waddrmgr.ManagedAddress), args.Error(1)
}

// ImportTaprootScript implements the waddrmgr.AccountStore interface.
func (m *AccountStore) ImportTaprootScript(ns walletdb.ReadWriteBucket,
	script *waddrmgr.Tapscript, bs *waddrmgr.BlockStamp, privKeyType byte,
	isInternal bool) (waddrmgr.ManagedTaprootScriptAddress, error) {

	args := m.Called(ns, script, bs, privKeyType, isInternal)
	return args.Get(0).(waddrmgr.ManagedTaprootScriptAddress), args.Error(1)
}

// ForEachAccount implements the waddrmgr.AccountStore interface.
func (m *AccountStore) ForEachAccount(ns walletdb.ReadBucket,
	fn func(account uint32) error) error {

	args := m.Called(ns, fn)
	return args.Error(0)
}

// IsWatchOnlyAccount implements the waddrmgr.AccountStore interface.
func (m *AccountStore) IsWatchOnlyAccount(ns walletdb.ReadBucket,
	account uint32) (bool, error) {

	args := m.Called(ns, account)
	return args.Bool(0), args.Error(1)
}

// IsImportedAccount implements the waddrmgr.AccountStore interface.
func (m *AccountStore) IsImportedAccount(ns walletdb.ReadBucket,
	account uint32) (bool, error) {

	args := m.Called(ns, account)
	return args.Bool(0), args.Error(1)
}

// NewAccountWatchingOnly implements the waddrmgr.AccountStore interface.
func (m *AccountStore) NewAccountWatchingOnly(ns walletdb.ReadWriteBucket,
	name string, pubKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32,
	addrSchema *waddrmgr.ScopeAddrSchema) (uint32, error) {

	args := m.Called(ns, name, pubKey, masterKeyFingerprint, addrSchema)
	return args.Get(0).(uint32), args.Error(1)
}

// InvalidateAccountCache implements the waddrmgr.AccountStore interface.
func (m *AccountStore) InvalidateAccountCache(account uint32) {
	m.Called(account)
}

// ImportPrivateKey implements the waddrmgr.AccountStore interface.
func (m *AccountStore) ImportPrivateKey(ns walletdb.ReadWriteBucket,
	wif *btcutil.WIF,
	bs *waddrmgr.BlockStamp) (waddrmgr.ManagedPubKeyAddress, error) {

	args := m.Called(ns, wif, bs)
	return args.Get(0).(waddrmgr.ManagedPubKeyAddress), args.Error(1)
}

// ActiveAccounts implements the waddrmgr.AccountStore interface.
func (m *AccountStore) ActiveAccounts() []uint32 {
	args := m.Called()
	return args.Get(0).([]uint32)
}

// ExtendAddresses implements the waddrmgr.AccountStore interface.
func (m *AccountStore) ExtendAddresses(ns walletdb.ReadWriteBucket,
	account uint32, lastIndex uint32, branch uint32) error {

	args := m.Called(ns, account, lastIndex, branch)
	return args.Error(0)
}

// DeriveAddr implements the waddrmgr.AccountStore interface.
func (m *AccountStore) DeriveAddr(account, branch, index uint32) (
	btcutil.Address, []byte, error) {

	args := m.Called(account, branch, index)

	var addr btcutil.Address
	if args.Get(0) != nil {
		addr = args.Get(0).(btcutil.Address)
	}

	var script []byte
	if args.Get(1) != nil {
		script = args.Get(1).([]byte)
	}

	return addr, script, args.Error(2)
}

// AddrAccount implements the waddrmgr.AccountStore interface.
func (m *AccountStore) AddrAccount(ns walletdb.ReadBucket,
	address btcutil.Address) (uint32, error) {

	args := m.Called(ns, address)
	return args.Get(0).(uint32), args.Error(1)
}

// DeriveFromKeyPathCache implements the waddrmgr.AccountStore interface.
func (m *AccountStore) DeriveFromKeyPathCache(
	kp waddrmgr.DerivationPath) (*btcec.PrivateKey, error) {

	args := m.Called(kp)
	return args.Get(0).(*btcec.PrivateKey), args.Error(1)
}

// NewRawAccount implements the waddrmgr.AccountStore interface.
func (m *AccountStore) NewRawAccount(ns walletdb.ReadWriteBucket,
	number uint32) error {

	args := m.Called(ns, number)
	return args.Error(0)
}

// NewRawAccountWatchingOnly implements the waddrmgr.AccountStore interface.
func (m *AccountStore) NewRawAccountWatchingOnly(
	ns walletdb.ReadWriteBucket,
	number uint32, pubKey *hdkeychain.ExtendedKey,
	masterKeyFingerprint uint32,
	addrSchema *waddrmgr.ScopeAddrSchema) error {

	args := m.Called(ns, number, pubKey, masterKeyFingerprint, addrSchema)
	return args.Error(0)
}

// ImportScript implements the waddrmgr.AccountStore interface.
func (m *AccountStore) ImportScript(
	ns walletdb.ReadWriteBucket, script []byte,
	bs *waddrmgr.BlockStamp) (waddrmgr.ManagedScriptAddress, error) {

	args := m.Called(ns, script, bs)
	return args.Get(0).(waddrmgr.ManagedScriptAddress), args.Error(1)
}

// ImportWitnessScript implements the waddrmgr.AccountStore interface.
func (m *AccountStore) ImportWitnessScript(ns walletdb.ReadWriteBucket,
	script []byte, bs *waddrmgr.BlockStamp, witnessVersion byte,
	isSecretScript bool) (waddrmgr.ManagedScriptAddress, error) {

	args := m.Called(ns, script, bs, witnessVersion, isSecretScript)
	if v := args.Get(0); v != nil {
		return v.(waddrmgr.ManagedScriptAddress), args.Error(1)
	}

	return nil, args.Error(1)
}
