// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mock

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/mock"
)

// ManagedPubKeyAddr is a mock implementation of the
// waddrmgr.ManagedPubKeyAddress interface, used for testing.
type ManagedPubKeyAddr struct {
	mock.Mock
}

// A compile-time check to ensure that ManagedPubKeyAddr implements the
// ManagedPubKeyAddress interface.
var _ waddrmgr.ManagedPubKeyAddress = (*ManagedPubKeyAddr)(nil)

// PubKey implements the waddrmgr.ManagedPubKeyAddress interface.
func (m *ManagedPubKeyAddr) PubKey() *btcec.PublicKey {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}

	return args.Get(0).(*btcec.PublicKey)
}

// ExportPrivKey implements the waddrmgr.ManagedPubKeyAddress interface.
func (m *ManagedPubKeyAddr) ExportPrivKey() (*btcutil.WIF, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*btcutil.WIF), args.Error(1)
}

// ExportPubKey implements the waddrmgr.ManagedPubKeyAddress interface.
func (m *ManagedPubKeyAddr) ExportPubKey() string {
	args := m.Called()
	return args.String(0)
}

// PrivKey implements the waddrmgr.ManagedPubKeyAddress interface.
func (m *ManagedPubKeyAddr) PrivKey() (*btcec.PrivateKey, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*btcec.PrivateKey), args.Error(1)
}

// Address implements the waddrmgr.ManagedAddress interface.
func (m *ManagedPubKeyAddr) Address() btcutil.Address {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}

	return args.Get(0).(btcutil.Address)
}

// AddrHash implements the waddrmgr.ManagedAddress interface.
func (m *ManagedPubKeyAddr) AddrHash() []byte {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}

	return args.Get(0).([]byte)
}

// Imported implements the waddrmgr.ManagedAddress interface.
func (m *ManagedPubKeyAddr) Imported() bool {
	args := m.Called()
	return args.Bool(0)
}

// Internal implements the waddrmgr.ManagedAddress interface.
func (m *ManagedPubKeyAddr) Internal() bool {
	args := m.Called()
	return args.Bool(0)
}

// Compressed implements the waddrmgr.ManagedAddress interface.
func (m *ManagedPubKeyAddr) Compressed() bool {
	args := m.Called()
	return args.Bool(0)
}

// Used implements the waddrmgr.ManagedAddress interface.
func (m *ManagedPubKeyAddr) Used(ns walletdb.ReadBucket) bool {
	args := m.Called(ns)
	return args.Bool(0)
}

// AddrType implements the waddrmgr.ManagedAddress interface.
func (m *ManagedPubKeyAddr) AddrType() waddrmgr.AddressType {
	args := m.Called()
	return args.Get(0).(waddrmgr.AddressType)
}

// InternalAccount implements the waddrmgr.ManagedAddress interface.
func (m *ManagedPubKeyAddr) InternalAccount() uint32 {
	args := m.Called()
	return args.Get(0).(uint32)
}

// DerivationInfo implements the waddrmgr.ManagedAddress interface.
func (m *ManagedPubKeyAddr) DerivationInfo() (waddrmgr.KeyScope,
	waddrmgr.DerivationPath, bool) {

	args := m.Called()

	return args.Get(0).(waddrmgr.KeyScope),
		args.Get(1).(waddrmgr.DerivationPath), args.Bool(2)
}
