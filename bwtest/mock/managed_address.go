// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mock

import (
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/mock"
)

// ManagedAddress is a mock implementation of the waddrmgr.ManagedAddress
// interface.
type ManagedAddress struct {
	mock.Mock
}

// A compile-time assertion to ensure that ManagedAddress implements the
// ManagedAddress interface.
var _ waddrmgr.ManagedAddress = (*ManagedAddress)(nil)

// Address implements the waddrmgr.ManagedAddress interface.
func (m *ManagedAddress) Address() address.Address {
	args := m.Called()
	return args.Get(0).(address.Address)
}

// AddrHash implements the waddrmgr.ManagedAddress interface.
func (m *ManagedAddress) AddrHash() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

// Imported implements the waddrmgr.ManagedAddress interface.
func (m *ManagedAddress) Imported() bool {
	args := m.Called()
	return args.Bool(0)
}

// Internal implements the waddrmgr.ManagedAddress interface.
func (m *ManagedAddress) Internal() bool {
	args := m.Called()
	return args.Bool(0)
}

// Compressed implements the waddrmgr.ManagedAddress interface.
func (m *ManagedAddress) Compressed() bool {
	args := m.Called()
	return args.Bool(0)
}

// Used implements the waddrmgr.ManagedAddress interface.
func (m *ManagedAddress) Used(ns walletdb.ReadBucket) bool {
	args := m.Called(ns)
	return args.Bool(0)
}

// AddrType implements the waddrmgr.ManagedAddress interface.
func (m *ManagedAddress) AddrType() waddrmgr.AddressType {
	args := m.Called()
	return args.Get(0).(waddrmgr.AddressType)
}

// InternalAccount implements the waddrmgr.ManagedAddress interface.
func (m *ManagedAddress) InternalAccount() uint32 {
	args := m.Called()
	return args.Get(0).(uint32)
}

// DerivationInfo implements the waddrmgr.ManagedAddress interface.
func (m *ManagedAddress) DerivationInfo() (
	waddrmgr.KeyScope, waddrmgr.DerivationPath, bool) {

	args := m.Called()

	return args.Get(0).(waddrmgr.KeyScope),
		args.Get(1).(waddrmgr.DerivationPath), args.Bool(2)
}
