// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mock

import (
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// ManagedTaprootScriptAddress is a mock implementation of the
// waddrmgr.ManagedTaprootScriptAddress interface.
type ManagedTaprootScriptAddress struct {
	ManagedAddress
}

// A compile-time assertion to ensure that ManagedTaprootScriptAddress
// implements the waddrmgr.ManagedTaprootScriptAddress interface.
var _ waddrmgr.ManagedTaprootScriptAddress = (*ManagedTaprootScriptAddress)(
	nil,
)

// Script implements the waddrmgr.ManagedScriptAddress interface.
func (m *ManagedTaprootScriptAddress) Script() ([]byte, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).([]byte), args.Error(1)
}

// TaprootScript implements the waddrmgr.ManagedTaprootScriptAddress interface.
func (m *ManagedTaprootScriptAddress) TaprootScript() (
	*waddrmgr.Tapscript, error) {

	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*waddrmgr.Tapscript), args.Error(1)
}
