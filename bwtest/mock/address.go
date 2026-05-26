// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mock

import (
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/mock"
)

// Address is a mock implementation of the btcutil.Address interface.
// It embeds mock.Mock to allow for flexible stubbing of its methods,
// enabling granular control over address behavior in tests.
type Address struct {
	mock.Mock
}

// EncodeAddress mocks the EncodeAddress method.
// It returns a predefined string based on mock expectations.
func (m *Address) EncodeAddress() string {
	args := m.Called()
	return args.String(0)
}

// ScriptAddress mocks the ScriptAddress method.
// It returns a predefined byte slice based on mock expectations.
func (m *Address) ScriptAddress() []byte {
	args := m.Called()
	return args.Get(0).([]byte)
}

// IsForNet mocks the IsForNet method.
// It returns a predefined boolean based on mock expectations.
func (m *Address) IsForNet(params *chaincfg.Params) bool {
	args := m.Called(params)
	return args.Bool(0)
}

// String mocks the String method.
// It returns a predefined string based on mock expectations.
func (m *Address) String() string {
	args := m.Called()
	return args.String(0)
}
