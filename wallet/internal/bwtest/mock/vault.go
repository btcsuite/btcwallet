// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mock

import (
	"context"

	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/mock"
)

// Vault is a testify-based mock for the wallet key-vault interface.
type Vault struct {
	mock.Mock
}

// Encrypt forwards to the configured testify expectations.
func (m *Vault) Encrypt(keyType waddrmgr.CryptoKeyType,
	plaintext []byte) ([]byte, error) {

	args := m.Called(keyType, plaintext)

	return returnBytes(args, keyType, plaintext), args.Error(1)
}

// Decrypt forwards to the configured testify expectations.
func (m *Vault) Decrypt(keyType waddrmgr.CryptoKeyType,
	ciphertext []byte) ([]byte, error) {

	args := m.Called(keyType, ciphertext)

	return returnBytes(args, keyType, ciphertext), args.Error(1)
}

// Unlock forwards to the configured testify expectations.
func (m *Vault) Unlock(ctx context.Context, passphrase []byte) error {
	args := m.Called(ctx, passphrase)
	return args.Error(0)
}

// Lock forwards to the configured testify expectations.
func (m *Vault) Lock() {
	m.Called()
}

// IsLocked forwards to the configured testify expectations.
func (m *Vault) IsLocked() bool {
	args := m.Called()
	return args.Bool(0)
}

// RefreshPrivatePassphrase forwards to the configured testify expectations.
func (m *Vault) RefreshPrivatePassphrase(ctx context.Context,
	passphrase []byte) error {

	args := m.Called(ctx, passphrase)
	return args.Error(0)
}

// returnBytes resolves the first programmed Return arg into a byte slice.
func returnBytes(args mock.Arguments, keyType waddrmgr.CryptoKeyType,
	input []byte) []byte {

	if fn, ok := args.Get(0).(func(waddrmgr.CryptoKeyType, []byte) []byte); ok {
		return fn(keyType, input)
	}

	if args.Get(0) == nil {
		return nil
	}

	b, ok := args.Get(0).([]byte)
	if !ok {
		return nil
	}

	return b
}
