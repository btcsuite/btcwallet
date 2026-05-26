// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mock

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/mock"
)

// UnsupportedManagedPubKeyAddr is a mock.Mock-based test double for
// waddrmgr.ManagedPubKeyAddress implementations whose concrete type is not
// supported by wallet metadata adapters.
type UnsupportedManagedPubKeyAddr struct {
	mock.Mock
	waddrmgr.ManagedAddress
}

// Imported reports whether the managed pubkey address is imported.
func (m *UnsupportedManagedPubKeyAddr) Imported() bool {
	args := m.Called()
	return args.Bool(0)
}

// PubKey returns the public key associated with the managed pubkey address.
func (m *UnsupportedManagedPubKeyAddr) PubKey() *btcec.PublicKey {
	args := m.Called()

	pubKey, _ := args.Get(0).(*btcec.PublicKey)

	return pubKey
}

// ExportPubKey returns the hex-encoded public key.
func (m *UnsupportedManagedPubKeyAddr) ExportPubKey() string {
	args := m.Called()
	return args.String(0)
}

// PrivKey returns the private key associated with the managed pubkey address.
func (m *UnsupportedManagedPubKeyAddr) PrivKey() (*btcec.PrivateKey, error) {
	args := m.Called()

	privKey, _ := args.Get(0).(*btcec.PrivateKey)

	return privKey, args.Error(1)
}

// ExportPrivKey returns the wallet import format encoding of the private key.
func (m *UnsupportedManagedPubKeyAddr) ExportPrivKey() (*btcutil.WIF,
	error) {

	args := m.Called()

	wif, _ := args.Get(0).(*btcutil.WIF)

	return wif, args.Error(1)
}

// DerivationInfo returns the BIP-32 derivation path for the managed pubkey
// address.
func (m *UnsupportedManagedPubKeyAddr) DerivationInfo() (waddrmgr.KeyScope,
	waddrmgr.DerivationPath, bool) {

	args := m.Called()

	scope, _ := args.Get(0).(waddrmgr.KeyScope)
	path, _ := args.Get(1).(waddrmgr.DerivationPath)

	return scope, path, args.Bool(2)
}
