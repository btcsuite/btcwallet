// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package kvdb

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestAddressStoreNewDerivedAddress verifies that kvdb.Store creates derived
// addresses through the legacy address manager.
func TestAddressStoreNewDerivedAddress(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)
	props := createLegacyAccount(
		t, dbConn, addrStore, waddrmgr.KeyScopeBIP0084, "addr",
	)

	info, err := store.NewDerivedAddress(
		t.Context(), db.NewDerivedAddressParams{
			WalletID:    0,
			AccountName: "addr",
			Scope:       db.KeyScope(waddrmgr.KeyScopeBIP0084),
		},
	)
	require.NoError(t, err)
	require.Equal(t, uint32(1), info.ID)
	require.Equal(t, db.DerivedAccount, info.Origin)
	require.Equal(t, db.WitnessPubKey, info.AddrType)
	require.Equal(t, "addr", info.AccountName)
	require.Equal(t, props.AccountNumber, info.AccountID)
	require.NotEmpty(t, info.ScriptPubKey)
	require.NotEmpty(t, info.PubKey)
}

// TestManagedAddressIsWatchOnlyUnsupportedPubKey verifies that unsupported
// managed public-key address implementations are reported explicitly.
func TestManagedAddressIsWatchOnlyUnsupportedPubKey(t *testing.T) {
	t.Parallel()

	m := &unsupportedManagedPubKeyAddress{}
	m.On("Imported").Return(true).Once()

	isWatchOnly, err := managedAddressIsWatchOnly(false, m)
	require.ErrorContains(t, err, "unsupported managed pubkey address")
	require.False(t, isWatchOnly)
	m.AssertExpectations(t)
}

// unsupportedManagedPubKeyAddress is a mock.Mock-based test double for
// waddrmgr.ManagedPubKeyAddress used to exercise the unsupported pubkey path
// in managedAddressIsWatchOnly.
//
// The embedded waddrmgr.ManagedAddress satisfies the base interface so the
// type assertion to waddrmgr.ManagedPubKeyAddress succeeds; the mock.Mock
// shim methods then drive the behavior the test exercises.
type unsupportedManagedPubKeyAddress struct {
	mock.Mock
	waddrmgr.ManagedAddress
}

// Imported reports whether the managed pubkey address is imported.
func (m *unsupportedManagedPubKeyAddress) Imported() bool {
	args := m.Called()
	return args.Bool(0)
}

// PubKey returns the public key associated with the managed pubkey address.
func (m *unsupportedManagedPubKeyAddress) PubKey() *btcec.PublicKey {
	args := m.Called()

	pubKey, _ := args.Get(0).(*btcec.PublicKey)

	return pubKey
}

// ExportPubKey returns the hex-encoded public key.
func (m *unsupportedManagedPubKeyAddress) ExportPubKey() string {
	args := m.Called()
	return args.String(0)
}

// PrivKey returns the private key associated with the managed pubkey address.
func (m *unsupportedManagedPubKeyAddress) PrivKey() (*btcec.PrivateKey, error) {
	args := m.Called()

	privKey, _ := args.Get(0).(*btcec.PrivateKey)

	return privKey, args.Error(1)
}

// ExportPrivKey returns the wallet import format encoding of the private key.
func (m *unsupportedManagedPubKeyAddress) ExportPrivKey() (*btcutil.WIF,
	error) {

	args := m.Called()

	wif, _ := args.Get(0).(*btcutil.WIF)

	return wif, args.Error(1)
}

// DerivationInfo returns the BIP-32 derivation path for the managed pubkey
// address.
func (m *unsupportedManagedPubKeyAddress) DerivationInfo() (waddrmgr.KeyScope,
	waddrmgr.DerivationPath, bool) {

	args := m.Called()

	scope, _ := args.Get(0).(waddrmgr.KeyScope)
	path, _ := args.Get(1).(waddrmgr.DerivationPath)

	return scope, path, args.Bool(2)
}
