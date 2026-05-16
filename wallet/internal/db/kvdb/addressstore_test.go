// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package kvdb

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
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

// TestAddressStoreImportedPublicKeyIsWatchOnly verifies that imported public
// keys are marked watch-only instead of relying only on imported origin.
func TestAddressStoreImportedPublicKeyIsWatchOnly(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	pubKeyBytes := pubKey.SerializeCompressed()
	addr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKeyBytes), addrStore.ChainParams(),
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	info, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:     0,
			Scope:        db.KeyScope(waddrmgr.KeyScopeBIP0084),
			AddressType:  db.WitnessPubKey,
			ScriptPubKey: pkScript,
			PubKey:       pubKeyBytes,
		},
	)
	require.NoError(t, err)
	require.Equal(t, db.ImportedAccount, info.Origin)
	require.Equal(t, db.WitnessPubKey, info.AddrType)
	require.Equal(t, pkScript, info.ScriptPubKey)
	require.Equal(t, pubKeyBytes, info.PubKey)
	require.True(t, info.IsWatchOnly)
}

// TestAddressStoreImportedPublicKeyRejectsMismatch verifies that kvdb rejects
// imported public-key requests when legacy import output does not match the
// requested type or script.
func TestAddressStoreImportedPublicKeyRejectsMismatch(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		addrType   db.AddressType
		scriptFunc func(*testing.T, []byte, *waddrmgr.Manager) []byte
	}{
		{
			name:     "type mismatch",
			addrType: db.PubKeyHash,
			scriptFunc: func(t *testing.T, script []byte,
				_ *waddrmgr.Manager) []byte {

				t.Helper()

				return script
			},
		},
		{
			name:     "script mismatch",
			addrType: db.WitnessPubKey,
			scriptFunc: func(t *testing.T, _ []byte,
				addrStore *waddrmgr.Manager) []byte {

				t.Helper()

				otherPrivKey, err := btcec.NewPrivateKey()
				require.NoError(t, err)

				otherPubKey := otherPrivKey.PubKey().SerializeCompressed()
				otherAddr, err := btcutil.NewAddressWitnessPubKeyHash(
					btcutil.Hash160(otherPubKey),
					addrStore.ChainParams(),
				)
				require.NoError(t, err)

				otherScript, err := txscript.PayToAddrScript(
					otherAddr,
				)
				require.NoError(t, err)

				return otherScript
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dbConn, cleanup := newTestDB(t)
			t.Cleanup(cleanup)

			addrStore := newSpendableAddrMgr(t, dbConn)
			store := NewStore(dbConn, nil, addrStore)

			privKey, err := btcec.NewPrivateKey()
			require.NoError(t, err)

			pubKeyBytes := privKey.PubKey().SerializeCompressed()
			addr, err := btcutil.NewAddressWitnessPubKeyHash(
				btcutil.Hash160(pubKeyBytes), addrStore.ChainParams(),
			)
			require.NoError(t, err)

			actualScript, err := txscript.PayToAddrScript(addr)
			require.NoError(t, err)

			_, err = store.NewImportedAddress(
				t.Context(), db.NewImportedAddressParams{
					WalletID: 0,
					Scope: db.KeyScope(
						waddrmgr.KeyScopeBIP0084,
					),
					AddressType: tc.addrType,
					ScriptPubKey: tc.scriptFunc(
						t, actualScript, addrStore,
					),
					PubKey: pubKeyBytes,
				},
			)
			require.ErrorIs(t, err, errImportedAddressMismatch)
		})
	}
}

// TestAddressStoreImportTaprootScript verifies that kvdb.Store imports taproot
// script metadata through the legacy address manager while preserving the store
// level script marker.
func TestAddressStoreImportTaprootScript(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	tapscript, pkScript := testTaprootScript(t, addrStore)
	encodedScript, err := waddrmgr.EncodeTaprootScript(&tapscript)
	require.NoError(t, err)
	encryptedScript, err := addrStore.Encrypt(
		waddrmgr.CKTPublic, encodedScript,
	)
	require.NoError(t, err)

	info, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:        0,
			Scope:           db.KeyScope(waddrmgr.KeyScopeBIP0086),
			AddressType:     db.TaprootPubKey,
			ScriptPubKey:    pkScript,
			EncryptedScript: encryptedScript,
		},
	)
	require.NoError(t, err)
	require.Equal(t, db.ImportedAccount, info.Origin)
	require.Equal(t, db.TaprootPubKey, info.AddrType)
	require.True(t, info.HasScript)
	require.Equal(t, pkScript, info.ScriptPubKey)
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

// testTaprootScript returns a tapscript and its P2TR output script.
func testTaprootScript(t *testing.T,
	addrStore *waddrmgr.Manager) (waddrmgr.Tapscript, []byte) {

	t.Helper()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()
	script, err := txscript.NewScriptBuilder().
		AddData(pubKey.SerializeCompressed()).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)

	leaf := txscript.NewTapLeaf(txscript.BaseLeafVersion, script)
	tree := txscript.AssembleTaprootScriptTree(leaf)
	rootHash := tree.RootNode.TapHash()
	taprootKey := txscript.ComputeTaprootOutputKey(pubKey, rootHash[:])
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(taprootKey), addrStore.ChainParams(),
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	return waddrmgr.Tapscript{
		Type: waddrmgr.TapscriptTypeFullTree,
		ControlBlock: &txscript.ControlBlock{
			InternalKey: pubKey,
		},
		Leaves: []txscript.TapLeaf{leaf},
	}, pkScript
}
