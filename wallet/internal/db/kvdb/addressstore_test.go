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
	"github.com/btcsuite/btcwallet/walletdb"
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

	got, err := store.GetAddress(
		t.Context(), db.GetAddressQuery{
			WalletID:     0,
			ScriptPubKey: info.ScriptPubKey,
		},
	)
	require.NoError(t, err)
	require.Equal(t, info, got)
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

	got, err := store.GetAddress(
		t.Context(), db.GetAddressQuery{
			WalletID:     0,
			ScriptPubKey: pkScript,
		},
	)
	require.NoError(t, err)
	require.True(t, got.IsWatchOnly)
}

// TestGetAddressBareMultisigReturnsNotFound verifies that GetAddress rejects
// scripts that cannot be uniquely identified by their extracted address.
func TestGetAddressBareMultisigReturnsNotFound(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	privKey1, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	privKey2, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKeyBytes := privKey1.PubKey().SerializeCompressed()
	addr, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(pubKeyBytes), addrStore.ChainParams(),
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	pubKeyAddr, err := btcutil.NewAddressPubKey(
		pubKeyBytes, addrStore.ChainParams(),
	)
	require.NoError(t, err)

	_, err = store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:     0,
			Scope:        db.KeyScope(waddrmgr.KeyScopeBIP0044),
			AddressType:  db.PubKeyHash,
			ScriptPubKey: pkScript,
			PubKey:       pubKeyBytes,
		},
	)
	require.NoError(t, err)

	otherPubKeyAddr, err := btcutil.NewAddressPubKey(
		privKey2.PubKey().SerializeCompressed(), addrStore.ChainParams(),
	)
	require.NoError(t, err)

	multisigScript, err := txscript.MultiSigScript(
		[]*btcutil.AddressPubKey{pubKeyAddr, otherPubKeyAddr}, 1,
	)
	require.NoError(t, err)

	_, err = store.GetAddress(t.Context(), db.GetAddressQuery{
		WalletID:     0,
		ScriptPubKey: multisigScript,
	})
	require.ErrorIs(t, err, db.ErrAddressNotFound)
}

// TestAddressStoreImportedPrivateKeyIsSpendable verifies that legacy imported
// private keys are not marked watch-only.
func TestAddressStoreImportedPrivateKeyIsSpendable(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	unlockAddrStore(t, dbConn, addrStore)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	wif, err := btcutil.NewWIF(privKey, addrStore.ChainParams(), false)
	require.NoError(t, err)

	manager, err := addrStore.FetchScopedKeyManager(waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)

	var pkScript []byte

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)

		managedAddr, err := manager.ImportPrivateKey(ns, wif, nil)
		if err != nil {
			return err
		}

		pkScript, err = txscript.PayToAddrScript(managedAddr.Address())

		return err
	})
	require.NoError(t, err)

	got, err := store.GetAddress(
		t.Context(), db.GetAddressQuery{
			WalletID:     0,
			ScriptPubKey: pkScript,
		},
	)
	require.NoError(t, err)
	require.False(t, got.IsWatchOnly)
	require.Len(t, got.PubKey, len(privKey.PubKey().SerializeUncompressed()))
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

	got, err := store.GetAddress(
		t.Context(), db.GetAddressQuery{
			WalletID:     0,
			ScriptPubKey: pkScript,
		},
	)
	require.NoError(t, err)
	require.True(t, got.HasScript)
	require.Equal(t, db.TaprootPubKey, got.AddrType)
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

// unlockAddrStore unlocks the legacy address manager for private-key imports.
func unlockAddrStore(t *testing.T, dbConn walletdb.DB,
	addrStore *waddrmgr.Manager) {

	t.Helper()

	err := walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)

		return addrStore.Unlock(ns, testPrivPass)
	})
	require.NoError(t, err)
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
