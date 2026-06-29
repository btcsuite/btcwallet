// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package kvdb

import (
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	bwmock "github.com/btcsuite/btcwallet/bwtest/mock"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/btcsuite/btcwallet/walletdb"
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
	require.Nil(t, info.AccountID)
	require.NotNil(t, info.AccountNumber)
	require.Equal(t, props.AccountNumber, *info.AccountNumber)
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

	pageReq, err := page.NewRequest[uint32](10)
	require.NoError(t, err)
	accountName := "addr"
	scope := db.KeyScope(waddrmgr.KeyScopeBIP0084)
	result, err := store.ListAddresses(
		t.Context(), db.ListAddressesQuery{
			WalletID:    0,
			AccountName: &accountName,
			Scope:       &scope,
			Page:        pageReq,
		},
	)
	require.NoError(t, err)
	require.Len(t, result.Items, 1)
	require.Equal(t, *info, result.Items[0])
}

// TestAddressStoreNewDerivedAddressWatchOnlyWallet verifies that derived
// address metadata inherits wallet-level watch-only mode.
func TestAddressStoreNewDerivedAddressWatchOnlyWallet(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)
	createLegacyAccount(
		t, dbConn, addrStore, waddrmgr.KeyScopeBIP0084, "watch",
	)
	convertAddrStoreToWatchOnly(t, dbConn, addrStore)

	info, err := store.NewDerivedAddress(
		t.Context(), db.NewDerivedAddressParams{
			WalletID:    0,
			AccountName: "watch",
			Scope:       db.KeyScope(waddrmgr.KeyScopeBIP0084),
		},
	)
	require.NoError(t, err)
	require.True(t, info.IsWatchOnly)

	got, err := store.GetAddress(
		t.Context(), db.GetAddressQuery{
			WalletID:     0,
			ScriptPubKey: info.ScriptPubKey,
		},
	)
	require.NoError(t, err)
	require.True(t, got.IsWatchOnly)

	pageReq, err := page.NewRequest[uint32](10)
	require.NoError(t, err)
	accountName := "watch"
	scope := db.KeyScope(waddrmgr.KeyScopeBIP0084)
	result, err := store.ListAddresses(
		t.Context(), db.ListAddressesQuery{
			WalletID:    0,
			AccountName: &accountName,
			Scope:       &scope,
			Page:        pageReq,
		},
	)
	require.NoError(t, err)
	require.Len(t, result.Items, 1)
	require.True(t, result.Items[0].IsWatchOnly)
}

// TestAddressStoreListAddressesPagination verifies that kvdb pagination uses
// collision-free synthetic IDs and does not skip or repeat addresses.
func TestAddressStoreListAddressesPagination(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)
	createLegacyAccount(
		t, dbConn, addrStore, waddrmgr.KeyScopeBIP0084, "page",
	)

	for range 5 {
		_, err := store.NewDerivedAddress(
			t.Context(), db.NewDerivedAddressParams{
				WalletID:    0,
				AccountName: "page",
				Scope:       db.KeyScope(waddrmgr.KeyScopeBIP0084),
			},
		)
		require.NoError(t, err)
	}

	pageReq, err := page.NewRequest[uint32](2)
	require.NoError(t, err)
	accountName := "page"
	scope := db.KeyScope(waddrmgr.KeyScopeBIP0084)

	query := db.ListAddressesQuery{
		WalletID:    0,
		AccountName: &accountName,
		Scope:       &scope,
		Page:        pageReq,
	}

	var addresses []db.AddressInfo
	for {
		result, err := store.ListAddresses(t.Context(), query)
		require.NoError(t, err)

		addresses = append(addresses, result.Items...)
		if result.Next == nil {
			break
		}

		query.Page.After = result.Next
	}

	require.Len(t, addresses, 5)

	for i := range addresses {
		require.Equal(t, uint32(i+1), addresses[i].ID)
	}
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
	addr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(pubKeyBytes), addrStore.ChainParams(),
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
	addr, err := address.NewAddressPubKeyHash(
		address.Hash160(pubKeyBytes), addrStore.ChainParams(),
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	pubKeyAddr, err := address.NewAddressPubKey(
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

	otherPubKeyAddr, err := address.NewAddressPubKey(
		privKey2.PubKey().SerializeCompressed(), addrStore.ChainParams(),
	)
	require.NoError(t, err)

	multisigScript, err := txscript.MultiSigScript(
		[]*address.AddressPubKey{pubKeyAddr, otherPubKeyAddr}, 1,
	)
	require.NoError(t, err)

	_, err = store.GetAddress(t.Context(), db.GetAddressQuery{
		WalletID:     0,
		ScriptPubKey: multisigScript,
	})
	require.ErrorIs(t, err, db.ErrAddressNotFound)
}

// TestAddressStoreResolveOwnedAddresses verifies that the batched resolver
// returns only the wallet-owned subset of a mixed script set in a single
// transaction, omits scripts that are not owned, and treats an empty input as
// an empty result without error.
func TestAddressStoreResolveOwnedAddresses(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	// importP2WKH imports a fresh P2WKH address and returns its script.
	importP2WKH := func(t *testing.T) []byte {
		t.Helper()

		privKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		addr, err := address.NewAddressWitnessPubKeyHash(
			address.Hash160(privKey.PubKey().SerializeCompressed()),
			addrStore.ChainParams(),
		)
		require.NoError(t, err)

		script, err := txscript.PayToAddrScript(addr)
		require.NoError(t, err)

		_, err = store.NewImportedAddress(
			t.Context(), db.NewImportedAddressParams{
				WalletID:     0,
				Scope:        db.KeyScope(waddrmgr.KeyScopeBIP0084),
				AddressType:  db.WitnessPubKey,
				ScriptPubKey: script,
				PubKey: privKey.PubKey().
					SerializeCompressed(),
			},
		)
		require.NoError(t, err)

		return script
	}

	owned1 := importP2WKH(t)
	owned2 := importP2WKH(t)

	// A valid P2WKH script for a key the wallet never imported.
	foreignKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	foreignAddr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(foreignKey.PubKey().SerializeCompressed()),
		addrStore.ChainParams(),
	)
	require.NoError(t, err)
	foreignScript, err := txscript.PayToAddrScript(foreignAddr)
	require.NoError(t, err)

	t.Run("mixed owned and foreign", func(t *testing.T) {
		t.Parallel()

		owned, err := store.ResolveOwnedAddresses(
			t.Context(), db.ResolveOwnedAddressesQuery{
				WalletID: 0,
				ScriptPubKeys: [][]byte{
					owned1, foreignScript, owned2,
				},
			},
		)
		require.NoError(t, err)

		require.Len(t, owned, 2)
		require.Contains(t, owned, string(owned1))
		require.Contains(t, owned, string(owned2))
		require.NotContains(t, owned, string(foreignScript))
	})

	t.Run("duplicate scripts resolve once", func(t *testing.T) {
		t.Parallel()

		owned, err := store.ResolveOwnedAddresses(
			t.Context(), db.ResolveOwnedAddressesQuery{
				WalletID:      0,
				ScriptPubKeys: [][]byte{owned1, owned1},
			},
		)
		require.NoError(t, err)
		require.Len(t, owned, 1)
		require.Contains(t, owned, string(owned1))
	})

	t.Run("empty input", func(t *testing.T) {
		t.Parallel()

		owned, err := store.ResolveOwnedAddresses(
			t.Context(), db.ResolveOwnedAddressesQuery{WalletID: 0},
		)
		require.NoError(t, err)
		require.NotNil(t, owned)
		require.Empty(t, owned)
	})
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
				otherAddr, err := address.NewAddressWitnessPubKeyHash(
					address.Hash160(otherPubKey),
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
			addr, err := address.NewAddressWitnessPubKeyHash(
				address.Hash160(pubKeyBytes), addrStore.ChainParams(),
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

	m := &bwmock.UnsupportedManagedPubKeyAddr{}
	m.On("Imported").Return(true).Once()

	isWatchOnly, err := managedAddressIsWatchOnly(false, m)
	require.ErrorContains(t, err, "unsupported managed pubkey address")
	require.False(t, isWatchOnly)
	m.AssertExpectations(t)
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

// convertAddrStoreToWatchOnly converts the legacy address manager to
// wallet-level watch-only mode for metadata adapter tests.
func convertAddrStoreToWatchOnly(t *testing.T, dbConn walletdb.DB,
	addrStore *waddrmgr.Manager) {

	t.Helper()

	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)

		return addrStore.ConvertToWatchingOnly(ns)
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
	addr, err := address.NewAddressTaproot(
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
