// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package kvdb

import (
	"context"
	"fmt"
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
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestForEachWatchAddressCancellation verifies that cancellation interrupts
// the scan between address rows in an already-open Bolt view.
func TestForEachWatchAddressCancellation(t *testing.T) {
	t.Parallel()

	// Arrange: Derive two eligible addresses in the same default scope so
	// the iterator has another row to visit after the request is canceled.
	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	scope, err := mgr.FetchScopedKeyManager(waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)

	err = walletdb.Update(store.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		_, err := scope.NextExternalAddresses(
			ns, waddrmgr.DefaultAccountNum, 2,
		)

		return err
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	visits := 0

	// Act: Cancel in the first address callback while the view is open.
	err = walletdb.View(store.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)

		return mgr.ForEachWatchAddress(
			ctx, ns, func(_ address.Address) error {
				visits++

				cancel()

				return nil
			},
		)
	})

	// Assert: The next callback is skipped and the error preserves the
	// cancellation cause across the storage iterator's error wrapping.
	require.Equal(t, 1, visits)
	require.ErrorIs(t, err, context.Canceled)
}

// TestForEachWatchAddressCallbackDecrypt verifies that a watch callback can
// read public metadata from the same manager during the Bolt view.
func TestForEachWatchAddressCallbackDecrypt(t *testing.T) {
	t.Parallel()

	// Arrange: Persist one eligible child and encrypt public metadata
	// with the manager the callback will re-enter.
	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	scope, err := mgr.FetchScopedKeyManager(waddrmgr.KeyScopeBIP0084)
	require.NoError(t, err)

	err = walletdb.Update(store.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		_, err := scope.NextExternalAddresses(
			ns, waddrmgr.DefaultAccountNum, 1,
		)

		return err
	})
	require.NoError(t, err)

	want := []byte("public metadata")
	ciphertext, err := mgr.Encrypt(waddrmgr.CKTPublic, want)
	require.NoError(t, err)

	var plaintext []byte

	// Act: Read the address snapshot and decrypt inside the callback.
	err = walletdb.View(store.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)

		return mgr.ForEachWatchAddress(
			t.Context(), ns, func(_ address.Address) error {
				decoded, err := mgr.Decrypt(
					waddrmgr.CKTPublic, ciphertext,
				)
				plaintext = decoded

				return err
			},
		)
	})

	// Assert: The callback completes re-entry and returns the metadata.
	require.NoError(t, err)
	require.Equal(t, want, plaintext)
}

// TestLoadWatchSetCustomScopeImport verifies that a persisted custom scope
// contributes its raw imports and change addresses.
func TestLoadWatchSetCustomScopeImport(t *testing.T) {
	t.Parallel()

	// Arrange: Persist one raw key and two derived children in a custom
	// scope. The external child belongs to that scope but is ineligible.
	baseStore, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)
	store := NewStore(baseStore.db, newTxStore(t, baseStore.db), mgr)

	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	wif, err := btcutil.NewWIF(key, mgr.ChainParams(), true)
	require.NoError(t, err)

	var expected [][]byte

	err = walletdb.Update(baseStore.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		schema := waddrmgr.ScopeAddrMap[waddrmgr.KeyScopeBIP0084]

		scope, err := mgr.NewScopedKeyManager(
			ns, waddrmgr.KeyScope{Purpose: 1017}, schema,
		)
		if err != nil {
			return err
		}

		// Use the same scope for both derivation branches so the watch
		// selection must distinguish change from external children.
		_, err = scope.NextExternalAddresses(
			ns, waddrmgr.DefaultAccountNum, 1,
		)
		if err != nil {
			return err
		}

		change, err := scope.NextInternalAddresses(
			ns, waddrmgr.DefaultAccountNum, 1,
		)
		if err != nil {
			return err
		}

		// A raw import in this scope is eligible despite having no
		// derivation branch.
		stamp := mgr.SyncedTo()

		imported, err := scope.ImportPrivateKey(ns, wif, &stamp)
		if err != nil {
			return err
		}

		for _, addr := range []waddrmgr.ManagedAddress{imported, change[0]} {
			script, err := txscript.PayToAddrScript(addr.Address())
			if err != nil {
				return err
			}

			expected = append(expected, script)
		}

		return nil
	})
	require.NoError(t, err)

	// Act: Read the watch set after the scope and all addresses commit.
	watches, err := store.LoadWatchSet(t.Context(), 0)

	// Assert: Both eligible scripts survive and the external one is absent.
	require.NoError(t, err)
	require.ElementsMatch(t, expected, watches.AddressScripts)
}

// TestAddressStoreNewDerivedAddress verifies that kvdb.Store creates derived
// addresses through the legacy address manager.
func TestAddressStoreNewDerivedAddress(t *testing.T) {
	t.Parallel()

	// Arrange a real root-derived account in a signing wallet so its child
	// provides the local-custody control for imported XPub addresses.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)
	props := createLegacyAccount(
		t, dbConn, addrStore, waddrmgr.KeyScopeBIP0084, "addr",
	)

	// Act by allocating through the normal named Store account selector.
	info, err := store.NewDerivedAddress(
		t.Context(), db.NewDerivedAddressParams{
			WalletID:    0,
			AccountName: "addr",
			Scope:       db.KeyScope(waddrmgr.KeyScopeBIP0084),
		},
	)

	// Assert the child retains local signing custody and its real account
	// identity, including through point and account-scoped ownership reads.
	require.NoError(t, err)
	require.Zero(t, info.ID)
	require.False(t, info.IsImported)
	require.False(t, info.IsWatchOnly)
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
	// Pagination alone retains the synthetic ordinal; all point metadata
	// stays identical when that page-local cursor is removed.
	require.Equal(t, uint32(1), result.Items[0].ID)
	result.Items[0].ID = 0
	require.Equal(t, *info, result.Items[0])
}

// TestAddressStoreNewDerivedAddressByNumber verifies that resolved numeric
// selectors allocate on both branches without needing a mutable account name.
func TestAddressStoreNewDerivedAddressByNumber(t *testing.T) {
	t.Parallel()

	for _, internal := range []bool{false, true} {
		t.Run(fmt.Sprintf("internal %v", internal), func(t *testing.T) {
			t.Parallel()

			// Arrange: Create a real legacy account, then address it only by
			// number so the test cannot succeed through a name lookup.
			dbConn, cleanup := newTestDB(t)
			t.Cleanup(cleanup)
			addrStore := newSpendableAddrMgr(t, dbConn)
			store := NewStore(dbConn, nil, addrStore)
			scope := waddrmgr.KeyScopeBIP0084
			props := createLegacyAccount(t, dbConn, addrStore, scope, "keys")
			params := db.NewDerivedAddressParams{
				Scope:         db.KeyScope(scope),
				AccountNumber: &props.AccountNumber,
				Change:        internal,
			}

			// Act: Allocate a fresh child using the same transaction as
			// ordinary named allocation, then read the persisted row.
			info, err := store.NewDerivedAddress(t.Context(), params)
			require.NoError(t, err)
			got, err := store.GetAddress(t.Context(), db.GetAddressQuery{
				ScriptPubKey: info.ScriptPubKey,
			})

			// Assert: Ownership and branch survive persistence; the missing
			// numeric account below must not silently select the default.
			require.NoError(t, err)
			require.Equal(t, info, got)
			require.Equal(t, props.AccountNumber, *got.AccountNumber)
			require.Equal(t, db.KeyScope(scope), got.KeyScope)
			require.Equal(t, internal, got.Branch == 1)
			require.Zero(t, got.Index)

			// Act: Retry with a number that has no legacy account row.
			missing := props.AccountNumber + 1
			params.AccountNumber = &missing
			info, err = store.NewDerivedAddress(t.Context(), params)

			// Assert: Missing numeric accounts expose the same Store sentinel
			// as named misses, without returning an unrelated key.
			require.ErrorIs(t, err, db.ErrAccountNotFound)
			require.Nil(t, info)
		})
	}
}

// TestAddressStoreImportedXpubChildHasNoAccountNumber verifies that kvdb
// matches SQL's imported-xpub contract: the address is imported key material,
// but its account number is not exposed as a wallet-derived BIP44 account
// number, and allocation and ownership reads retain external custody.
func TestAddressStoreImportedXpubChildHasNoAccountNumber(t *testing.T) {
	t.Parallel()

	// Arrange: Import an independent XPub into a signing wallet. Its children
	// must remain external even though the wallet root has signing material.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)
	accountName := "imported-xpub-address"
	accountNumber := createImportedXpubAccount(
		t, store, waddrmgr.KeyScopeBIP0084, accountName, 0xA5,
	)

	params := db.NewDerivedAddressParams{
		WalletID:      0,
		AccountName:   accountName,
		Scope:         db.KeyScope(waddrmgr.KeyScopeBIP0084),
		AccountNumber: &accountNumber,
	}

	// Act: Try the internal kvdb number as a wallet-derived account selector.
	info, err := store.NewDerivedAddress(t.Context(), params)

	// Assert: Refusal returns no child; ordinary allocation below must still
	// receive index zero, proving the legacy manager consumed nothing.
	require.ErrorIs(t, err, db.ErrAccountNotFound)
	require.Nil(t, info)

	// Act: Select the imported account by name to derive its first child.
	params.AccountNumber = nil
	info, err = store.NewDerivedAddress(t.Context(), params)

	// Assert: The child retains external custody and has no public wallet-root
	// account number, even while the wallet root can sign.
	require.NoError(t, err)
	require.Zero(t, info.Index)
	require.True(t, info.IsImported)
	require.True(t, info.IsWatchOnly)
	require.Nil(t, info.AccountNumber)
	require.Equal(t, accountName, info.AccountName)

	// Act: Resolve the persisted child by its script instead of the legacy
	// account number to exercise the public ownership read.
	got, err := store.GetAddress(
		t.Context(), db.GetAddressQuery{
			WalletID:     0,
			ScriptPubKey: info.ScriptPubKey,
		},
	)

	// Assert: Re-reading retains imported ownership and external custody;
	// the signing root must not make this child locally signable.
	require.NoError(t, err)
	require.True(t, got.IsImported)
	require.True(t, got.IsWatchOnly)
	require.Nil(t, got.AccountNumber)
	require.Equal(t, accountName, got.AccountName)

	// Arrange an account-scoped page so the list observes only this imported
	// account's allocated child, using the existing ownership selector.
	pageReq, err := page.NewRequest[uint32](10)
	require.NoError(t, err)

	// Act: Read the same persisted child through the paged ownership API.
	listed, err := store.ListAddresses(
		t.Context(), db.ListAddressesQuery{
			WalletID:    0,
			AccountName: &accountName,
			Scope:       &params.Scope,
			Page:        pageReq,
		},
	)

	// Assert: Listing the tracked child reports the same external custody
	// as allocation and the point read, without a separate wallet.
	require.NoError(t, err)
	require.Len(t, listed.Items, 1)
	require.True(t, listed.Items[0].IsWatchOnly)
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
			AddressType:  db.WitnessPubKey,
			ScriptPubKey: pkScript,
			PubKey:       pubKeyBytes,
		},
	)
	require.NoError(t, err)
	require.True(t, info.IsImported)
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

// TestGetAddressUnknownStandardAddressReturnsNotFound verifies that a valid
// standard script for an unowned address reaches the legacy manager lookup and
// returns only the Store-owned address-miss sentinel.
func TestGetAddressUnknownStandardAddressReturnsNotFound(t *testing.T) {
	t.Parallel()

	// Arrange: build a real legacy-backed Store, then encode a standard
	// witness address from a fresh key that was never imported into it. This
	// keeps script extraction successful so the lookup reaches waddrmgr.
	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)

	foreignKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	foreignAddr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(foreignKey.PubKey().SerializeCompressed()),
		addrStore.ChainParams(),
	)
	require.NoError(t, err)

	foreignScript, err := txscript.PayToAddrScript(foreignAddr)
	require.NoError(t, err)

	// Act: resolve the valid but unowned script through the modern kvdb Store
	// boundary, which must normalize the legacy manager miss.
	_, err = store.GetAddress(t.Context(), db.GetAddressQuery{
		WalletID:     0,
		ScriptPubKey: foreignScript,
	})

	// Assert: callers can classify the Store sentinel without inheriting the
	// backend-specific waddrmgr.ManagerError in the error chain.
	require.ErrorIs(t, err, db.ErrAddressNotFound)

	var managerErr waddrmgr.ManagerError
	require.NotErrorAs(t, err, &managerErr)
}

// TestAddressStoreResolveOwnedAddresses verifies that the batched resolver
// returns only the wallet-owned subset of a mixed script set in a single
// transaction, omits scripts that are not owned, and treats an empty input as
// an empty result without error.
func TestAddressStoreResolveOwnedAddresses(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	// Arrange: Forward only the declared address-store interface so the
	// real imports also guard constructor compatibility for wrapped stores.
	addrStore := newSpendableAddrMgr(t, dbConn)
	store := NewStore(dbConn, nil, struct {
		waddrmgr.AddrStore
	}{
		AddrStore: addrStore,
	})

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

		// Act: Resolve the mixed scripts through the declared store interface.
		owned, err := store.ResolveOwnedAddresses(
			t.Context(), db.ResolveOwnedAddressesQuery{
				WalletID: 0,
				ScriptPubKeys: [][]byte{
					owned1, foreignScript, owned2,
				},
			},
		)

		// Assert: Only both imported scripts are owned; the foreign key
		// stays absent instead of producing a capability error.
		require.NoError(t, err)

		require.Len(t, owned, 2)
		require.Contains(t, owned, string(owned1))
		require.Contains(t, owned, string(owned2))
		require.NotContains(t, owned, string(foreignScript))
	})

	t.Run("duplicate scripts resolve once", func(t *testing.T) {
		t.Parallel()

		// Act: Resolve repeated scripts through the same public resolver.
		owned, err := store.ResolveOwnedAddresses(
			t.Context(), db.ResolveOwnedAddressesQuery{
				WalletID:      0,
				ScriptPubKeys: [][]byte{owned1, owned1},
			},
		)

		// Assert: Repeated input has one owned result, preserving subset
		// deduplication through an ordinary interface forwarder.
		require.NoError(t, err)
		require.Len(t, owned, 1)
		require.Contains(t, owned, string(owned1))
	})

	t.Run("empty input", func(t *testing.T) {
		t.Parallel()

		// Act: Resolve no scripts through the same declared store interface.
		owned, err := store.ResolveOwnedAddresses(
			t.Context(), db.ResolveOwnedAddressesQuery{WalletID: 0},
		)

		// Assert: The public empty-query result remains a usable empty
		// map rather than a nil result or an unsupported-operation error.
		require.NoError(t, err)
		require.NotNil(t, owned)
		require.Empty(t, owned)
	})
}

// TestAddressStoreResolveOwnedAddressesUnlock protects cold ownership reads
// while the native manager derives and clears private keys during unlock.
func TestAddressStoreResolveOwnedAddressesUnlock(t *testing.T) {
	t.Parallel()

	// Arrange: Persist default children, then reopen locked so ownership
	// must populate cold scoped caches while the vault changes lock state.
	store, old, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	params := old.ChainParams()

	var scripts [][]byte

	err := walletdb.Update(store.db, func(tx walletdb.ReadWriteTx) error {
		scoped, err := old.FetchScopedKeyManager(waddrmgr.KeyScopeBIP0084)
		if err != nil {
			return err
		}

		addrs, err := scoped.NextExternalAddresses(
			tx.ReadWriteBucket(waddrmgr.NamespaceKey), 0, 64,
		)
		if err != nil {
			return err
		}

		for _, managed := range addrs {
			script, err := txscript.PayToAddrScript(managed.Address())
			if err != nil {
				return err
			}

			scripts = append(scripts, script)
		}

		return nil
	})
	require.NoError(t, err)
	old.Close()

	var mgr *waddrmgr.Manager

	err = walletdb.View(store.db, func(tx walletdb.ReadTx) error {
		var err error

		mgr, err = waddrmgr.Open(
			tx.ReadBucket(waddrmgr.NamespaceKey), []byte("pub"), params,
		)

		return err
	})
	require.NoError(t, err)
	t.Cleanup(mgr.Close)
	store = NewStore(store.db, nil, mgr)

	// Act: Start both public operations together. Each bounded goroutine
	// returns one result so the owner joins both before assertions/cleanup.
	start := make(chan struct{})
	errs := make(chan error, 2)

	var owned map[string]*db.AddressInfo

	go func() {
		<-start

		var err error

		owned, err = store.ResolveOwnedAddresses(
			t.Context(), db.ResolveOwnedAddressesQuery{
				ScriptPubKeys: scripts,
			},
		)
		errs <- err
	}()
	go func() {
		<-start

		for range 16 {
			err := walletdb.View(store.db, func(tx walletdb.ReadTx) error {
				return mgr.Unlock(
					tx.ReadBucket(waddrmgr.NamespaceKey), []byte("priv"),
				)
			})
			if err != nil {
				errs <- err
				return
			}

			err = mgr.Lock()
			if err != nil {
				errs <- err
				return
			}
		}

		errs <- nil
	}()

	close(start)

	first, second := <-errs, <-errs

	// Assert: Every persisted script remains owned across vault changes;
	// the race detector also verifies synchronized native derivation state.
	require.NoError(t, first)
	require.NoError(t, second)
	require.Len(t, owned, len(scripts))
}

// TestAddressStoreResolveScriptAliases prefers exact owners for shared key
// hashes and keeps the legacy lookup when only an alias matches.
func TestAddressStoreResolveScriptAliases(t *testing.T) {
	t.Parallel()

	// Arrange: Give one custom child a second owner in a legacy scope.
	// Keep the other child's hash unshared to exercise alias fallback.
	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	custom := db.KeyScope{
		Purpose: 1017,
		Coin:    1,
	}
	schema := db.ScopeAddrMap[db.KeyScopeBIP0084]
	number := uint32(0)

	const name = "overlapping-keys"

	_, err := store.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			Scope:         custom,
			Name:          name,
			AddrSchema:    &schema,
			AccountNumber: &number,
		}, kvdbDeriveFnFixture(t, mgr),
	)
	require.NoError(t, err)

	params := db.NewDerivedAddressParams{
		Scope:       custom,
		AccountName: name,
	}
	aliasOwner, err := store.NewDerivedAddress(t.Context(), params)
	require.NoError(t, err)
	overlap, err := store.NewDerivedAddress(t.Context(), params)
	require.NoError(t, err)
	legacyKey, err := address.NewAddressPubKeyHash(
		address.Hash160(overlap.PubKey), mgr.ChainParams(),
	)
	require.NoError(t, err)
	legacyScript, err := txscript.PayToAddrScript(legacyKey)
	require.NoError(t, err)
	_, err = store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			AddressType:  db.PubKeyHash,
			ScriptPubKey: legacyScript,
			PubKey:       overlap.PubKey,
		},
	)
	require.NoError(t, err)

	// No legacy row exists for the first key, so its legacy alias must keep
	// the native hash-only fallback when there is no exact-script owner.
	alias, err := address.NewAddressPubKeyHash(
		address.Hash160(aliasOwner.PubKey), mgr.ChainParams(),
	)
	require.NoError(t, err)
	aliasScript, err := txscript.PayToAddrScript(alias)
	require.NoError(t, err)

	// Fix scope order at the root reader boundary while the real native
	// iterator still loads and verifies every owner in the Bolt read view.
	resolver := &bwmock.AddrStore{}
	resolver.On("ChainParams").Return(mgr.ChainParams())
	resolver.On("ForEachAddressOwner", mock.Anything, mock.Anything,
		mock.Anything).Run(func(args mock.Arguments) {
		ns, ok := args.Get(0).(walletdb.ReadBucket)
		require.True(t, ok)

		addr, ok := args.Get(1).(address.Address)
		require.True(t, ok)

		visit, ok := args.Get(2).(func(waddrmgr.AccountStore, uint32,
			waddrmgr.ManagedAddress) error)
		require.True(t, ok)

		for _, scope := range []waddrmgr.KeyScope{
			waddrmgr.KeyScope(custom), waddrmgr.KeyScopeBIP0044,
		} {
			err := mgr.ForEachAddressOwner(ns, addr, func(
				owner waddrmgr.AccountStore, account uint32,
				managed waddrmgr.ManagedAddress) error {

				if owner.Scope() != scope {
					return nil
				}

				return visit(owner, account, managed)
			})
			require.NoError(t, err)
		}
	}).Return(nil)
	resolver.On("WatchOnly").Return(false)
	t.Cleanup(func() {
		resolver.AssertExpectations(t)
	})

	store = NewStore(store.db, nil, resolver)

	// Act: Resolve both formats of the shared key and the legacy alias of
	// the first child. The custom scope is visited before the import.
	owned, err := store.ResolveOwnedAddresses(
		t.Context(), db.ResolveOwnedAddressesQuery{
			ScriptPubKeys: [][]byte{
				overlap.ScriptPubKey,
				legacyScript,
				aliasScript,
			},
		},
	)

	// Assert: Each exact script resolves to its own scope. In the absence
	// of an exact match, the first child remains visible through its alias.
	require.NoError(t, err)
	require.Len(t, owned, 3)

	key := owned[string(overlap.ScriptPubKey)]
	require.NotNil(t, key)
	require.True(t, key.HasDerivationPath)
	require.Equal(t, custom, key.KeyScope)
	require.Equal(t, name, key.AccountName)
	require.Equal(t, overlap.ScriptPubKey, key.ScriptPubKey)

	legacy := owned[string(legacyScript)]
	require.NotNil(t, legacy)
	require.True(t, legacy.IsImported)
	require.Equal(t, legacyScript, legacy.ScriptPubKey)

	fallback := owned[string(aliasScript)]
	require.NotNil(t, fallback)
	require.Equal(t, custom, fallback.KeyScope)
	require.Equal(t, aliasOwner.ScriptPubKey, fallback.ScriptPubKey)
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
					WalletID:    0,
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

	// Deriving the taproot key needs an unlocked manager; the transport blob
	// travels under the public crypto key, as the wallet seals it.
	unlockAddrStore(t, dbConn, addrStore)

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
			AddressType:     db.TaprootPubKey,
			ScriptPubKey:    pkScript,
			EncryptedScript: encryptedScript,
		},
	)
	require.NoError(t, err)
	require.True(t, info.IsImported)
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
