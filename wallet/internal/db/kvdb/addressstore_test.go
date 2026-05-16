// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package kvdb

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// TestAddressStoreNewDerivedAddress verifies that kvdb.Store creates derived
// addresses through the legacy address manager.
func TestAddressStoreNewDerivedAddress(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	addrStore := newAddrStore(t, dbConn)
	store := NewStore(dbConn, nil, addrStore)
	props := createLegacyAccount(
		t, dbConn, addrStore, waddrmgr.KeyScopeBIP0084, "addr",
	)
	deriveFn := testAddressDerivationFunc(
		t, dbConn, addrStore, waddrmgr.KeyScopeBIP0084, "addr",
	)
	callbackCalled := false

	info, err := store.NewDerivedAddress(
		t.Context(), db.NewDerivedAddressParams{
			WalletID:    0,
			AccountName: "addr",
			Scope:       db.KeyScope(waddrmgr.KeyScopeBIP0084),
		}, func(ctx context.Context, accountID, branch, index uint32) (
			*db.DerivedAddressData, error) {

			callbackCalled = true

			require.Equal(t, props.AccountNumber, accountID)

			return deriveFn(ctx, accountID, branch, index)
		},
	)
	require.NoError(t, err)
	require.True(t, callbackCalled)
	require.Equal(t, uint32(1), info.ID)
	require.Equal(t, db.DerivedAccount, info.Origin)
	require.Equal(t, db.WitnessPubKey, info.AddrType)
	require.Equal(t, "addr", info.AccountName)
	require.Equal(t, props.AccountNumber, info.AccountID)
	require.NotEmpty(t, info.ScriptPubKey)
	require.NotEmpty(t, info.PubKey)
}

// testAddressDerivationFunc returns a derivation callback backed by the legacy
// address manager.
func testAddressDerivationFunc(t *testing.T, dbConn walletdb.DB,
	addrStore *waddrmgr.Manager, scope waddrmgr.KeyScope,
	accountName string) db.AddressDerivationFunc {

	t.Helper()

	return func(_ context.Context, _ uint32, branch, index uint32) (
		*db.DerivedAddressData, error) {

		manager, err := addrStore.FetchScopedKeyManager(scope)
		require.NoError(t, err)

		var derivedData *db.DerivedAddressData

		err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
			ns := tx.ReadBucket(waddrmgr.NamespaceKey)

			account, err := manager.LookupAccount(ns, accountName)
			if err != nil {
				return err
			}

			managedAddr, err := manager.DeriveFromKeyPath(
				ns, waddrmgr.DerivationPath{
					InternalAccount: account,
					Branch:          branch,
					Index:           index,
				},
			)
			if err != nil {
				return err
			}

			scriptPubKey, err := txscript.PayToAddrScript(
				managedAddr.Address(),
			)
			if err != nil {
				return err
			}

			derivedData = &db.DerivedAddressData{
				ScriptPubKey: scriptPubKey,
			}

			pubKeyAddr, ok := managedAddr.(waddrmgr.ManagedPubKeyAddress)
			if ok {
				derivedData.PubKey = pubKeyAddr.PubKey().
					SerializeCompressed()
			}

			return nil
		})
		if err != nil {
			return nil, err
		}

		return derivedData, nil
	}
}
