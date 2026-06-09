//go:build itest

package itest

import (
	"context"
	"encoding/binary"
	"math"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/wallet/internal/db/page"
	"github.com/stretchr/testify/require"
)

// mockDeriveFunc returns a test address derivation function. It generates
// deterministic script pubkeys from scope, account number, branch, and index so
// derived test addresses are unique across scopes.
func mockDeriveFunc() db.AddressDerivationFunc {
	return func(ctx context.Context,
		params db.AddressDerivationParams) (*db.DerivedAddressData, error) {

		_ = ctx

		scriptPubKey := make([]byte, 20)
		binary.BigEndian.PutUint32(scriptPubKey[0:4], params.AccountNumber)
		binary.BigEndian.PutUint32(scriptPubKey[4:8], params.Branch)
		binary.BigEndian.PutUint32(scriptPubKey[8:12], params.Index)
		binary.BigEndian.PutUint32(scriptPubKey[12:16], params.Scope.Purpose)
		binary.BigEndian.PutUint32(scriptPubKey[16:20], params.Scope.Coin)

		return &db.DerivedAddressData{
			ScriptPubKey: scriptPubKey,
		}, nil
	}
}

// newDerivedAddress creates and returns a derived address for testing.
func newDerivedAddress(t *testing.T, store db.AddressStore, walletID uint32,
	scope db.KeyScope, accountName string, change bool) *db.AddressInfo {

	t.Helper()

	info, err := store.NewDerivedAddress(
		t.Context(), db.NewDerivedAddressParams{
			WalletID:    walletID,
			Scope:       scope,
			AccountName: accountName,
			Change:      change,
		},
	)
	require.NoError(t, err)

	return info
}

// createDerivedAddresses creates and returns a slice of derived addresses for
// testing.
func createDerivedAddresses(t *testing.T, store db.AddressStore,
	walletID uint32, scope db.KeyScope, accountName string, change bool,
	count int) []db.AddressInfo {

	t.Helper()

	addresses := make([]db.AddressInfo, 0, count)
	for range count {
		info := newDerivedAddress(
			t, store, walletID, scope, accountName, change,
		)
		addresses = append(addresses, *info)
	}

	return addresses
}

// getAccountByName retrieves an account by wallet, scope, and name for testing.
func getAccountByName(t *testing.T, store db.AccountStore, walletID uint32,
	scope db.KeyScope, accountName string) *db.AccountInfo {

	t.Helper()

	account, err := store.GetAccount(
		t.Context(), getAccountQueryByName(walletID, scope, accountName),
	)
	require.NoError(t, err)

	return account
}

// collectAddressPages collects paginated address results by iterating through
// all pages from ListAddresses until Next is nil.
func collectAddressPages(t *testing.T, store db.AddressStore,
	query db.ListAddressesQuery) []page.Result[db.AddressInfo, uint32] {

	t.Helper()

	pages := make([]page.Result[db.AddressInfo, uint32], 0)
	for {
		pageResult, err := store.ListAddresses(t.Context(), query)
		require.NoError(t, err)

		pages = append(pages, pageResult)

		if pageResult.Next == nil {
			return pages
		}

		query.Page.After = pageResult.Next
	}
}

// flattenAddressPages flattens paginated address results into a single
// slice containing all addresses from all pages.
func flattenAddressPages(
	pages []page.Result[db.AddressInfo, uint32]) []db.AddressInfo {

	count := 0
	for i := range pages {
		count += len(pages[i].Items)
	}

	addresses := make([]db.AddressInfo, 0, count)
	for i := range pages {
		addresses = append(addresses, pages[i].Items...)
	}

	return addresses
}

// importedAddressWallet picks the wallet flavor a subtest needs based on
// whether the imported address carries private-key material. Per ADR
// 0012, public-only (no private key) imports require a watch-only
// wallet, while imports with private-key material require a spendable
// wallet.
func importedAddressWallet(t *testing.T, store db.WalletStore,
	name string, withPrivateKey bool) uint32 {

	t.Helper()

	if withPrivateKey {
		return newWallet(t, store, name)
	}

	return newWatchOnlyWallet(t, store, name)
}

// TestNewImportedAddress verifies that NewImportedAddress correctly imports
// addresses of different types, with and without private key material.
func TestNewImportedAddress(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := privKey.PubKey()

	p2pkhAddr, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chaincfg.MainNetParams,
	)
	require.NoError(t, err)

	p2wpkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()), &chaincfg.MainNetParams,
	)
	require.NoError(t, err)

	p2trAddr, err := btcutil.NewAddressTaproot(
		pubKey.SerializeCompressed()[1:], &chaincfg.MainNetParams,
	)
	require.NoError(t, err)

	testCases := []struct {
		name              string
		addr              btcutil.Address
		scope             db.KeyScope
		expectedAddrType  db.AddressType
		providePrivateKey bool
	}{
		{
			name:              "P2PKH without private key",
			addr:              p2pkhAddr,
			scope:             db.KeyScopeBIP0044,
			expectedAddrType:  db.PubKeyHash,
			providePrivateKey: false,
		},
		{
			name:              "P2PKH with private key",
			addr:              p2pkhAddr,
			scope:             db.KeyScopeBIP0044,
			expectedAddrType:  db.PubKeyHash,
			providePrivateKey: true,
		},
		{
			name:              "P2WPKH without private key",
			addr:              p2wpkhAddr,
			scope:             db.KeyScopeBIP0084,
			expectedAddrType:  db.WitnessPubKey,
			providePrivateKey: false,
		},
		{
			name:              "P2WPKH with private key",
			addr:              p2wpkhAddr,
			scope:             db.KeyScopeBIP0084,
			expectedAddrType:  db.WitnessPubKey,
			providePrivateKey: true,
		},
		{
			name:              "P2TR without private key",
			addr:              p2trAddr,
			scope:             db.KeyScopeBIP0086,
			expectedAddrType:  db.TaprootPubKey,
			providePrivateKey: false,
		},
		{
			name:              "P2TR with private key",
			addr:              p2trAddr,
			scope:             db.KeyScopeBIP0086,
			expectedAddrType:  db.TaprootPubKey,
			providePrivateKey: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			walletID := importedAddressWallet(
				t, store, "wallet-imported-"+tc.name,
				tc.providePrivateKey,
			)

			params := db.NewImportedAddressParams{
				WalletID:     walletID,
				Scope:        tc.scope,
				AddressType:  tc.expectedAddrType,
				PubKey:       RandomBytes(33),
				ScriptPubKey: RandomBytes(32),
			}

			if tc.providePrivateKey {
				params.EncryptedPrivateKey = RandomBytes(32)
			}

			// Import the address.
			info, err := store.NewImportedAddress(t.Context(), params)
			require.NoError(t, err)

			// Verify AddressInfo fields.
			require.NotZero(t, info.ID)
			require.NotZero(t, info.AccountID)
			require.Equal(t, db.ImportedAccount, info.Origin)
			require.NotZero(t, info.CreatedAt)
			require.Equal(t, uint32(0), info.Branch)
			require.Equal(t, uint32(0), info.Index)
			require.NotNil(t, info.PubKey)
			require.NotNil(t, info.ScriptPubKey)
			require.Equal(t, tc.expectedAddrType, info.AddrType)

			// Verify address creation returned complete account metadata.
			account, err := store.GetAccount(
				t.Context(), getAccountQueryByName(
					walletID, tc.scope, "imported",
				),
			)
			require.NoError(t, err)
			require.Equal(t, account.AccountNumber, info.AccountNumber)
			require.Equal(t, account.AccountName, info.AccountName)
			require.Equal(t, account.KeyScope, info.KeyScope)
			require.Equal(
				t, account.MasterKeyFingerprint,
				info.MasterKeyFingerprint,
			)

			// Verify account imported_key_count incremented.
			require.Positive(t, account.ImportedKeyCount)

			// Verify address_secrets row for imported addresses.
			addressID := getAddressID(
				t, queries, params.ScriptPubKey, walletID,
			)

			secret, err := store.GetAddressSecret(
				t.Context(), db.GetAddressSecretQuery{
					WalletID:  walletID,
					AddressID: uint32(addressID),
				},
			)

			if tc.providePrivateKey {
				require.NoError(t, err)
				require.Equal(
					t, params.EncryptedPrivateKey, secret.EncryptedPrivKey,
				)
				require.Empty(t, secret.EncryptedScript)
			} else {
				require.ErrorIs(t, err, db.ErrSecretNotFound)
			}
		})
	}
}

// TestImportedAddressLandsInImportedAccount documents the SQL import policy
// for private-key address imports: an imported address is always placed in
// the per-scope dedicated "imported" account and is never treated as a
// member of a derived (HD) account, even when a derived account already
// exists in the same scope. See ADR 0012.
func TestImportedAddressLandsInImportedAccount(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	scope := db.KeyScopeBIP0084

	// Spendable wallet so the private-key-bearing import is the path the
	// ADR 0012 symmetric invariant accepts.
	walletID := newWallet(t, store, "wallet-import-lands-in-imported")

	// A derived account exists in the same scope. The imported address
	// must NOT be attributed to it; it must go to the auto-created
	// wallet-level "imported" bucket instead.
	createDerivedAccount(t, store, walletID, scope, "derived-acct")

	// Import a private-key-bearing address. No "imported" account exists
	// yet in this scope, so the import auto-creates the keyless bucket.
	info, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:            walletID,
			Scope:               scope,
			AddressType:         db.WitnessPubKey,
			PubKey:              RandomBytes(33),
			ScriptPubKey:        RandomBytes(32),
			EncryptedPrivateKey: RandomBytes(32),
		},
	)
	require.NoError(t, err)

	// The address is owned by the "imported" account, not the derived one.
	require.Equal(t, db.ImportedAccount, info.Origin)
	require.Equal(t, db.DefaultImportedAccountName, info.AccountName)

	importedAccountID := GetAccountID(
		t, store.Queries(),
		GetKeyScopeID(t, store.Queries(), walletID, scope),
		db.DefaultImportedAccountName,
	)
	require.EqualValues(t, importedAccountID, info.AccountID)
}

// TestImportedAddressNeverLandsInDerivedAccount documents that the SQL import
// flow never retargets an imported address into a derived account: when no
// "imported" bucket exists yet in the address's scope, the import
// auto-creates the keyless wallet-level bucket and attributes the address to
// it, even though a derived account is present in the same scope. See ADR
// 0012.
func TestImportedAddressNeverLandsInDerivedAccount(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	scope := db.KeyScopeBIP0084

	walletID := newWallet(t, store, "wallet-import-no-imported-account")

	// Only a derived account exists; no "imported" bucket has been created
	// in this scope. The import must NOT reuse the derived account.
	createDerivedAccount(t, store, walletID, scope, "derived-only")

	derivedAccountID := GetAccountID(
		t, queries, GetKeyScopeID(t, queries, walletID, scope),
		"derived-only",
	)

	info, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:            walletID,
			Scope:               scope,
			AddressType:         db.WitnessPubKey,
			PubKey:              RandomBytes(33),
			ScriptPubKey:        RandomBytes(32),
			EncryptedPrivateKey: RandomBytes(32),
		},
	)
	require.NoError(t, err)

	// The address landed in the freshly auto-created imported bucket, not
	// in the pre-existing derived account.
	require.Equal(t, db.ImportedAccount, info.Origin)
	require.Equal(t, db.DefaultImportedAccountName, info.AccountName)
	require.NotEqualValues(t, derivedAccountID, info.AccountID)
}

// TestNewImportedAddressWithEncryptedScript verifies that NewImportedAddress
// correctly imports script-based addresses (P2SH, P2WSH) with EncryptedScript,
// and that the EncryptedScript is stored and retrievable via GetAddressSecret.
func TestNewImportedAddressWithEncryptedScript(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()

	redeemScript := RandomBytes(32)
	witnessScript := RandomBytes(48)

	testCases := []struct {
		name             string
		scope            db.KeyScope
		addressType      db.AddressType
		encryptedScript  []byte
		hasPrivateKey    bool
		expectedAddrType db.AddressType
	}{
		{
			name:             "P2SH with EncryptedScript only",
			scope:            db.KeyScopeBIP0044,
			addressType:      db.ScriptHash,
			encryptedScript:  redeemScript,
			hasPrivateKey:    false,
			expectedAddrType: db.ScriptHash,
		},
		{
			name: "P2SH with both EncryptedPrivateKey and " +
				"EncryptedScript",
			scope:            db.KeyScopeBIP0044,
			addressType:      db.ScriptHash,
			encryptedScript:  redeemScript,
			hasPrivateKey:    true,
			expectedAddrType: db.ScriptHash,
		},
		{
			name:             "P2WSH with EncryptedScript only",
			scope:            db.KeyScopeBIP0049Plus,
			addressType:      db.WitnessScript,
			encryptedScript:  witnessScript,
			hasPrivateKey:    false,
			expectedAddrType: db.WitnessScript,
		},
		{
			name: "P2WSH with both EncryptedPrivateKey and " +
				"EncryptedScript",
			scope:            db.KeyScopeBIP0049Plus,
			addressType:      db.WitnessScript,
			encryptedScript:  witnessScript,
			hasPrivateKey:    true,
			expectedAddrType: db.WitnessScript,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			walletIsWatchOnly := !tc.hasPrivateKey
			walletID := importedAddressWallet(
				t, store, "wallet-encrypted-script-"+tc.name,
				tc.hasPrivateKey,
			)

			scriptPubKey := RandomBytes(32)

			params := db.NewImportedAddressParams{
				WalletID:        walletID,
				Scope:           tc.scope,
				AddressType:     tc.addressType,
				PubKey:          RandomBytes(33),
				ScriptPubKey:    scriptPubKey,
				EncryptedScript: tc.encryptedScript,
			}

			if tc.hasPrivateKey {
				params.EncryptedPrivateKey = RandomBytes(32)
			}

			info, err := store.NewImportedAddress(t.Context(), params)
			require.NoError(t, err)

			require.NotZero(t, info.ID)
			require.NotZero(t, info.AccountID)
			require.Equal(t, db.ImportedAccount, info.Origin)
			require.NotZero(t, info.CreatedAt)
			require.Equal(t, uint32(0), info.Branch)
			require.Equal(t, uint32(0), info.Index)
			require.NotNil(t, info.PubKey)
			require.NotNil(t, info.ScriptPubKey)
			require.Equal(t, tc.expectedAddrType, info.AddrType)
			require.Equal(t, walletIsWatchOnly, info.IsWatchOnly)

			addressID := getAddressID(
				t, queries, params.ScriptPubKey, walletID,
			)

			secret, err := store.GetAddressSecret(
				t.Context(), db.GetAddressSecretQuery{
					WalletID:  walletID,
					AddressID: uint32(addressID),
				},
			)
			require.NoError(t, err)
			require.Equal(t, tc.encryptedScript, secret.EncryptedScript)

			if tc.hasPrivateKey {
				require.Equal(
					t, params.EncryptedPrivateKey, secret.EncryptedPrivKey,
				)
			} else {
				require.Empty(t, secret.EncryptedPrivKey)
			}
		})
	}
}

// TestNewImportedAddressNormalizesEmptyPrivateKey verifies that empty private
// key payloads are treated as absent for validation and persisted as NULL.
func TestNewImportedAddressNormalizesEmptyPrivateKey(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWatchOnlyWallet(
		t, store, "wallet-empty-private-import",
	)

	params := db.NewImportedAddressParams{
		WalletID:            walletID,
		Scope:               db.KeyScopeBIP0044,
		AddressType:         db.ScriptHash,
		PubKey:              RandomBytes(33),
		ScriptPubKey:        RandomBytes(32),
		EncryptedPrivateKey: []byte{},
		EncryptedScript:     RandomBytes(48),
	}

	info, err := store.NewImportedAddress(t.Context(), params)
	require.NoError(t, err)
	require.NotNil(t, info)
	require.True(t, info.IsWatchOnly)

	secret, err := store.GetAddressSecret(
		t.Context(), db.GetAddressSecretQuery{
			WalletID:  walletID,
			AddressID: info.ID,
		},
	)
	require.NoError(t, err)
	require.Nil(t, secret.EncryptedPrivKey)
	require.Equal(t, params.EncryptedScript, secret.EncryptedScript)
}

// TestWatchOnlyHierarchyAddressRules is the canonical wallet-to-account-to-
// address watch-only matrix for derived and imported addresses.
func TestWatchOnlyHierarchyAddressRules(t *testing.T) {
	t.Parallel()

	type watchOnlyAddressStore interface {
		db.AddressStore
		db.AccountStore
	}

	tests := []struct {
		name            string
		walletParams    func(string) db.CreateWalletParams
		wantWatchOnly   bool
		wantErr         error
		createAddressFn func(*testing.T, watchOnlyAddressStore, uint32) (bool,
			error)
	}{
		{
			name: "standard wallet derived address is " +
				"spendable",
			walletParams:  CreateWalletParamsFixture,
			wantWatchOnly: false,
			createAddressFn: func(t *testing.T, store watchOnlyAddressStore,
				walletID uint32) (bool, error) {

				t.Helper()
				createDerivedAccount(
					t, store, walletID, db.KeyScopeBIP0084, "derived",
				)

				info := newDerivedAddress(
					t, store, walletID, db.KeyScopeBIP0084, "derived", false,
				)

				return info.IsWatchOnly, nil
			},
		},
		{
			name: "watch-only wallet derived address is " +
				"watch-only",
			walletParams:  CreateWatchOnlyWalletParams,
			wantWatchOnly: true,
			createAddressFn: func(t *testing.T, store watchOnlyAddressStore,
				walletID uint32) (bool, error) {

				t.Helper()
				createDerivedAccount(
					t, store, walletID, db.KeyScopeBIP0084, "derived",
				)

				info := newDerivedAddress(
					t, store, walletID, db.KeyScopeBIP0084, "derived", false,
				)

				return info.IsWatchOnly, nil
			},
		},
		{
			name: "standard wallet imported address with " +
				"private key is spendable",
			walletParams:  CreateWalletParamsFixture,
			wantWatchOnly: false,
			createAddressFn: func(t *testing.T, store watchOnlyAddressStore,
				walletID uint32) (bool, error) {

				t.Helper()

				// No "imported" account is pre-created: the import
				// auto-creates the keyless bucket.
				info, err := store.NewImportedAddress(
					t.Context(), db.NewImportedAddressParams{
						WalletID:            walletID,
						Scope:               db.KeyScopeBIP0084,
						AddressType:         db.WitnessPubKey,
						PubKey:              RandomBytes(33),
						ScriptPubKey:        RandomBytes(32),
						EncryptedPrivateKey: RandomBytes(32),
					},
				)
				if err != nil {
					return false, err
				}

				return info.IsWatchOnly, nil
			},
		},
		{
			name: "standard wallet imported address without " +
				"private key is rejected",
			walletParams: CreateWalletParamsFixture,
			wantErr:      db.ErrSpendableWalletNeedsAddressPrivKey,
			createAddressFn: func(t *testing.T, store watchOnlyAddressStore,
				walletID uint32) (bool, error) {

				t.Helper()

				// The spendable-wallet invariant rejects a public-only
				// import before any bucket is created.
				info, err := store.NewImportedAddress(
					t.Context(), db.NewImportedAddressParams{
						WalletID:     walletID,
						Scope:        db.KeyScopeBIP0084,
						AddressType:  db.WitnessPubKey,
						PubKey:       RandomBytes(33),
						ScriptPubKey: RandomBytes(32),
					},
				)
				if err != nil {
					return false, err
				}

				return info.IsWatchOnly, nil
			},
		},
		{
			name: "watch-only wallet script-only imported " +
				"address is watch-only",
			walletParams:  CreateWatchOnlyWalletParams,
			wantWatchOnly: true,
			createAddressFn: func(t *testing.T, store watchOnlyAddressStore,
				walletID uint32) (bool, error) {

				t.Helper()

				// The import auto-creates the keyless bucket; a
				// script-only import on a watch-only wallet is
				// watch-only.
				info, err := store.NewImportedAddress(
					t.Context(), db.NewImportedAddressParams{
						WalletID:        walletID,
						Scope:           db.KeyScopeBIP0084,
						AddressType:     db.WitnessScript,
						PubKey:          RandomBytes(33),
						ScriptPubKey:    RandomBytes(32),
						EncryptedScript: RandomBytes(48),
					},
				)
				if err != nil {
					return false, err
				}

				return info.IsWatchOnly, nil
			},
		},
		{
			name: "watch-only wallet imported address with " +
				"private key is rejected",
			walletParams: CreateWatchOnlyWalletParams,
			wantErr:      db.ErrWatchOnlyViolation,
			createAddressFn: func(t *testing.T, store watchOnlyAddressStore,
				walletID uint32) (bool, error) {

				t.Helper()

				// The watch-only invariant rejects a private-key
				// import before any bucket is created.
				info, err := store.NewImportedAddress(
					t.Context(), db.NewImportedAddressParams{
						WalletID:            walletID,
						Scope:               db.KeyScopeBIP0084,
						AddressType:         db.WitnessScript,
						PubKey:              RandomBytes(33),
						ScriptPubKey:        RandomBytes(32),
						EncryptedPrivateKey: RandomBytes(32),
						EncryptedScript:     RandomBytes(48),
					},
				)
				if err != nil {
					return false, err
				}

				return info.IsWatchOnly, nil
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := NewTestStore(t)

			walletInfo, err := store.CreateWallet(
				t.Context(), tc.walletParams("watch-only-address-matrix"),
			)
			require.NoError(t, err)

			isWatchOnly, err := tc.createAddressFn(t, store, walletInfo.ID)
			require.ErrorIs(t, err, tc.wantErr)

			if tc.wantErr != nil {
				return
			}

			require.Equal(t, tc.wantWatchOnly, isWatchOnly)
		})
	}
}

// TestWatchOnlyAddressSecretTriggers verifies that address_secrets rejects
// private-key writes for watch-only imported addresses while still allowing
// inserts and updates for non-watch-only parent wallets.
func TestWatchOnlyAddressSecretTriggers(t *testing.T) {
	t.Parallel()

	t.Run("watch-only insert is rejected", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)

		walletInfo, err := store.CreateWallet(
			t.Context(),
			CreateWatchOnlyWalletParams("watch-only-address-secret-insert"),
		)
		require.NoError(t, err)

		// The import auto-creates the keyless bucket; no "imported"
		// account is pre-created.
		info, err := store.NewImportedAddress(
			t.Context(), db.NewImportedAddressParams{
				WalletID:     walletInfo.ID,
				Scope:        db.KeyScopeBIP0084,
				AddressType:  db.WitnessPubKey,
				PubKey:       RandomBytes(33),
				ScriptPubKey: RandomBytes(32),
			},
		)
		require.NoError(t, err)

		err = insertAddressSecretRaw(
			t, store.DB(), int64(info.ID), RandomBytes(32), nil,
		)
		require.Error(t, err)
		requireDriverConstraintError(t, err)
	})

	t.Run("watch-only update is rejected", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)

		walletInfo, err := store.CreateWallet(
			t.Context(),
			CreateWatchOnlyWalletParams("watch-only-address-secret-update"),
		)
		require.NoError(t, err)

		// The import auto-creates the keyless bucket; no "imported"
		// account is pre-created.
		info, err := store.NewImportedAddress(
			t.Context(), db.NewImportedAddressParams{
				WalletID:        walletInfo.ID,
				Scope:           db.KeyScopeBIP0084,
				AddressType:     db.WitnessScript,
				PubKey:          RandomBytes(33),
				ScriptPubKey:    RandomBytes(32),
				EncryptedScript: RandomBytes(48),
			},
		)
		require.NoError(t, err)
		require.True(t, info.IsWatchOnly)

		err = updateAddressSecretRaw(
			t, store.DB(), int64(info.ID), RandomBytes(32), RandomBytes(48),
		)
		require.Error(t, err)
		requireDriverConstraintError(t, err)
	})

	t.Run("non-watch-only update succeeds", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)

		// ADR 0012: an imported address on a spendable wallet must
		// carry encrypted private-key material at creation time, so
		// the API path inserts the secret row. The trigger's
		// non-watch-only allow path is exercised via UPDATE on that
		// row; a raw INSERT would conflict with the API-inserted
		// row and is no longer reachable.
		walletID := newWallet(
			t, store, "spendable-address-secret-trigger",
		)

		initialPrivKey := RandomBytes(32)
		info, err := store.NewImportedAddress(
			t.Context(), db.NewImportedAddressParams{
				WalletID:            walletID,
				Scope:               db.KeyScopeBIP0084,
				AddressType:         db.WitnessPubKey,
				PubKey:              RandomBytes(33),
				ScriptPubKey:        RandomBytes(32),
				EncryptedPrivateKey: initialPrivKey,
			},
		)
		require.NoError(t, err)
		require.False(t, info.IsWatchOnly)

		updatedPrivKey := RandomBytes(32)
		updatedScript := RandomBytes(48)
		err = updateAddressSecretRaw(
			t, store.DB(), int64(info.ID), updatedPrivKey, updatedScript,
		)
		require.NoError(t, err)

		secret, err := store.GetAddressSecret(
			t.Context(), db.GetAddressSecretQuery{
				WalletID:  walletID,
				AddressID: info.ID,
			},
		)
		require.NoError(t, err)
		require.Equal(t, updatedPrivKey, secret.EncryptedPrivKey)
		require.Equal(t, updatedScript, secret.EncryptedScript)
	})
}

// TestImportedAddressCounterInsertDelete verifies that imported address inserts
// increment the per-account counter and deletes decrement it.
func TestImportedAddressCounterInsertDelete(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	dbConn := store.DB()
	// ADR 0012: imported addresses without private-key material need a
	// watch-only wallet to satisfy the symmetric invariant.
	walletID := newWatchOnlyWallet(
		t, store, "wallet-imported-counter",
	)

	const importedAddrCount = 5

	addressIDs := make([]uint32, 0, importedAddrCount)

	// The bucket does not exist until the first import auto-creates it, so
	// the counter starts implicitly at zero and reaches importedAddrCount
	// once every address is imported.
	for range importedAddrCount {
		info, err := store.NewImportedAddress(
			t.Context(), db.NewImportedAddressParams{
				WalletID:     walletID,
				Scope:        db.KeyScopeBIP0084,
				AddressType:  db.WitnessPubKey,
				ScriptPubKey: RandomBytes(32),
				PubKey:       RandomBytes(33),
			},
		)
		require.NoError(t, err)

		addressIDs = append(addressIDs, info.ID)
	}

	account := getAccountByName(
		t, store, walletID, db.KeyScopeBIP0084, "imported",
	)
	require.Equal(t, uint32(importedAddrCount), account.ImportedKeyCount)

	for _, addressID := range addressIDs {
		MustDeleteAddress(t, dbConn, addressID)
	}

	account = getAccountByName(
		t, store, walletID, db.KeyScopeBIP0084, "imported",
	)
	require.Zero(t, account.ImportedKeyCount)
}

// TestImportedAddressCounterConcurrentInsert verifies that concurrent imported
// address inserts correctly update the per-account imported key counter.
func TestImportedAddressCounterConcurrentInsert(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	dbConn := store.DB()
	// ADR 0012: imported addresses without private-key material need a
	// watch-only wallet to satisfy the symmetric invariant.
	walletID := newWatchOnlyWallet(
		t, store, "wallet-imported-counter-concurrent",
	)

	const workers = 20

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	// Materialize the bucket with one sequential import before the
	// concurrent inserts so all workers reuse it. Concurrent first-imports
	// would otherwise race to auto-create the same (scope, name) bucket and
	// collide on the unique constraint.
	warmup, err := store.NewImportedAddress(
		ctx, db.NewImportedAddressParams{
			WalletID:     walletID,
			Scope:        db.KeyScopeBIP0084,
			AddressType:  db.WitnessPubKey,
			ScriptPubKey: RandomBytes(32),
			PubKey:       RandomBytes(33),
		},
	)
	require.NoError(t, err)

	type insertResult struct {
		id  uint32
		err error
	}

	insertResultChan := make(chan insertResult, workers)

	var wg sync.WaitGroup

	for range workers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			info, err := store.NewImportedAddress(
				ctx, db.NewImportedAddressParams{
					WalletID:     walletID,
					Scope:        db.KeyScopeBIP0084,
					AddressType:  db.WitnessPubKey,
					ScriptPubKey: RandomBytes(32),
					PubKey:       RandomBytes(33),
				},
			)
			if err != nil {
				insertResultChan <- insertResult{err: err}
				return
			}

			insertResultChan <- insertResult{id: info.ID}
		}()
	}

	wg.Wait()
	close(insertResultChan)

	addressIDs := make([]uint32, 0, workers+1)
	addressIDs = append(addressIDs, warmup.ID)

	for result := range insertResultChan {
		require.NoError(t, result.err)
		addressIDs = append(addressIDs, result.id)
	}

	require.Len(t, addressIDs, workers+1)

	account := getAccountByName(
		t, store, walletID, db.KeyScopeBIP0084, "imported",
	)
	require.Equal(t, uint32(workers+1), account.ImportedKeyCount)

	deleteErrChan := make(chan error, len(addressIDs))
	for _, addressID := range addressIDs {
		wg.Add(1)

		go func() {
			defer wg.Done()

			deleteErrChan <- deleteAddress(ctx, dbConn, addressID)
		}()
	}

	wg.Wait()
	close(deleteErrChan)

	for err := range deleteErrChan {
		require.NoError(t, err)
	}

	account = getAccountByName(
		t, store, walletID, db.KeyScopeBIP0084, "imported",
	)
	require.Zero(t, account.ImportedKeyCount)
}

// TestImportedBucketMaterializationIdempotent proves that materializing the
// keyless wallet-level imported bucket is an idempotent get-or-create: once a
// scope owns its bucket, re-running the materialization (the path a racing
// concurrent first-import takes) is a no-op rather than a collision on the
// (scope_id, account_name) unique index. This is the regression guard for the
// concurrency race where two first-imports into the same empty scope both
// observed sql.ErrNoRows and the second insert aborted the write transaction.
func TestImportedBucketMaterializationIdempotent(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	scope := db.KeyScopeBIP0084

	// ADR 0012: a keyless imported bucket and its keyless addresses need a
	// watch-only wallet to satisfy the symmetric invariant.
	walletID := newWatchOnlyWallet(t, store, "wallet-bucket-idempotent")

	// Arrange: the first import materializes the scope and the keyless
	// bucket, mirroring the winner of a concurrent first-import race.
	info, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:     walletID,
			Scope:        scope,
			AddressType:  db.WitnessPubKey,
			ScriptPubKey: RandomBytes(32),
			PubKey:       RandomBytes(33),
		},
	)
	require.NoError(t, err)
	require.Equal(t, db.DefaultImportedAccountName, info.AccountName)

	scopeID := GetKeyScopeID(t, queries, walletID, scope)
	bucketID := GetAccountID(t, queries, scopeID, db.DefaultImportedAccountName)

	// Act: re-run the bucket materialization twice more, exactly as the
	// losers of a concurrent first-import race would. Before the fix these
	// inserts hit the unique index and aborted; with ON CONFLICT DO NOTHING
	// each is a clean no-op.
	require.NoError(t, createImportedBucketAccountRaw(
		t.Context(), queries, scopeID,
	))
	require.NoError(t, createImportedBucketAccountRaw(
		t.Context(), queries, scopeID,
	))

	// Assert: the bucket was reused, not duplicated. A second accounts row
	// could not exist (the unique index forbids it), and GetAccountID
	// resolving to the original ID confirms the one bucket survived.
	reusedID := GetAccountID(
		t, queries, scopeID, db.DefaultImportedAccountName,
	)
	require.Equal(t, bucketID, reusedID)
}

// TestNewImportedAddressDuplicate verifies that importing an address with
// a duplicate ScriptPubKey fails with a constraint error.
func TestNewImportedAddressDuplicate(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-duplicate-import")

	// Set up encryption parameters (same for both imports). The first
	// import auto-creates the keyless bucket.
	scriptPubKey := RandomBytes(32)

	params := db.NewImportedAddressParams{
		WalletID:            walletID,
		Scope:               db.KeyScopeBIP0084,
		AddressType:         db.WitnessPubKey,
		PubKey:              RandomBytes(33),
		ScriptPubKey:        scriptPubKey,
		EncryptedPrivateKey: RandomBytes(32),
	}

	// Import address first time (should succeed).
	_, err := store.NewImportedAddress(t.Context(), params)
	require.NoError(t, err)

	// Attempt to import with same ScriptPubKey (should fail).
	_, err = store.NewImportedAddress(t.Context(), params)
	require.Error(t, err)
	require.ErrorContains(t, err, "constraint")
	require.ErrorContains(t, err, "script_pub_key")
}

// TestNewImportedAddressDuplicateAcrossScopes verifies that imported-address
// creation rejects the same script pubkey across different imported scopes in
// one wallet.
func TestNewImportedAddressDuplicateAcrossScopes(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	// ADR 0012: imported addresses without private-key material require
	// a watch-only wallet to satisfy the symmetric invariant.
	walletID := newWatchOnlyWallet(
		t, store, "wallet-duplicate-import-cross-scope",
	)

	scriptPubKey := RandomBytes(32)

	_, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:     walletID,
			Scope:        db.KeyScopeBIP0044,
			AddressType:  db.PubKeyHash,
			PubKey:       RandomBytes(33),
			ScriptPubKey: scriptPubKey,
		},
	)
	require.NoError(t, err)

	_, err = store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:     walletID,
			Scope:        db.KeyScopeBIP0084,
			AddressType:  db.WitnessPubKey,
			PubKey:       RandomBytes(33),
			ScriptPubKey: scriptPubKey,
		},
	)
	require.Error(t, err)
	require.ErrorContains(t, err, "constraint")
	require.ErrorContains(t, err, "script_pub_key")
}

// TestNewImportedAddressDuplicateAcrossWallets verifies that wallet-scoped
// uniqueness allows the same script pubkey to be imported into different
// wallets.
func TestNewImportedAddressDuplicateAcrossWallets(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	// ADR 0012: imported addresses without private-key material require
	// watch-only wallets to satisfy the symmetric invariant.
	firstWalletID := newWatchOnlyWallet(
		t, store, "wallet-duplicate-import-a",
	)
	secondWalletID := newWatchOnlyWallet(
		t, store, "wallet-duplicate-import-b",
	)

	scriptPubKey := RandomBytes(32)

	_, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:     firstWalletID,
			Scope:        db.KeyScopeBIP0084,
			AddressType:  db.WitnessPubKey,
			PubKey:       RandomBytes(33),
			ScriptPubKey: scriptPubKey,
		},
	)
	require.NoError(t, err)

	info, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:     secondWalletID,
			Scope:        db.KeyScopeBIP0084,
			AddressType:  db.WitnessPubKey,
			PubKey:       RandomBytes(33),
			ScriptPubKey: scriptPubKey,
		},
	)
	require.NoError(t, err)
	require.NotZero(t, info.ID)
	require.NotZero(t, info.AccountID)
}

// TestCreateImportedAddressRejectsWalletAccountMismatch verifies that the
// composite wallet/account invariant is enforced by the database on direct
// imported-address inserts.
func TestCreateImportedAddressRejectsWalletAccountMismatch(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	firstWalletID := newWallet(t, store, "wallet-raw-import-mismatch-a")
	secondWalletID := newWallet(t, store, "wallet-raw-import-mismatch-b")

	// Materialize the keyless bucket in the first wallet via a real import
	// so its account row exists for the raw-insert mismatch below.
	_, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:            firstWalletID,
			Scope:               db.KeyScopeBIP0084,
			AddressType:         db.WitnessPubKey,
			PubKey:              RandomBytes(33),
			ScriptPubKey:        RandomBytes(32),
			EncryptedPrivateKey: RandomBytes(32),
		},
	)
	require.NoError(t, err)

	firstScopeID := GetKeyScopeID(t, queries, firstWalletID, db.KeyScopeBIP0084)
	firstAccountID := GetAccountID(t, queries, firstScopeID, "imported")

	err = createImportedAddressRaw(
		t.Context(), queries, secondWalletID, firstAccountID, RandomBytes(32),
	)
	require.Error(t, err)
	require.ErrorContains(t, err, "constraint")
}

// TestCreateDerivedAddressRejectsWalletAccountMismatch verifies that the
// composite wallet/account invariant is enforced by the database on direct
// derived-address inserts.
func TestCreateDerivedAddressRejectsWalletAccountMismatch(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	firstWalletID := newWallet(t, store, "wallet-raw-derived-mismatch-a")
	secondWalletID := newWallet(t, store, "wallet-raw-derived-mismatch-b")
	accountName := "raw-derived"

	createDerivedAccount(
		t, store, firstWalletID, db.KeyScopeBIP0084, accountName,
	)
	createDerivedAccount(
		t, store, secondWalletID, db.KeyScopeBIP0084, accountName,
	)

	firstScopeID := GetKeyScopeID(t, queries, firstWalletID, db.KeyScopeBIP0084)
	firstAccountID := GetAccountID(t, queries, firstScopeID, accountName)

	err := createDerivedAddressRaw(
		t, queries, secondWalletID, firstAccountID, 0, 0, RandomBytes(20),
	)
	require.Error(t, err)
	require.ErrorContains(t, err, "constraint")
}

// TestAddressWalletIDImmutable verifies that raw address reparenting updates
// cannot change wallet ownership after insert.
func TestAddressWalletIDImmutable(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	// ADR 0012: public-only imported addresses need watch-only wallets
	// to satisfy the symmetric invariant.
	sourceWalletID := newWatchOnlyWallet(
		t, store, "address-wallet-immutable-source",
	)
	targetWalletID := newWatchOnlyWallet(
		t, store, "address-wallet-immutable-target",
	)

	scriptPubKey := RandomBytes(32)
	info, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:     sourceWalletID,
			Scope:        db.KeyScopeBIP0084,
			AddressType:  db.WitnessPubKey,
			PubKey:       RandomBytes(33),
			ScriptPubKey: scriptPubKey,
		},
	)
	require.NoError(t, err)

	// Materialize the target wallet's bucket via a real import so its
	// account row exists for the raw reparent attempt below.
	_, err = store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:     targetWalletID,
			Scope:        db.KeyScopeBIP0084,
			AddressType:  db.WitnessPubKey,
			PubKey:       RandomBytes(33),
			ScriptPubKey: RandomBytes(32),
		},
	)
	require.NoError(t, err)

	targetScopeID := GetKeyScopeID(
		t, queries, targetWalletID, db.KeyScopeBIP0084,
	)
	targetAccountID := GetAccountID(
		t, queries, targetScopeID, "imported",
	)

	err = reparentAddressRaw(
		t, store.DB(), int64(info.ID), targetWalletID, targetAccountID,
	)
	require.Error(t, err)
	requireDriverConstraintError(t, err)

	addressInfo, err := store.GetAddress(
		t.Context(), db.GetAddressQuery{
			WalletID:     sourceWalletID,
			ScriptPubKey: scriptPubKey,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, addressInfo)
	require.Equal(t, info.ID, addressInfo.ID)
}

// TestGetAddressSecret verifies that GetAddressSecret correctly retrieves
// address secrets for watch-only imported addresses and returns an error for
// spendable addresses or non-existent address IDs.
func TestGetAddressSecret(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	testCases := []struct {
		name              string
		providePrivateKey bool
		shouldHaveSecret  bool
	}{
		{
			name:              "spendable import",
			providePrivateKey: true,
			shouldHaveSecret:  true,
		},
		{
			name:              "watch-only import",
			providePrivateKey: false,
			shouldHaveSecret:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			walletID := importedAddressWallet(
				t, store, "wallet-secrets-"+tc.name,
				tc.providePrivateKey,
			)

			params := db.NewImportedAddressParams{
				WalletID:     walletID,
				Scope:        db.KeyScopeBIP0044,
				AddressType:  db.PubKeyHash,
				PubKey:       RandomBytes(33),
				ScriptPubKey: RandomBytes(32),
			}

			if tc.providePrivateKey {
				params.EncryptedPrivateKey = RandomBytes(32)
			}

			info, errNewAddr := store.NewImportedAddress(t.Context(), params)
			require.NoError(t, errNewAddr)

			if tc.shouldHaveSecret {
				secret, err := store.GetAddressSecret(
					t.Context(), db.GetAddressSecretQuery{
						WalletID:  walletID,
						AddressID: info.ID,
					},
				)
				require.NoError(t, err)
				require.NotNil(t, secret)
				require.Equal(t, info.ID, secret.AddressID)
				require.Equal(
					t, params.EncryptedPrivateKey, secret.EncryptedPrivKey,
				)
				require.Empty(t, secret.EncryptedScript)
			} else {
				_, err := store.GetAddressSecret(
					t.Context(), db.GetAddressSecretQuery{
						WalletID:  walletID,
						AddressID: info.ID,
					},
				)
				require.ErrorIs(t, err, db.ErrSecretNotFound)
			}
		})
	}

	t.Run("cross-wallet address denied", func(t *testing.T) {
		walletID := newWallet(t, store, "wallet-secrets-cross-self")

		otherWalletID := newWallet(t, store, "wallet-secrets-other")

		params := db.NewImportedAddressParams{
			WalletID:            walletID,
			Scope:               db.KeyScopeBIP0044,
			AddressType:         db.PubKeyHash,
			PubKey:              RandomBytes(33),
			ScriptPubKey:        RandomBytes(32),
			EncryptedPrivateKey: RandomBytes(32),
		}

		info, err := store.NewImportedAddress(t.Context(), params)
		require.NoError(t, err)

		_, err = store.GetAddressSecret(
			t.Context(), db.GetAddressSecretQuery{
				WalletID:  otherWalletID,
				AddressID: info.ID,
			},
		)
		require.ErrorIs(t, err, db.ErrAddressNotFound)
	})

	// Test non-existent address ID.
	t.Run("non-existent address", func(t *testing.T) {
		walletID := newWallet(t, store, "wallet-secrets-nonexistent")

		_, err := store.GetAddressSecret(
			t.Context(), db.GetAddressSecretQuery{
				WalletID:  walletID,
				AddressID: 999999,
			},
		)
		require.ErrorIs(t, err, db.ErrAddressNotFound)
	})
}

// TestGetAddress verifies that GetAddress correctly retrieves addresses by
// ID and by encrypted script pubkey, and returns appropriate errors for
// invalid or non-existent queries.
func TestGetAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setupFunc func(t *testing.T, addrStore db.AddressStore,
			accountStore db.AccountStore, walletID uint32) db.GetAddressQuery
		watchOnlyWallet bool
		wantErr         error
		validate        func(t *testing.T, addr *db.AddressInfo)
	}{
		{
			name:            "get by encrypted script pubkey",
			watchOnlyWallet: true,
			setupFunc: func(t *testing.T, addrStore db.AddressStore,
				accountStore db.AccountStore,
				walletID uint32) db.GetAddressQuery {

				t.Helper()

				script := RandomBytes(32)
				params := db.NewImportedAddressParams{
					WalletID:     walletID,
					Scope:        db.KeyScopeBIP0084,
					AddressType:  db.WitnessPubKey,
					PubKey:       RandomBytes(33),
					ScriptPubKey: script,
				}
				_, err := addrStore.NewImportedAddress(t.Context(), params)
				require.NoError(t, err)

				return db.GetAddressQuery{
					WalletID:     walletID,
					ScriptPubKey: script,
				}
			},
			validate: func(t *testing.T, addr *db.AddressInfo) {
				t.Helper()

				require.NotNil(t, addr.ScriptPubKey)
				require.Equal(t, db.ImportedAccount, addr.Origin)
				require.True(t, addr.IsWatchOnly)
			},
		},
		{
			name: "get imported address with private key",
			setupFunc: func(t *testing.T, addrStore db.AddressStore,
				accountStore db.AccountStore,
				walletID uint32) db.GetAddressQuery {

				t.Helper()

				script := RandomBytes(32)
				params := db.NewImportedAddressParams{
					WalletID:            walletID,
					Scope:               db.KeyScopeBIP0084,
					AddressType:         db.WitnessPubKey,
					PubKey:              RandomBytes(33),
					ScriptPubKey:        script,
					EncryptedPrivateKey: RandomBytes(32),
				}
				_, err := addrStore.NewImportedAddress(t.Context(), params)
				require.NoError(t, err)

				return db.GetAddressQuery{
					WalletID:     walletID,
					ScriptPubKey: script,
				}
			},
			validate: func(t *testing.T, addr *db.AddressInfo) {
				t.Helper()
				require.NotNil(t, addr.ScriptPubKey)
				require.Equal(t, db.ImportedAccount, addr.Origin)
				require.False(t, addr.IsWatchOnly)
			},
		},
		{
			name: "address not found by script",
			setupFunc: func(_ *testing.T, _ db.AddressStore,
				_ db.AccountStore, walletID uint32) db.GetAddressQuery {

				return db.GetAddressQuery{
					WalletID:     walletID,
					ScriptPubKey: RandomBytes(32),
				}
			},
			wantErr: db.ErrAddressNotFound,
		},
		{
			name: "invalid query - empty script pubkey",
			setupFunc: func(_ *testing.T, _ db.AddressStore,
				_ db.AccountStore, walletID uint32) db.GetAddressQuery {

				return db.GetAddressQuery{
					WalletID:     walletID,
					ScriptPubKey: nil,
				}
			},
			wantErr: db.ErrInvalidAddressQuery,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewTestStore(t)

			var walletID uint32
			if tc.watchOnlyWallet {
				walletID = newWatchOnlyWallet(
					t, store, tc.name+"-wallet",
				)
			} else {
				walletID = newWallet(t, store, tc.name+"-wallet")
			}

			query := tc.setupFunc(t, store, store, walletID)
			addr, err := store.GetAddress(t.Context(), query)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, addr)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, addr)

			if tc.validate != nil {
				tc.validate(t, addr)
			}
		})
	}
}

// TestListAddresses verifies that ListAddresses correctly returns addresses
// with page-contract behavior, filters by scope appropriately, and handles
// empty results without error.
func TestListAddresses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setupFunc func(t *testing.T, addrStore db.AddressStore,
			accountStore db.AccountStore, walletID uint32) db.ListAddressesQuery
		wantCount int
		wantErr   error
		validate  func(t *testing.T, addrs []db.AddressInfo)
	}{
		{
			name: "list multiple addresses for account",
			setupFunc: func(t *testing.T, addrStore db.AddressStore,
				accountStore db.AccountStore,
				walletID uint32) db.ListAddressesQuery {

				t.Helper()

				createDerivedAccount(
					t, accountStore, walletID, db.KeyScopeBIP0044,
					"test-account",
				)

				createDerivedAddresses(
					t, addrStore, walletID, db.KeyScopeBIP0044,
					"test-account",
					false, 5,
				)

				return db.ListAddressesQuery{
					WalletID:    walletID,
					Scope:       db.KeyScopeBIP0044,
					AccountName: "test-account",
					Page:        newTestReq[uint32](t, 10),
				}
			},
			wantCount: 5,
			validate: func(t *testing.T, addrs []db.AddressInfo) {
				t.Helper()

				require.Len(t, addrs, 5)
				for i, addr := range addrs {
					require.Equal(t, uint32(i), addr.Index)
					require.Equal(t, uint32(0), addr.Branch)
					require.Equal(t, db.DerivedAccount, addr.Origin)
					require.False(t, addr.IsWatchOnly)
					require.Equal(t, uint32(0), addr.AccountNumber)
					require.Equal(t, "test-account", addr.AccountName)
					require.Equal(t, db.KeyScopeBIP0044, addr.KeyScope)
					require.Equal(
						t, uint32(0xC0DEC0DE),
						addr.MasterKeyFingerprint,
					)
				}

				require.False(t, addrs[0].IsWatchOnly)
			},
		},

		{
			name: "list addresses - empty result",
			setupFunc: func(t *testing.T, _ db.AddressStore,
				accountStore db.AccountStore,
				walletID uint32) db.ListAddressesQuery {

				t.Helper()

				createDerivedAccount(
					t, accountStore, walletID, db.KeyScopeBIP0084,
					"empty-account",
				)

				return db.ListAddressesQuery{
					WalletID:    walletID,
					Scope:       db.KeyScopeBIP0084,
					AccountName: "empty-account",
					Page:        newTestReq[uint32](t, 10),
				}
			},
			wantCount: 0,
		},
		{
			name: "list addresses filters by scope correctly",
			setupFunc: func(t *testing.T, addrStore db.AddressStore,
				accountStore db.AccountStore,
				walletID uint32) db.ListAddressesQuery {

				t.Helper()

				// Create accounts in different scopes.
				createDerivedAccount(
					t, accountStore, walletID, db.KeyScopeBIP0044,
					"bip44-multi",
				)
				createDerivedAccount(
					t, accountStore, walletID, db.KeyScopeBIP0049Plus,
					"bip49-multi",
				)

				createDerivedAddresses(
					t, addrStore, walletID, db.KeyScopeBIP0044,
					"bip44-multi",
					false, 3,
				)

				createDerivedAddresses(
					t, addrStore, walletID, db.KeyScopeBIP0049Plus,
					"bip49-multi",
					false, 2,
				)

				// Query only BIP0044 scope.
				return db.ListAddressesQuery{
					WalletID:    walletID,
					Scope:       db.KeyScopeBIP0044,
					AccountName: "bip44-multi",
					Page:        newTestReq[uint32](t, 10),
				}
			},
			wantCount: 3,
			validate: func(t *testing.T, addrs []db.AddressInfo) {
				t.Helper()

				require.Len(t, addrs, 3)
				for _, addr := range addrs {
					require.Equal(t, db.DerivedAccount, addr.Origin)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewTestStore(t)
			walletID := newWallet(t, store, tc.name+"-wallet")

			query := tc.setupFunc(t, store, store, walletID)
			pageResult, err := store.ListAddresses(t.Context(), query)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)

			addrs := pageResult.Items
			require.Len(t, addrs, tc.wantCount)

			if tc.validate != nil {
				tc.validate(t, addrs)
			}
		})
	}
}

// TestListAddressesZeroLimit verifies ListAddresses rejects a zero page limit.
func TestListAddressesZeroLimit(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-addresses-zero-limit")

	_, err := store.ListAddresses(t.Context(), db.ListAddressesQuery{
		WalletID:    walletID,
		Scope:       db.KeyScopeBIP0044,
		AccountName: "test-account",
	})
	require.ErrorIs(t, err, db.ErrInvalidPageLimit)
}

// TestListAddressesWatchOnlyWallet verifies that ListAddresses preserves the
// watch-only flag for derived addresses from a watch-only wallet.
func TestListAddressesWatchOnlyWallet(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	walletInfo, err := store.CreateWallet(
		t.Context(), CreateWatchOnlyWalletParams("watch-only-list-wallet"),
	)
	require.NoError(t, err)

	_, err = store.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID: walletInfo.ID,
			Scope:    db.KeyScopeBIP0084,
			Name:     "watch-only-account",
		},
		SpendableDeriveFn(),
	)
	require.NoError(t, err)

	createDerivedAddresses(
		t, store, walletInfo.ID, db.KeyScopeBIP0084, "watch-only-account",
		false, 3,
	)

	pageResult, err := store.ListAddresses(
		t.Context(), db.ListAddressesQuery{
			WalletID:    walletInfo.ID,
			Scope:       db.KeyScopeBIP0084,
			AccountName: "watch-only-account",
			Page:        newTestReq[uint32](t, 10),
		},
	)
	require.NoError(t, err)

	addrs := pageResult.Items
	require.Len(t, addrs, 3)

	for _, addr := range addrs {
		require.Equal(t, db.DerivedAccount, addr.Origin)
	}

	require.True(t, addrs[0].IsWatchOnly)
}

// TestNewDerivedAddress verifies that NewDerivedAddress correctly creates
// derived addresses with proper AddressInfo fields for both external and
// change addresses.
func TestNewDerivedAddress(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-derived")

	// Create account in BIP44 scope.
	accountName := "derived-test"
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0044, accountName)
	account := getAccountByName(
		t, store, walletID, db.KeyScopeBIP0044, accountName,
	)

	testCases := []struct {
		name           string
		change         bool
		expectedBranch uint32
	}{
		{
			name:           "external address",
			change:         false,
			expectedBranch: 0,
		},
		{
			name:           "change address",
			change:         true,
			expectedBranch: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info := newDerivedAddress(
				t, store, walletID, db.KeyScopeBIP0044, accountName, tc.change,
			)

			// Verify AddressInfo fields.
			require.NotZero(t, info.ID)
			require.NotZero(t, info.AccountID)
			require.Equal(t, db.DerivedAccount, info.Origin)
			require.NotZero(t, info.CreatedAt)
			require.Equal(t, tc.expectedBranch, info.Branch)
			require.NotNil(t, info.ScriptPubKey)
			require.Nil(t, info.PubKey)
			require.Equal(t, account.AccountNumber, info.AccountNumber)
			require.Equal(t, account.AccountName, info.AccountName)
			require.Equal(t, account.KeyScope, info.KeyScope)
			require.Equal(
				t, account.MasterKeyFingerprint,
				info.MasterKeyFingerprint,
			)
		})
	}
}

// TestNewDerivedAddressUsesStoredScopeSchema verifies that derived addresses
// use the address schema persisted on the key scope instead of recomputing the
// default schema from the scope tuple.
func TestNewDerivedAddressUsesStoredScopeSchema(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-derived-stored-schema")

	strictBIP49 := &db.ScopeAddrSchema{
		ExternalAddrType: db.NestedWitnessPubKey,
		InternalAddrType: db.NestedWitnessPubKey,
	}

	_, err := store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			WalletID:            walletID,
			Scope:               db.KeyScopeBIP0049Plus,
			Name:                "strict-bip49-import",
			PublicKey:           RandomBytes(32),
			EncryptedPrivateKey: RandomBytes(32),
			AddrSchema:          strictBIP49,
		},
	)
	require.NoError(t, err)

	accountName := "derived-on-strict-bip49"
	createDerivedAccount(
		t, store, walletID, db.KeyScopeBIP0049Plus, accountName,
	)

	info := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0049Plus, accountName, true,
	)
	require.Equal(t, db.NestedWitnessPubKey, info.AddrType)
}

// TestNewDerivedAddressDerivesByAccountNumber verifies that the derivation
// callback receives the BIP44 account number, not the SQL account row ID.
func TestNewDerivedAddressDerivesByAccountNumber(t *testing.T) {
	t.Parallel()

	var derivedAccountNumber uint32

	baseDerive := mockDeriveFunc()
	deriveFn := func(ctx context.Context,
		params db.AddressDerivationParams) (*db.DerivedAddressData, error) {

		derivedAccountNumber = params.AccountNumber

		return baseDerive(ctx, params)
	}

	store := NewTestStoreWithDerive(t, deriveFn)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-derived-account-number")

	createDerivedAccount(
		t, store, walletID, db.KeyScopeBIP0084, "first-account",
	)

	scopeID := GetKeyScopeID(t, queries, walletID, db.KeyScopeBIP0084)

	const accountNumber uint32 = 17

	accountName := "account-number-17"
	CreateAccountWithNumber(t, queries, scopeID, accountNumber, accountName)

	info, err := store.NewDerivedAddress(
		t.Context(), db.NewDerivedAddressParams{
			WalletID:    walletID,
			Scope:       db.KeyScopeBIP0084,
			AccountName: accountName,
		},
	)
	require.NoError(t, err)

	require.NotEqual(t, info.AccountID, info.AccountNumber)
	require.Equal(t, accountNumber, info.AccountNumber)
	require.Equal(t, accountNumber, derivedAccountNumber)
}

// TestNewDerivedAddressOnImportedAccount verifies that an imported xpub
// account can derive addresses through the store even though its
// accounts.account_number column is NULL. The derivation callback uses
// AccountPubKey from the imported account; AccountNumber is 0 because no
// BIP44 number applies to imported xpub accounts.
//
// Regression for the rejection that returns ErrNilDBAccountNumber when an
// imported xpub account row reaches NewDerivedAddressWithTx — the store
// now tolerates NULL account_number and passes 0 through to the callback.
func TestNewDerivedAddressOnImportedAccount(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	// ADR 0012: a public-only xpub import requires a watch-only wallet;
	// the spendable-wallet invariant rejects the same import.
	walletID := newWatchOnlyWallet(
		t, store, "wallet-imported-derive",
	)

	// Create an imported xpub account: real PublicKey, no encrypted
	// private key (watch-only xpub import).
	name := "imported-xpub"
	_, err := store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			WalletID:  walletID,
			Name:      name,
			Scope:     db.KeyScopeBIP0084,
			PublicKey: RandomBytes(32),
		},
	)
	require.NoError(t, err)

	info, err := store.NewDerivedAddress(
		t.Context(), db.NewDerivedAddressParams{
			WalletID:    walletID,
			Scope:       db.KeyScopeBIP0084,
			AccountName: name,
			Change:      false,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, info)

	// AddressInfo.Origin is the address-level origin set by
	// createDerivedAddress (always DerivedAccount); the imported-account
	// signal here is AccountNumber == 0 paired with a non-nil
	// AccountInfo.PublicKey at lookup time.
	require.Equal(t, db.DerivedAccount, info.Origin)
	require.Zero(t, info.AccountNumber)
}

// TestNewDerivedAddressDerivationGuards verifies that NewDerivedAddress returns
// errors instead of panicking when the derivation callback is nil or returns
// nil derived data.
func TestNewDerivedAddressDerivationGuards(t *testing.T) {
	t.Parallel()

	t.Run("nil derive callback", func(t *testing.T) {
		store := NewTestStoreWithDerive(t, nil)
		walletID := newWallet(t, store, "wallet-derived-nil-derive")
		accountName := "derived-guard-test"
		createDerivedAccount(
			t, store, walletID, db.KeyScopeBIP0084, accountName,
		)

		params := db.NewDerivedAddressParams{
			WalletID:    walletID,
			Scope:       db.KeyScopeBIP0084,
			AccountName: accountName,
			Change:      false,
		}

		var (
			info *db.AddressInfo
			err  error
		)

		require.NotPanics(
			t, func() {
				info, err = store.NewDerivedAddress(t.Context(), params)
			},
		)

		require.Nil(t, info)
		require.Error(t, err)
	})

	t.Run("nil derived data", func(t *testing.T) {
		deriveFn := func(context.Context,
			db.AddressDerivationParams) (*db.DerivedAddressData, error) {

			//nolint:nilnil // Intentionally exercise nil-data success guard.
			return nil, nil
		}
		store := NewTestStoreWithDerive(t, deriveFn)
		walletID := newWallet(t, store, "wallet-derived-nil-data")
		accountName := "derived-guard-test"
		createDerivedAccount(
			t, store, walletID, db.KeyScopeBIP0084, accountName,
		)

		params := db.NewDerivedAddressParams{
			WalletID:    walletID,
			Scope:       db.KeyScopeBIP0084,
			AccountName: accountName,
			Change:      false,
		}

		var (
			info *db.AddressInfo
			err  error
		)

		require.NotPanics(
			t, func() {
				info, err = store.NewDerivedAddress(t.Context(), params)
			},
		)

		require.Nil(t, info)
		require.Error(t, err)
	})
}

// TestNewImportedAddressAutoCreatesAndReusesBucket verifies that importing an
// address into a scope with no "imported" account auto-creates the keyless
// wallet-level bucket, and that a second import into the same scope reuses
// that bucket rather than creating a duplicate account.
func TestNewImportedAddressAutoCreatesAndReusesBucket(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "test-wallet")
	scope := db.KeyScopeBIP0084

	// First import into the scope. No "imported" account exists yet, so the
	// bucket must be auto-created.
	first, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:            walletID,
			Scope:               scope,
			AddressType:         db.WitnessPubKey,
			PubKey:              RandomBytes(33),
			EncryptedPrivateKey: RandomBytes(32),
			ScriptPubKey:        RandomBytes(32),
		},
	)
	require.NoError(t, err)
	require.Equal(t, db.ImportedAccount, first.Origin)
	require.Equal(t, db.DefaultImportedAccountName, first.AccountName)

	// The bucket is keyless: it must carry no account-level key material.
	bucket, err := store.GetAccount(
		t.Context(), getAccountQueryByName(
			walletID, scope, db.DefaultImportedAccountName,
		),
	)
	require.NoError(t, err)
	require.Equal(t, db.ImportedAccount, bucket.Origin)
	require.Empty(t, bucket.PublicKey)
	require.Zero(t, bucket.MasterKeyFingerprint)
	require.False(t, bucket.IsWatchOnly)

	bucketID := GetAccountID(
		t, queries, GetKeyScopeID(t, queries, walletID, scope),
		db.DefaultImportedAccountName,
	)
	require.EqualValues(t, bucketID, first.AccountID)

	// Second import into the same scope must reuse the same bucket, not
	// create a duplicate account.
	second, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:            walletID,
			Scope:               scope,
			AddressType:         db.WitnessPubKey,
			PubKey:              RandomBytes(33),
			EncryptedPrivateKey: RandomBytes(32),
			ScriptPubKey:        RandomBytes(32),
		},
	)
	require.NoError(t, err)
	require.Equal(t, first.AccountID, second.AccountID)

	// Exactly one "imported" account exists in this wallet/scope.
	accounts, err := store.ListAccounts(
		t.Context(), db.ListAccountsQuery{
			WalletID: walletID,
			Scope:    &scope,
		},
	)
	require.NoError(t, err)

	var importedCount int
	for _, acct := range accounts {
		if acct.AccountName == db.DefaultImportedAccountName {
			importedCount++
		}
	}

	require.Equal(t, 1, importedCount)
}

// TestNewImportedAddressBucketIsScopeIsolated verifies that the imported
// bucket is per-scope: a bucket auto-created in one scope is not reused for an
// import into a different scope of the same wallet. The second import
// auto-creates a distinct bucket rather than failing.
func TestNewImportedAddressBucketIsScopeIsolated(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-import-scope-isolated")

	// First import auto-creates the bucket in BIP0044.
	bip44, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:            walletID,
			Scope:               db.KeyScopeBIP0044,
			AddressType:         db.PubKeyHash,
			PubKey:              RandomBytes(33),
			ScriptPubKey:        RandomBytes(32),
			EncryptedPrivateKey: RandomBytes(32),
		},
	)
	require.NoError(t, err)

	// Importing into BIP0084 must not reuse the BIP0044 bucket; it
	// auto-creates a separate bucket in the BIP0084 scope.
	bip84, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:            walletID,
			Scope:               db.KeyScopeBIP0084,
			AddressType:         db.WitnessPubKey,
			PubKey:              RandomBytes(33),
			ScriptPubKey:        RandomBytes(32),
			EncryptedPrivateKey: RandomBytes(32),
		},
	)
	require.NoError(t, err)

	require.Equal(t, db.DefaultImportedAccountName, bip44.AccountName)
	require.Equal(t, db.DefaultImportedAccountName, bip84.AccountName)
	require.NotEqual(t, bip44.AccountID, bip84.AccountID)
}

// TestGetAddressSecret_DerivedAddress verifies that calling GetAddressSecret
// on a derived address returns db.ErrSecretNotFound (not ErrAddressNotFound).
// This validates the LEFT JOIN: derived addresses exist in the addresses
// table but have no corresponding row in address_secrets. The query returns a
// row with NULL encrypted_priv_key, and the converter returns
// ErrSecretNotFound.
func TestGetAddressSecret_DerivedAddress(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "test-wallet")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "test-account")

	params := db.NewDerivedAddressParams{
		WalletID:    walletID,
		AccountName: "test-account",
		Scope:       db.KeyScopeBIP0084,
		Change:      false,
	}
	addrInfo, err := store.NewDerivedAddress(
		t.Context(), params,
	)
	require.NoError(t, err)

	// Attempt to get secret for derived address.
	// Derived addresses have no row in address_secrets table.
	_, err = store.GetAddressSecret(
		t.Context(), db.GetAddressSecretQuery{
			WalletID:  walletID,
			AddressID: addrInfo.ID,
		},
	)

	// Expect ErrSecretNotFound (not ErrAddressNotFound) because the
	// LEFT JOIN returns a row with NULL encrypted_priv_key.
	require.ErrorIs(t, err, db.ErrSecretNotFound)
}

// TestNewDerivedAddressSequentialIndexes verifies that derived addresses
// receive sequential indexes 0, 1, 2, 3, 4 within the same account and
// branch.
func TestNewDerivedAddressSequentialIndexes(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-sequential-indexes")

	// Create derived account for the test.
	accountName := "sequential-test"
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, accountName)

	// Create 5 addresses in external branch and verify sequential indexes.
	for i := range 5 {
		info := newDerivedAddress(
			t, store, walletID, db.KeyScopeBIP0084, accountName, false,
		)
		require.NotNil(t, info)
		require.Equal(t, uint32(i), info.Index)
	}
}

// TestListAddressesOrdering verifies that ListAddresses returns addresses
// sorted by index in ascending order, with addresses grouped by branch.
func TestListAddressesOrdering(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-ordering")

	createDerivedAccount(
		t, store, walletID, db.KeyScopeBIP0084, "ordering-account",
	)

	createDerivedAddresses(
		t, store, walletID, db.KeyScopeBIP0084, "ordering-account", false, 3,
	)
	createDerivedAddresses(
		t, store, walletID, db.KeyScopeBIP0084, "ordering-account", true, 3,
	)

	pageResult, err := store.ListAddresses(
		t.Context(),
		db.ListAddressesQuery{
			WalletID:    walletID,
			Scope:       db.KeyScopeBIP0084,
			AccountName: "ordering-account",
			Page:        newTestReq[uint32](t, 10),
		},
	)

	require.NoError(t, err)

	addresses := pageResult.Items
	require.Len(t, addresses, 6)

	// Separate addresses by branch for verification.
	var (
		externalAddrs []db.AddressInfo
		changeAddrs   []db.AddressInfo
	)

	for _, addr := range addresses {
		if addr.Branch == 0 {
			externalAddrs = append(externalAddrs, addr)
		} else {
			changeAddrs = append(changeAddrs, addr)
		}
	}

	// Verify external addresses sorted by index.
	for i := 1; i < len(externalAddrs); i++ {
		require.LessOrEqual(
			t, externalAddrs[i-1].Index, externalAddrs[i].Index,
			"external addresses not in order",
		)
	}

	// Verify change addresses sorted by index.
	for i := 1; i < len(changeAddrs); i++ {
		require.LessOrEqual(
			t, changeAddrs[i-1].Index, changeAddrs[i].Index,
			"change addresses not in order",
		)
	}
}

// TestListAddressesPagination verifies that ListAddresses paginates correctly
// and sets Next without requiring an extra round-trip.
func TestListAddressesPagination(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-addresses-strong-mode")
	scope := db.KeyScopeBIP0084

	createDerivedAccount(t, store, walletID, scope, "account-a")
	createDerivedAccount(t, store, walletID, scope, "account-b")

	accountA := createDerivedAddresses(
		t, store, walletID, scope, "account-a", false, 5,
	)
	createDerivedAddresses(t, store, walletID, scope, "account-b", false, 2)

	query := db.ListAddressesQuery{
		WalletID:    walletID,
		Scope:       scope,
		AccountName: "account-a",
		Page:        newTestReq[uint32](t, 2),
	}

	page1, err := store.ListAddresses(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, page1.Items, 2)
	require.Equal(t, accountA[:2], page1.Items)
	require.NotNil(t, page1.Next)

	query.Page.After = page1.Next
	page2, err := store.ListAddresses(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, page2.Items, 2)
	require.Equal(t, accountA[2:4], page2.Items)
	require.NotNil(t, page2.Next)

	query.Page.After = page2.Next
	page3, err := store.ListAddresses(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, page3.Items, 1)
	require.Equal(t, accountA[4:], page3.Items)
	require.Nil(t, page3.Next)

	query.Page.After = uint32Ptr(page3.Items[len(page3.Items)-1].ID)
	page4, err := store.ListAddresses(t.Context(), query)
	require.NoError(t, err)
	require.Empty(t, page4.Items)
	require.Nil(t, page4.Next)

	paged := append([]db.AddressInfo{}, page1.Items...)
	paged = append(paged, page2.Items...)
	paged = append(paged, page3.Items...)
	require.Equal(t, accountA, paged)

	for i, addr := range paged {
		require.Equal(t, uint32(i), addr.Index)
		require.Equal(t, uint32(0), addr.Branch)
	}
}

// TestListAddressesExactBoundary verifies that pagination correctly handles
// the exact boundary case where total results equal page-size multiples.
func TestListAddressesExactBoundary(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "boundary-wallet")
	scope := db.KeyScopeBIP0084
	accountName := "boundary-account"

	createDerivedAccount(t, store, walletID, scope, accountName)
	expected := createDerivedAddresses(
		t, store, walletID, scope, accountName, false, 4,
	)

	query := db.ListAddressesQuery{
		WalletID:    walletID,
		Scope:       scope,
		AccountName: accountName,
		Page:        newTestReq[uint32](t, 2),
	}

	page1, err := store.ListAddresses(t.Context(), query)
	require.NoError(t, err)
	require.Equal(t, expected[:2], page1.Items)
	require.NotNil(t, page1.Next)
	require.Equal(t, page1.Items[1].ID, *page1.Next)

	query.Page.After = page1.Next
	page2, err := store.ListAddresses(t.Context(), query)
	require.NoError(t, err)
	require.Equal(t, expected[2:], page2.Items)
	require.Nil(t, page2.Next)
	require.Greater(t, page2.Items[0].ID, *page1.Next)

	query.Page.After = uint32Ptr(page2.Items[len(page2.Items)-1].ID)
	page3, err := store.ListAddresses(t.Context(), query)
	require.NoError(t, err)
	require.Empty(t, page3.Items)
	require.Nil(t, page3.Next)
}

// TestListAddressesPagedEmptyResult verifies that paginated ListAddresses
// returns an empty result with no cursor for an account with no addresses.
func TestListAddressesPagedEmptyResult(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-addresses-empty")
	scope := db.KeyScopeBIP0084
	pageSize := uint(2)

	createDerivedAccount(t, store, walletID, scope, "empty-account")

	pageResult, err := store.ListAddresses(t.Context(), db.ListAddressesQuery{
		WalletID:    walletID,
		Scope:       scope,
		AccountName: "empty-account",
		Page:        newTestReq[uint32](t, uint32(pageSize)),
	})
	require.NoError(t, err)
	require.Empty(t, pageResult.Items)
	require.Nil(t, pageResult.Next)
}

// TestListAddressesDeterministicPagination verifies stable ID-ordered address
// pagination and next-cursor behavior.
func TestListAddressesDeterministicPagination(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-address-deterministic")
	scope := db.KeyScopeBIP0084
	accountName := "deterministic-account"
	createDerivedAccount(t, store, walletID, scope, accountName)
	expected := createDerivedAddresses(
		t, store, walletID, scope, accountName, false, 5,
	)

	pages := collectAddressPages(t, store, db.ListAddressesQuery{
		WalletID:    walletID,
		Scope:       scope,
		AccountName: accountName,
		Page:        newTestReq[uint32](t, 2),
	})
	require.Len(t, pages, 3)
	require.Len(t, pages[0].Items, 2)
	require.Len(t, pages[1].Items, 2)
	require.Len(t, pages[2].Items, 1)
	require.NotNil(t, pages[0].Next)
	require.NotNil(t, pages[1].Next)
	require.Nil(t, pages[2].Next)

	addresses := flattenAddressPages(pages)
	require.Equal(t, expected, addresses)

	seenIDs := make(map[uint32]struct{}, len(addresses))
	for i := range pages {
		for j, addr := range pages[i].Items {
			_, duplicate := seenIDs[addr.ID]
			require.False(t, duplicate)

			seenIDs[addr.ID] = struct{}{}

			// Skip the first item on the first page; there's no prior cursor
			// to compare against.
			if i == 0 && j == 0 {
				continue
			}

			// First item on a later page: verify it sorts strictly after the
			// previous page's cursor to ensure no gaps or duplicates at page
			// boundaries.
			if j == 0 {
				require.Greater(t, addr.ID, *pages[i-1].Next)
				continue
			}

			// Items within the same page: verify strict ordering to ensure
			// the page contents are sorted.
			require.Greater(t, addr.ID, pages[i].Items[j-1].ID)
		}
	}

	for i := range addresses {
		if i == 0 {
			continue
		}

		require.Less(t, addresses[i-1].ID, addresses[i].ID)
	}
}

// TestListAddressesAccountIsolation verifies that ListAddresses returns only
// addresses for the requested account, excluding addresses from other accounts.
func TestListAddressesAccountIsolation(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-address-account-isolation")
	scope := db.KeyScopeBIP0084

	createDerivedAccount(t, store, walletID, scope, "account-a")
	createDerivedAccount(t, store, walletID, scope, "account-b")

	expected := createDerivedAddresses(
		t, store, walletID, scope, "account-a", false, 5,
	)
	otherAccount := createDerivedAddresses(
		t, store, walletID, scope, "account-b", false, 3,
	)

	pages := collectAddressPages(t, store, db.ListAddressesQuery{
		WalletID:    walletID,
		Scope:       scope,
		AccountName: "account-a",
		Page:        newTestReq[uint32](t, 2),
	})
	addresses := flattenAddressPages(pages)

	require.Len(t, addresses, len(expected))
	require.Equal(t, expected, addresses)
	accountAID := expected[0].AccountID

	accountBID := otherAccount[0].AccountID
	for _, addr := range addresses {
		require.Equal(t, accountAID, addr.AccountID)
		require.NotEqual(t, accountBID, addr.AccountID)
	}
}

// TestListAddressesInsertAfterCursor verifies inserts after page N are
// returned on page N+1 when pagination uses increasing ID cursors.
func TestListAddressesInsertAfterCursor(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-address-boundary-insert")
	scope := db.KeyScopeBIP0084
	accountName := "boundary-account"
	createDerivedAccount(t, store, walletID, scope, accountName)
	createDerivedAddresses(t, store, walletID, scope, accountName, false, 3)

	query := db.ListAddressesQuery{
		WalletID:    walletID,
		Scope:       scope,
		AccountName: accountName,
		Page:        newTestReq[uint32](t, 2),
	}
	page1, err := store.ListAddresses(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, page1.Items, 2)
	require.NotNil(t, page1.Next)

	// Pagination is by increasing address ID (id > cursor).
	// An address created after page 1 should therefore appear on page 2.
	inserted := newDerivedAddress(
		t, store, walletID, scope, accountName, false,
	)

	query.Page.After = page1.Next
	page2, err := store.ListAddresses(t.Context(), query)
	require.NoError(t, err)
	require.Len(t, page2.Items, 2)
	require.Equal(t, uint32(2), page2.Items[0].Index)
	require.Equal(t, inserted.ID, page2.Items[1].ID)
	require.Equal(t, uint32(3), page2.Items[1].Index)
	require.Nil(t, page2.Next)
}

// TestListAddressesCursorEdges verifies stale and zero-value cursors produce
// deterministic page results.
func TestListAddressesCursorEdges(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-address-cursor-edges")
	scope := db.KeyScopeBIP0084
	accountName := "cursor-account"
	createDerivedAccount(t, store, walletID, scope, accountName)
	createDerivedAddresses(t, store, walletID, scope, accountName, false, 3)

	staleReq := newTestReq[uint32](t, 2)
	staleReq.After = uint32Ptr(math.MaxUint32)

	stalePage, err := store.ListAddresses(t.Context(), db.ListAddressesQuery{
		WalletID:    walletID,
		Scope:       scope,
		AccountName: accountName,
		Page:        staleReq,
	})
	require.NoError(t, err)
	require.Empty(t, stalePage.Items)
	require.Nil(t, stalePage.Next)

	zeroReq := newTestReq[uint32](t, 2)
	zeroReq.After = uint32Ptr(0)

	zeroPage, err := store.ListAddresses(t.Context(), db.ListAddressesQuery{
		WalletID:    walletID,
		Scope:       scope,
		AccountName: accountName,
		Page:        zeroReq,
	})
	require.NoError(t, err)
	require.Len(t, zeroPage.Items, 2)
	require.Equal(t, uint32(0), zeroPage.Items[0].Index)
	require.Equal(t, uint32(1), zeroPage.Items[1].Index)
	require.NotNil(t, zeroPage.Next)
}

// TestIterAddresses verifies that IterAddresses yields the same addresses in
// the same order as manual cursor-based pagination.
func TestIterAddresses(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-iter-addresses")
	scope := db.KeyScopeBIP0084
	pageSize := uint(2)

	createDerivedAccount(t, store, walletID, scope, "iter-account")
	expected := createDerivedAddresses(
		t, store, walletID, scope, "iter-account", false, 5,
	)

	query := db.ListAddressesQuery{
		WalletID:    walletID,
		Scope:       scope,
		AccountName: "iter-account",
		Page:        newTestReq[uint32](t, uint32(pageSize)),
	}

	iterAddrs := make([]db.AddressInfo, 0, len(expected))
	for addr, err := range store.IterAddresses(t.Context(), query) {
		require.NoError(t, err)

		iterAddrs = append(iterAddrs, addr)
	}

	paged := flattenAddressPages(collectAddressPages(t, store, query))
	require.Equal(t, expected, paged)
	require.Equal(t, expected, iterAddrs)
	require.Equal(t, paged, iterAddrs)
}

// TestIterAddressesPaginated verifies that IterAddresses produces the same
// results as manual pagination and correctly signals end-of-list.
func TestIterAddressesPaginated(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-iter-addresses-early")
	scope := db.KeyScopeBIP0084

	createDerivedAccount(t, store, walletID, scope, "iter-account")
	createDerivedAddresses(
		t, store, walletID, scope, "iter-account", false, 4,
	)

	query := db.ListAddressesQuery{
		WalletID:    walletID,
		Scope:       scope,
		AccountName: "iter-account",
		Page:        newTestReq[uint32](t, 2),
	}

	pages := collectAddressPages(t, store, query)
	require.Len(t, pages, 2)
	require.NotNil(t, pages[0].Next)
	require.Nil(t, pages[1].Next)

	expected := flattenAddressPages(pages)

	iterAddrs := make([]db.AddressInfo, 0, len(expected))
	for addr, err := range store.IterAddresses(t.Context(), query) {
		require.NoError(t, err)

		iterAddrs = append(iterAddrs, addr)
	}

	require.Equal(t, expected, iterAddrs)
}

// TestIterAddressesEmpty verifies that IterAddresses correctly handles
// empty accounts without error and yields no addresses.
func TestIterAddressesEmpty(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-iter-addresses-empty")
	scope := db.KeyScopeBIP0084

	createDerivedAccount(t, store, walletID, scope, "empty-account")

	query := db.ListAddressesQuery{
		WalletID:    walletID,
		Scope:       scope,
		AccountName: "empty-account",
		Page:        newTestReq[uint32](t, 10),
	}

	for addr, err := range store.IterAddresses(t.Context(), query) {
		require.NoError(t, err)
		require.Failf(t, "unexpected address", "address=%v", addr)
	}
}

// TestNewDerivedAddressErrors verifies that NewDerivedAddress returns
// appropriate errors for invalid parameters, including non-existent
// accounts, unknown key scopes, and empty account names.
func TestNewDerivedAddressErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		params  db.NewDerivedAddressParams
		wantErr error
	}{
		{
			name: "non-existent account",
			params: db.NewDerivedAddressParams{
				Scope:       db.KeyScopeBIP0084,
				AccountName: "non-existent",
				Change:      false,
			},
			wantErr: db.ErrAccountNotFound,
		},
		{
			name: "empty account name",
			params: db.NewDerivedAddressParams{
				Scope:       db.KeyScopeBIP0044,
				AccountName: "",
				Change:      false,
			},
			wantErr: db.ErrAccountNotFound,
		},
		{
			name: "unknown key scope returns account not found",
			params: db.NewDerivedAddressParams{
				Scope: db.KeyScope{
					Purpose: 999,
					Coin:    999,
				},
				AccountName: "any-name",
				Change:      false,
			},
			wantErr: db.ErrAccountNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			store := NewTestStore(t)
			walletID := newWallet(t, store, tc.name+"-wallet")
			tc.params.WalletID = walletID

			info, err := store.NewDerivedAddress(
				t.Context(), tc.params,
			)
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, info)
		})
	}
}

// TestNewDerivedAddress_WalletAccountMismatch verifies that derived address
// creation rejects a wallet/scope/account lookup that resolves in another
// wallet but not in the caller's wallet.
func TestNewDerivedAddress_WalletAccountMismatch(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	firstWalletID := newWallet(t, store, "wallet-derived-mismatch-a")
	secondWalletID := newWallet(t, store, "wallet-derived-mismatch-b")
	accountName := "shared-name"

	createDerivedAccount(
		t, store, firstWalletID, db.KeyScopeBIP0084, accountName,
	)
	createDerivedAccount(
		t, store, secondWalletID, db.KeyScopeBIP0044, accountName,
	)

	info, err := store.NewDerivedAddress(
		t.Context(), db.NewDerivedAddressParams{
			WalletID:    secondWalletID,
			Scope:       db.KeyScopeBIP0084,
			AccountName: accountName,
			Change:      false,
		},
	)
	require.ErrorIs(t, err, db.ErrAccountNotFound)
	require.Nil(t, info)
}

// TestNewDerivedAddressConcurrent verifies that concurrent address
// creation produces unique sequential indexes without conflicts.
func TestNewDerivedAddressConcurrent(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "concurrent-wallet")

	accountName := "concurrent-account"
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, accountName)

	const workers = 20

	type deriveResult struct {
		info db.AddressInfo
		err  error
	}

	resultCh := make(chan deriveResult, workers)

	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	for range workers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			info, err := store.NewDerivedAddress(
				ctx, db.NewDerivedAddressParams{
					WalletID:    walletID,
					Scope:       db.KeyScopeBIP0084,
					AccountName: accountName,
					Change:      false,
				},
			)
			if err != nil {
				resultCh <- deriveResult{err: err}
				return
			}

			resultCh <- deriveResult{info: *info}
		}()
	}

	wg.Wait()
	close(resultCh)

	results := make([]db.AddressInfo, 0, workers)
	for result := range resultCh {
		require.NoError(t, result.err)
		results = append(results, result.info)
	}

	require.Len(t, results, workers)

	// Verify all indexes are unique and sequential.
	indexes := make([]uint32, workers)
	for i, addr := range results {
		indexes[i] = addr.Index
	}

	sort.Slice(indexes, func(i, j int) bool {
		return indexes[i] < indexes[j]
	})

	for i := range workers {
		require.Equal(t, uint32(i), indexes[i])
	}
}

// TestNewDerivedAddressBranchIsolation verifies that external (branch 0)
// and change (branch 1) addresses maintain independent sequential index
// counters within the same account.
func TestNewDerivedAddressBranchIsolation(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-branch-isolation")

	// Create derived account for the test.
	accountName := "branch-isolation-test"
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, accountName)

	// Create addresses alternating between branches:
	// external-0, change-0, external-1, change-1, external-2, change-2.
	externalAddrs := make([]db.AddressInfo, 0, 3)
	changeAddrs := make([]db.AddressInfo, 0, 3)

	for range 3 {
		// Create external address (branch 0).
		extInfo := newDerivedAddress(
			t, store, walletID, db.KeyScopeBIP0084, accountName, false,
		)
		externalAddrs = append(externalAddrs, *extInfo)

		// Create change address (branch 1).
		chgInfo := newDerivedAddress(
			t, store, walletID, db.KeyScopeBIP0084, accountName, true,
		)
		changeAddrs = append(changeAddrs, *chgInfo)
	}

	// Verify external addresses have indexes 0, 1, 2.
	for i, addr := range externalAddrs {
		require.Equal(t, uint32(i), addr.Index)
		require.Equal(t, uint32(0), addr.Branch)
	}

	// Verify change addresses have indexes 0, 1, 2.
	for i, addr := range changeAddrs {
		require.Equal(t, uint32(i), addr.Index)
		require.Equal(t, uint32(1), addr.Branch)
	}
}

// TestNewDerivedAddressAccountKeyCounts verifies that account key counts are
// derived from the next index counters for both external and internal branches.
func TestNewDerivedAddressAccountKeyCounts(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-account-key-counts")

	accountName := "counted-account"
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, accountName)

	createDerivedAddresses(
		t, store, walletID, db.KeyScopeBIP0084, accountName, false, 3,
	)
	createDerivedAddresses(
		t, store, walletID, db.KeyScopeBIP0084, accountName, true, 2,
	)

	account := getAccountByName(
		t, store, walletID, db.KeyScopeBIP0084, accountName,
	)
	require.Equal(t, uint32(3), account.ExternalKeyCount)
	require.Equal(t, uint32(2), account.InternalKeyCount)
	require.Zero(t, account.ImportedKeyCount)
}

// TestNewDerivedAddressBranchCounters verifies that external and internal
// counters advance independently when new addresses are created.
func TestNewDerivedAddressBranchCounters(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-branch-counters")

	accountName := "branch-counter-account"
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, accountName)

	newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, accountName, true,
	)

	account := getAccountByName(
		t, store, walletID, db.KeyScopeBIP0084, accountName,
	)
	require.Equal(t, uint32(0), account.ExternalKeyCount)
	require.Equal(t, uint32(1), account.InternalKeyCount)

	newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, accountName, false,
	)

	account = getAccountByName(
		t, store, walletID, db.KeyScopeBIP0084, accountName,
	)
	require.Equal(t, uint32(1), account.ExternalKeyCount)
	require.Equal(t, uint32(1), account.InternalKeyCount)
}

// TestNewDerivedAddressMaxIndex verifies that addresses can be created
// up to the maximum index (math.MaxUint32), but the next address creation
// fails due to overflow.
func TestNewDerivedAddressMaxIndex(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	dbConn := store.DB()
	walletID := newWallet(t, store, "wallet-max-index")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "max-acct")

	scopeID := GetKeyScopeID(t, queries, walletID, db.KeyScopeBIP0084)
	accountID := GetAccountID(t, queries, scopeID, "max-acct")

	// Insert address at MaxUint32 - 1
	CreateAddressWithIndex(t, queries, walletID, accountID, 0, math.MaxUint32-1)

	// Set the counter to MaxUint32 so the next allocation gives us MaxUint32
	UpdateAccountNextExternalIndex(t, dbConn, accountID, math.MaxUint32)

	// This should succeed with address index = MaxUint32.
	info := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "max-acct", false,
	)
	require.Equal(t, uint32(math.MaxUint32), info.Index)

	// This should fail; the next allocation would overflow
	// uint32.
	_, err := store.NewDerivedAddress(
		t.Context(), db.NewDerivedAddressParams{
			WalletID:    walletID,
			Scope:       db.KeyScopeBIP0084,
			AccountName: "max-acct",
			Change:      false,
		},
	)
	require.ErrorIs(t, err, db.ErrMaxAddressIndexReached)
}

// TestNewDerivedAddressMaxIndexInternal verifies that internal addresses can be
// created up to the maximum index (math.MaxUint32), but the next address
// creation fails due to overflow.
func TestNewDerivedAddressMaxIndexInternal(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	dbConn := store.DB()
	walletID := newWallet(t, store, "wallet-max-index-internal")
	createDerivedAccount(t, store, walletID, db.KeyScopeBIP0084, "max-acct")

	scopeID := GetKeyScopeID(t, queries, walletID, db.KeyScopeBIP0084)
	accountID := GetAccountID(t, queries, scopeID, "max-acct")

	// Insert address at MaxUint32 - 1 in the internal branch.
	CreateAddressWithIndex(t, queries, walletID, accountID, 1, math.MaxUint32-1)

	// Set the internal counter to MaxUint32 so the next allocation gives us
	// MaxUint32.
	UpdateAccountNextInternalIndex(t, dbConn, accountID, math.MaxUint32)

	// This should succeed with address index = MaxUint32.
	info := newDerivedAddress(
		t, store, walletID, db.KeyScopeBIP0084, "max-acct", true,
	)
	require.Equal(t, uint32(math.MaxUint32), info.Index)

	// This should fail; the next allocation would overflow uint32.
	_, err := store.NewDerivedAddress(
		t.Context(), db.NewDerivedAddressParams{
			WalletID:    walletID,
			Scope:       db.KeyScopeBIP0084,
			AccountName: "max-acct",
			Change:      true,
		},
	)
	require.ErrorIs(t, err, db.ErrMaxAddressIndexReached)
}
