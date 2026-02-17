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
	"github.com/stretchr/testify/require"
)

// mockDeriveFunc is a test helper that returns a mock AddressDerivationFunc
// for testing NewDerivedAddress. It generates deterministic script_pub_key
// values based on accountID, branch, and index to ensure uniqueness.
func mockDeriveFunc() db.AddressDerivationFunc {
	return func(ctx context.Context, accountID uint32, branch uint32,
		index uint32) (*db.DerivedAddressData, error) {

		scriptPubKey := make([]byte, 20)
		binary.BigEndian.PutUint32(scriptPubKey[0:4], accountID)
		binary.BigEndian.PutUint32(scriptPubKey[4:8], branch)
		binary.BigEndian.PutUint32(scriptPubKey[8:12], index)
		return &db.DerivedAddressData{
			ScriptPubKey: scriptPubKey,
		}, nil
	}
}

func newDerivedAddress(t *testing.T, store db.AddressStore, walletID uint32,
	scope db.KeyScope, accountName string, change bool) *db.AddressInfo {

	t.Helper()

	info, err := store.NewDerivedAddress(
		t.Context(), db.NewDerivedAddressParams{
			WalletID:    walletID,
			Scope:       scope,
			AccountName: accountName,
			Change:      change,
		}, mockDeriveFunc(),
	)
	require.NoError(t, err)

	return info
}

func createDerivedAddresses(t *testing.T, store db.AddressStore,
	walletID uint32, scope db.KeyScope, accountName string, change bool,
	count int) []db.AddressInfo {

	t.Helper()

	addresses := make([]db.AddressInfo, 0, count)
	for i := 0; i < count; i++ {
		info := newDerivedAddress(
			t, store, walletID, scope, accountName, change,
		)
		addresses = append(addresses, *info)
	}

	return addresses
}

func getAccountByName(t *testing.T, store db.AccountStore, walletID uint32,
	scope db.KeyScope, accountName string) *db.AccountInfo {

	t.Helper()

	account, err := store.GetAccount(
		t.Context(), getAccountQueryByName(walletID, scope, accountName),
	)
	require.NoError(t, err)

	return account
}

// TestNewImportedAddress verifies that NewImportedAddress correctly imports
// addresses of different types, both watch-only and spendable.
func TestNewImportedAddress(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-imported-addresses")

	createImportedAccount(t, store, walletID, db.KeyScopeBIP0044, "imported")
	createImportedAccount(t, store, walletID, db.KeyScopeBIP0084, "imported")
	createImportedAccount(t, store, walletID, db.KeyScopeBIP0086, "imported")

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
			name:              "P2PKH watch-only",
			addr:              p2pkhAddr,
			scope:             db.KeyScopeBIP0044,
			expectedAddrType:  db.PubKeyHash,
			providePrivateKey: false,
		},
		{
			name:              "P2PKH spendable",
			addr:              p2pkhAddr,
			scope:             db.KeyScopeBIP0044,
			expectedAddrType:  db.PubKeyHash,
			providePrivateKey: true,
		},
		{
			name:              "P2WPKH watch-only",
			addr:              p2wpkhAddr,
			scope:             db.KeyScopeBIP0084,
			expectedAddrType:  db.WitnessPubKey,
			providePrivateKey: false,
		},
		{
			name:              "P2WPKH spendable",
			addr:              p2wpkhAddr,
			scope:             db.KeyScopeBIP0084,
			expectedAddrType:  db.WitnessPubKey,
			providePrivateKey: true,
		},
		{
			name:              "P2TR watch-only",
			addr:              p2trAddr,
			scope:             db.KeyScopeBIP0086,
			expectedAddrType:  db.TaprootPubKey,
			providePrivateKey: false,
		},
		{
			name:              "P2TR spendable",
			addr:              p2trAddr,
			scope:             db.KeyScopeBIP0086,
			expectedAddrType:  db.TaprootPubKey,
			providePrivateKey: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

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
			require.Equal(t, !tc.providePrivateKey, info.IsWatchOnly)

			// Verify account imported_key_count incremented.
			account, err := store.GetAccount(
				t.Context(), getAccountQueryByName(
					walletID, tc.scope, "imported",
				),
			)
			require.NoError(t, err)
			require.Greater(t, account.ImportedKeyCount, uint32(0))

			// Verify address_secrets row for imported addresses.
			addressID := getAddressID(
				t, queries, params.ScriptPubKey, walletID,
			)

			secret, err := getAddressSecret(t, queries, addressID)
			require.NoError(t, err)
			if tc.providePrivateKey {
				require.Equal(
					t, params.EncryptedPrivateKey, secret.EncryptedPrivKey,
				)
				require.Empty(t, secret.EncryptedScript)
			} else {
				require.Empty(t, secret.EncryptedPrivKey)
				require.Empty(t, secret.EncryptedScript)
			}
		})
	}
}

// TestNewImportedAddressWithEncryptedScript verifies that NewImportedAddress
// correctly imports script-based addresses (P2SH, P2WSH) with EncryptedScript,
// and that the EncryptedScript is stored and retrievable via GetAddressSecret.
func TestNewImportedAddressWithEncryptedScript(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWallet(t, store, "wallet-encrypted-script")
	createImportedAccount(t, store, walletID, db.KeyScopeBIP0044, "imported")
	createImportedAccount(t, store, walletID, db.KeyScopeBIP0049Plus, "imported")

	redeemScript := RandomBytes(32)
	witnessScript := RandomBytes(48)

	testCases := []struct {
		name             string
		scope            db.KeyScope
		addressType      db.AddressType
		encryptedScript  []byte
		hasPrivateKey    bool
		hasScript        bool
		expectedAddrType db.AddressType
	}{
		{
			name:             "P2SH with EncryptedScript only (watch-only)",
			scope:            db.KeyScopeBIP0044,
			addressType:      db.ScriptHash,
			encryptedScript:  redeemScript,
			hasPrivateKey:    false,
			hasScript:        true,
			expectedAddrType: db.ScriptHash,
		},
		{
			name:             "P2SH with both EncryptedPrivateKey and EncryptedScript",
			scope:            db.KeyScopeBIP0044,
			addressType:      db.ScriptHash,
			encryptedScript:  redeemScript,
			hasPrivateKey:    true,
			hasScript:        true,
			expectedAddrType: db.ScriptHash,
		},
		{
			name:             "P2WSH with EncryptedScript only (watch-only)",
			scope:            db.KeyScopeBIP0049Plus,
			addressType:      db.WitnessScript,
			encryptedScript:  witnessScript,
			hasPrivateKey:    false,
			hasScript:        true,
			expectedAddrType: db.WitnessScript,
		},
		{
			name:             "P2WSH with both EncryptedPrivateKey and EncryptedScript",
			scope:            db.KeyScopeBIP0049Plus,
			addressType:      db.WitnessScript,
			encryptedScript:  witnessScript,
			hasPrivateKey:    true,
			hasScript:        true,
			expectedAddrType: db.WitnessScript,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
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

			addressID := getAddressID(
				t, queries, params.ScriptPubKey, walletID,
			)

			secret, err := getAddressSecret(t, queries, addressID)
			require.NoError(t, err)

			require.Equal(t, tc.encryptedScript, secret.EncryptedScript)

			if tc.hasPrivateKey {
				require.Equal(
					t, params.EncryptedPrivateKey, secret.EncryptedPrivKey,
				)
			}
		})
	}
}

// TestImportedAddressCounterInsertDelete verifies that imported address inserts
// increment the per-account counter and deletes decrement it.
func TestImportedAddressCounterInsertDelete(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	dbConn := store.DB()
	walletID := newWallet(t, store, "wallet-imported-counter")
	createImportedAccount(t, store, walletID, db.KeyScopeBIP0084, "imported")

	const importedAddrCount = 5
	addressIDs := make([]uint32, 0, importedAddrCount)

	account := getAccountByName(
		t, store, walletID, db.KeyScopeBIP0084, "imported",
	)
	require.Zero(t, account.ImportedKeyCount)

	for i := 0; i < importedAddrCount; i++ {
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

	account = getAccountByName(
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
	walletID := newWallet(t, store, "wallet-imported-counter-concurrent")
	createImportedAccount(t, store, walletID, db.KeyScopeBIP0084, "imported")

	const workers = 20
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

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

	addressIDs := make([]uint32, 0, workers)
	for result := range insertResultChan {
		require.NoError(t, result.err)
		addressIDs = append(addressIDs, result.id)
	}

	require.Len(t, addressIDs, workers)

	account := getAccountByName(
		t, store, walletID, db.KeyScopeBIP0084, "imported",
	)
	require.Equal(t, uint32(workers), account.ImportedKeyCount)

	deleteErrChan := make(chan error, workers)
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

// TestNewImportedAddressDuplicate verifies that importing an address with
// a duplicate ScriptPubKey fails with a constraint error.
func TestNewImportedAddressDuplicate(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-duplicate-import")
	createImportedAccount(t, store, walletID, db.KeyScopeBIP0084, "imported")

	// Set up encryption parameters (same for both imports).
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

// TestGetAddressSecret verifies that GetAddressSecret correctly retrieves
// address secrets for watch-only imported addresses and returns an error for
// spendable addresses or non-existent address IDs.
func TestGetAddressSecret(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-secrets")
	createImportedAccount(t, store, walletID, db.KeyScopeBIP0044, "imported")

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
				secret, err := store.GetAddressSecret(t.Context(), info.ID)
				require.NoError(t, err)
				require.NotNil(t, secret)
				require.Equal(t, info.ID, secret.AddressID)
				require.Equal(
					t, params.EncryptedPrivateKey, secret.EncryptedPrivKey,
				)
				require.Empty(t, secret.EncryptedScript)
			} else {
				_, err := store.GetAddressSecret(t.Context(), info.ID)
				require.ErrorIs(t, err, db.ErrSecretNotFound)
			}
		})
	}

	// Test non-existent address ID.
	t.Run("non-existent address", func(t *testing.T) {
		_, err := store.GetAddressSecret(t.Context(), 999999)
		require.ErrorIs(t, err, db.ErrAddressNotFound)
	})
}

// TestGetAddress verifies that GetAddress correctly retrieves addresses by
// ID and by encrypted script pubkey, and returns appropriate errors for
// invalid or non-existent queries.
func TestGetAddress(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-get-address")

	tests := []struct {
		name      string
		setupFunc func(t *testing.T) db.GetAddressQuery
		wantErr   error
		validate  func(t *testing.T, addr *db.AddressInfo)
	}{
		{
			name: "get by encrypted script pubkey",
			setupFunc: func(t *testing.T) db.GetAddressQuery {
				createImportedAccount(
					t, store, walletID, db.KeyScopeBIP0084, "imported",
				)

				script := RandomBytes(32)
				params := db.NewImportedAddressParams{
					WalletID:     walletID,
					Scope:        db.KeyScopeBIP0084,
					AddressType:  db.WitnessPubKey,
					PubKey:       RandomBytes(33),
					ScriptPubKey: script,
				}
				_, err := store.NewImportedAddress(t.Context(), params)
				require.NoError(t, err)

				return db.GetAddressQuery{
					WalletID:     walletID,
					ScriptPubKey: script,
				}
			},
			validate: func(t *testing.T, addr *db.AddressInfo) {
				require.NotNil(t, addr.ScriptPubKey)
				require.Equal(t, db.ImportedAccount, addr.Origin)
			},
		},
		{
			name: "address not found by script",
			setupFunc: func(t *testing.T) db.GetAddressQuery {
				return db.GetAddressQuery{
					WalletID:     walletID,
					ScriptPubKey: RandomBytes(32),
				}
			},
			wantErr: db.ErrAddressNotFound,
		},
		{
			name: "invalid query - empty script pubkey",
			setupFunc: func(t *testing.T) db.GetAddressQuery {
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
			query := tc.setupFunc(t)
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

// TestListAddresses verifies that ListAddresses correctly returns all
// addresses for an account in a specified scope, filters by scope
// appropriately, and handles empty results without error.
func TestListAddresses(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-list-addresses")

	tests := []struct {
		name      string
		setupFunc func(t *testing.T) db.ListAddressesQuery
		wantCount int
		wantErr   error
		validate  func(t *testing.T, addrs []db.AddressInfo)
	}{
		{
			name: "list multiple addresses for account",
			setupFunc: func(t *testing.T) db.ListAddressesQuery {
				createDerivedAccount(
					t, store, walletID, db.KeyScopeBIP0044, "test-account",
				)

				createDerivedAddresses(
					t, store, walletID, db.KeyScopeBIP0044, "test-account",
					false, 5,
				)

				return db.ListAddressesQuery{
					WalletID:    walletID,
					Scope:       db.KeyScopeBIP0044,
					AccountName: "test-account",
				}
			},
			wantCount: 5,
			validate: func(t *testing.T, addrs []db.AddressInfo) {
				require.Len(t, addrs, 5)
				for i, addr := range addrs {
					require.Equal(t, uint32(i), addr.Index)
					require.Equal(t, uint32(0), addr.Branch)
					require.Equal(t, db.DerivedAccount, addr.Origin)
				}
			},
		},
		{
			name: "list addresses - empty result",
			setupFunc: func(t *testing.T) db.ListAddressesQuery {
				createDerivedAccount(
					t, store, walletID, db.KeyScopeBIP0084, "empty-account",
				)

				return db.ListAddressesQuery{
					WalletID:    walletID,
					Scope:       db.KeyScopeBIP0084,
					AccountName: "empty-account",
				}
			},
			wantCount: 0,
		},
		{
			name: "list addresses filters by scope correctly",
			setupFunc: func(t *testing.T) db.ListAddressesQuery {
				// Create accounts in different scopes.
				createDerivedAccount(
					t, store, walletID, db.KeyScopeBIP0044, "bip44-multi",
				)
				createDerivedAccount(
					t, store, walletID, db.KeyScopeBIP0049Plus, "bip49-multi",
				)

				createDerivedAddresses(
					t, store, walletID, db.KeyScopeBIP0044, "bip44-multi",
					false, 3,
				)

				createDerivedAddresses(
					t, store, walletID, db.KeyScopeBIP0049Plus, "bip49-multi",
					false, 2,
				)

				// Query only BIP0044 scope.
				return db.ListAddressesQuery{
					WalletID:    walletID,
					Scope:       db.KeyScopeBIP0044,
					AccountName: "bip44-multi",
				}
			},
			wantCount: 3,
			validate: func(t *testing.T, addrs []db.AddressInfo) {
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
			query := tc.setupFunc(t)
			addrs, err := store.ListAddresses(t.Context(), query)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.Len(t, addrs, tc.wantCount)

			if tc.validate != nil {
				tc.validate(t, addrs)
			}
		})
	}
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
			require.GreaterOrEqual(t, info.Index, uint32(0))
			require.NotNil(t, info.ScriptPubKey)
			require.Nil(t, info.PubKey)
			require.False(t, info.IsWatchOnly)
		})
	}
}

// TestNewImportedAddress_NonExistentImportedAccount verifies that calling
// NewImportedAddress when the implicit "imported" account doesn't exist
// returns db.ErrAccountNotFound. This validates that the implicit account
// lookup fails appropriately when the "imported" account has not been created
// in the specified scope.
func TestNewImportedAddress_NonExistentImportedAccount(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "test-wallet")

	// Attempt to import address when "imported" account doesn't exist.
	params := db.NewImportedAddressParams{
		WalletID:            walletID,
		Scope:               db.KeyScopeBIP0084,
		AddressType:         db.WitnessPubKey,
		PubKey:              RandomBytes(33),
		EncryptedPrivateKey: RandomBytes(32),
		ScriptPubKey:        RandomBytes(32),
	}
	_, err := store.NewImportedAddress(t.Context(), params)

	// Expect account not found error because an implicit "imported" account
	// doesn't exist.
	require.ErrorIs(t, err, db.ErrAccountNotFound)
}

// TestGetAddressSecret_DerivedAddress verifies that calling GetAddressSecret
// on a derived address returns db.ErrSecretNotFound (not ErrAddressNotFound).
// This validates the LEFT JOIN: derived addresses exist in the addresses
// table but have no corresponding row in address_secrets. The query returns a
// row with NULL encrypted_priv_key, and the converter returns ErrSecretNotFound.
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
	addrInfo, err := store.NewDerivedAddress(t.Context(), params, mockDeriveFunc())
	require.NoError(t, err)

	// Attempt to get secret for derived address.
	// Derived addresses have no row in address_secrets table.
	_, err = store.GetAddressSecret(t.Context(), addrInfo.ID)

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
	for i := 0; i < 5; i++ {
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

	addresses, err := store.ListAddresses(
		t.Context(),
		db.ListAddressesQuery{
			WalletID:    walletID,
			Scope:       db.KeyScopeBIP0084,
			AccountName: "ordering-account",
		},
	)

	require.NoError(t, err)
	require.Len(t, addresses, 6)

	// Separate addresses by branch for verification.
	var externalAddrs []db.AddressInfo
	var changeAddrs []db.AddressInfo

	for _, addr := range addresses {
		if addr.Branch == 0 {
			externalAddrs = append(externalAddrs, addr)
		} else {
			changeAddrs = append(changeAddrs, addr)
		}
	}

	// Verify external addresses sorted by index.
	for i := 1; i < len(externalAddrs); i++ {
		require.True(
			t, externalAddrs[i-1].Index <= externalAddrs[i].Index,
			"external addresses not in order",
		)
	}

	// Verify change addresses sorted by index.
	for i := 1; i < len(changeAddrs); i++ {
		require.True(
			t, changeAddrs[i-1].Index <= changeAddrs[i].Index,
			"change addresses not in order",
		)
	}
}

// TestNewDerivedAddressErrors verifies that NewDerivedAddress returns
// appropriate errors for invalid parameters, including non-existent
// accounts, unknown key scopes, and empty account names.
func TestNewDerivedAddressErrors(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-new-derived-address-errors")

	tests := []struct {
		name    string
		params  db.NewDerivedAddressParams
		wantErr error
	}{
		{
			name: "non-existent account",
			params: db.NewDerivedAddressParams{
				WalletID:    walletID,
				Scope:       db.KeyScopeBIP0084,
				AccountName: "non-existent",
				Change:      false,
			},
			wantErr: db.ErrAccountNotFound,
		},
		{
			name: "empty account name",
			params: db.NewDerivedAddressParams{
				WalletID:    walletID,
				Scope:       db.KeyScopeBIP0044,
				AccountName: "",
				Change:      false,
			},
			wantErr: db.ErrAccountNotFound,
		},
		{
			name: "unknown key scope returns account not found",
			params: db.NewDerivedAddressParams{
				WalletID: walletID,
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

			info, err := store.NewDerivedAddress(t.Context(), tc.params, mockDeriveFunc())
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, info)
		})
	}
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
	results := make([]db.AddressInfo, workers)
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	deriveFn := mockDeriveFunc()

	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			info, err := store.NewDerivedAddress(
				ctx, db.NewDerivedAddressParams{
					WalletID:    walletID,
					Scope:       db.KeyScopeBIP0084,
					AccountName: accountName,
					Change:      false,
				}, deriveFn,
			)
			require.NoError(t, err)
			results[i] = *info
		}(i)
	}

	wg.Wait()

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
	var externalAddrs []db.AddressInfo
	var changeAddrs []db.AddressInfo

	for i := 0; i < 3; i++ {
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
	CreateAddressWithIndex(t, queries, accountID, 0, math.MaxUint32-1)

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
		}, mockDeriveFunc(),
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
	CreateAddressWithIndex(t, queries, accountID, 1, math.MaxUint32-1)

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
		}, mockDeriveFunc(),
	)
	require.ErrorIs(t, err, db.ErrMaxAddressIndexReached)
}
