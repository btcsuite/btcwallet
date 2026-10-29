package kvdb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

const savingsAccountName = "savings"

// newAccountStoreFixture creates a kvdb Store backed by a freshly initialized
// spendable wallet and unlocks it so account-derivation paths are valid.
func newAccountStoreFixture(t *testing.T) (*Store, *waddrmgr.Manager, func()) {
	t.Helper()

	dbConn, cleanup := newTestDB(t)
	mgr := newSpendableAddrMgr(t, dbConn)

	// Unlock the manager so scoped key managers can derive new accounts.
	err := walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		return mgr.Unlock(ns, []byte("priv"))
	})
	require.NoError(t, err)

	cleanupAll := func() {
		_ = mgr.Lock()
		mgr.Close()
		cleanup()
	}

	return NewStore(dbConn, nil, mgr), mgr, cleanupAll
}

// createDerivedAccount creates a derived account directly through
// waddrmgr's legacy NewAccount path so kvdb's read methods have a row to
// observe.
func createDerivedAccount(t *testing.T, dbConn walletdb.DB,
	mgr *waddrmgr.Manager, scope waddrmgr.KeyScope,
	name string) uint32 {

	t.Helper()

	var accountNumber uint32

	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)

		scopedMgr, err := mgr.FetchScopedKeyManager(scope)
		if err != nil {
			return err
		}

		accountNumber, err = scopedMgr.NewAccount(ns, name)

		return err
	})
	require.NoError(t, err)

	return accountNumber
}

// TestGetAccountByName verifies that GetAccount returns the expected
// AccountInfo when the account exists and is looked up by name.
func TestGetAccountByName(t *testing.T) {
	t.Parallel()

	// Arrange: persist one ordinary derived account in the legacy format and
	// retain its name and number for the normalized read assertions.
	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	accountName := savingsAccountName
	accountNumber := createDerivedAccount(
		t, store.db, mgr, waddrmgr.KeyScopeBIP0084, accountName,
	)

	// Act: load the legacy row through the shared AccountInfo conversion,
	// without any SQL-only account metadata in storage.
	info, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		Scope: db.KeyScope{
			Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
			Coin:    waddrmgr.KeyScopeBIP0084.Coin,
		},
		Name: &accountName,
	})

	// Assert: the legacy fields are preserved and the absent synchronization
	// policy is reported truthfully as false.
	require.NoError(t, err)
	require.NotNil(t, info)
	require.Equal(t, accountName, info.AccountName)
	require.NotNil(t, info.AccountNumber)
	require.Equal(t, accountNumber, *info.AccountNumber)
	require.False(t, info.IsImported)
	require.False(t, info.IsWatchOnly)

	// kvdb populates the durable AccountID from the internal waddrmgr account
	// number; for a derived account it coincides with the BIP44 number.
	require.NotNil(t, info.AccountID)
	require.Equal(t, accountNumber, *info.AccountID)

	// The plaintext account-level public key must be parseable.
	require.NotEmpty(t, info.PublicKey)
	parsed, err := hdkeychain.NewKeyFromString(string(info.PublicKey))
	require.NoError(t, err)
	require.False(t, parsed.IsPrivate())
	require.False(t, info.NoChainSync)
}

// TestGetAccountByNumber verifies the AccountNumber-keyed lookup branch.
func TestGetAccountByNumber(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	accountName := savingsAccountName
	accountNumber := createDerivedAccount(
		t, store.db, mgr, waddrmgr.KeyScopeBIP0084, accountName,
	)

	info, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		Scope: db.KeyScope{
			Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
			Coin:    waddrmgr.KeyScopeBIP0084.Coin,
		},
		AccountNumber: &accountNumber,
	})
	require.NoError(t, err)
	require.NotNil(t, info)
	require.Equal(t, accountName, info.AccountName)
}

// TestGetAccountNotFound verifies the not-found translation.
func TestGetAccountNotFound(t *testing.T) {
	t.Parallel()

	store, _, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	missing := "nonexistent"
	_, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		Scope: db.KeyScope{
			Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
			Coin:    waddrmgr.KeyScopeBIP0084.Coin,
		},
		Name: &missing,
	})
	require.ErrorIs(t, err, db.ErrAccountNotFound)
}

// TestGetAccountIncludesImportedPseudoAccount verifies the legacy imported
// address pseudo-account remains queryable by name through the store.
func TestGetAccountIncludesImportedPseudoAccount(t *testing.T) {
	t.Parallel()

	store, _, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	name := waddrmgr.ImportedAddrAccountName
	info, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		Scope: db.KeyScope{
			Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
			Coin:    waddrmgr.KeyScopeBIP0084.Coin,
		},
		Name: &name,
	})
	require.NoError(t, err)
	require.Equal(t, waddrmgr.ImportedAddrAccountName, info.AccountName)
	require.True(t, info.IsImported)
	require.Nil(t, info.AccountNumber)

	// The masked BIP44 number is nil, but the durable store AccountID is still
	// populated from the internal waddrmgr account number.
	require.NotNil(t, info.AccountID)
	require.Equal(t, uint32(waddrmgr.ImportedAddrAccount), *info.AccountID)
}

// TestListAccountsByNameIncludesImportedPseudoAccount verifies the
// name-filtered list path also returns the legacy imported address
// pseudo-account.
func TestListAccountsByNameIncludesImportedPseudoAccount(t *testing.T) {
	t.Parallel()

	// Arrange: select the implicit imported-address account, which is encoded
	// entirely by legacy waddrmgr state without SQL account policy metadata.
	store, _, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	name := waddrmgr.ImportedAddrAccountName

	// Act: list accounts through the second kvdb read surface that materializes
	// normalized AccountInfo values.
	infos, err := store.ListAccounts(t.Context(), db.ListAccountsQuery{
		Name: &name,
	})

	// Assert: the pseudo-account remains intact and truthfully reports the
	// historical chain-synchronized behavior.
	require.NoError(t, err)
	require.Len(t, infos, 1)
	require.Equal(t, waddrmgr.ImportedAddrAccountName, infos[0].AccountName)
	require.True(t, infos[0].IsImported)
	require.Nil(t, infos[0].AccountNumber)
	require.False(t, infos[0].NoChainSync)
}

// TestRenameAccountByName verifies that RenameAccount renames by old
// name and that GetAccount with the new name returns the same row.
func TestRenameAccountByName(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	accountNumber := createDerivedAccount(
		t, store.db, mgr, waddrmgr.KeyScopeBIP0084, savingsAccountName,
	)

	err := store.RenameAccount(t.Context(), db.RenameAccountParams{
		Scope: db.KeyScope{
			Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
			Coin:    waddrmgr.KeyScopeBIP0084.Coin,
		},
		OldName: savingsAccountName,
		NewName: "renamed",
	})
	require.NoError(t, err)

	newName := "renamed"
	info, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		Scope: db.KeyScope{
			Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
			Coin:    waddrmgr.KeyScopeBIP0084.Coin,
		},
		Name: &newName,
	})
	require.NoError(t, err)
	require.NotNil(t, info.AccountNumber)
	require.Equal(t, accountNumber, *info.AccountNumber)
}

// TestRenameAccountByNumber verifies the AccountNumber-keyed rename branch.
func TestRenameAccountByNumber(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	accountNumber := createDerivedAccount(
		t, store.db, mgr, waddrmgr.KeyScopeBIP0084, savingsAccountName,
	)

	err := store.RenameAccount(t.Context(), db.RenameAccountParams{
		Scope: db.KeyScope{
			Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
			Coin:    waddrmgr.KeyScopeBIP0084.Coin,
		},
		AccountNumber: &accountNumber,
		NewName:       "renamed-by-number",
	})
	require.NoError(t, err)
}

// TestRenameAccountNotFound verifies the not-found translation.
func TestRenameAccountNotFound(t *testing.T) {
	t.Parallel()

	store, _, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	err := store.RenameAccount(t.Context(), db.RenameAccountParams{
		Scope: db.KeyScope{
			Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
			Coin:    waddrmgr.KeyScopeBIP0084.Coin,
		},
		OldName: "nonexistent",
		NewName: "anything",
	})
	require.ErrorIs(t, err, db.ErrAccountNotFound)
}

// TestRenameAccountImported verifies imported xpubs can be renamed by name,
// while internal-number selection and the raw-import pseudo-account reject.
func TestRenameAccountImported(t *testing.T) {
	t.Parallel()

	// Retain supplied metadata through the optional Store input.
	fingerprint := uint32(0xDEADBEEF)

	store, _, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	seed := bytes.Repeat([]byte{0xC1}, hdkeychain.RecommendedSeedLen)
	master, err := hdkeychain.NewMaster(seed, &chaincfg.SimNetParams)
	require.NoError(t, err)
	masterPub, err := master.Neuter()
	require.NoError(t, err)

	scope := db.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0084.Coin,
	}
	name := "imported-rename"

	_, err = store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			Scope:             scope,
			Name:              name,
			MasterFingerprint: &fingerprint,
			PublicKey:         []byte(masterPub.String()),
		},
	)
	require.NoError(t, err)

	err = store.RenameAccount(t.Context(), db.RenameAccountParams{
		Scope:   scope,
		OldName: name,
		NewName: "renamed-imported",
	})
	require.NoError(t, err)

	_, err = store.GetAccount(
		t.Context(), db.GetAccountQuery{
			Scope: scope,
			Name:  &name,
		},
	)
	require.ErrorIs(t, err, db.ErrAccountNotFound)

	renamedName := "renamed-imported"
	info, err := store.GetAccount(
		t.Context(), db.GetAccountQuery{
			Scope: scope,
			Name:  &renamedName,
		},
	)
	require.NoError(t, err)
	require.Equal(t, renamedName, info.AccountName)
	require.True(t, info.IsImported)
	require.Nil(t, info.AccountNumber)

	mgrScope := waddrmgr.KeyScope(scope)
	scopedMgr, err := store.addrStore.FetchScopedKeyManager(mgrScope)
	require.NoError(t, err)

	var internalNumber uint32

	err = walletdb.View(store.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)

		var err error

		internalNumber, err = scopedMgr.LookupAccount(ns, renamedName)

		return err
	})
	require.NoError(t, err)

	err = store.RenameAccount(
		t.Context(), db.RenameAccountParams{
			Scope:         scope,
			AccountNumber: &internalNumber,
			NewName:       "renamed-imported-number",
		},
	)
	require.ErrorIs(t, err, db.ErrAccountNotFound)

	err = store.RenameAccount(
		t.Context(), db.RenameAccountParams{
			Scope:   scope,
			OldName: waddrmgr.ImportedAddrAccountName,
			NewName: "renamed-raw-import",
		},
	)
	require.ErrorIs(t, err, db.ErrAccountNotFound)

	info, err = store.GetAccount(
		t.Context(), db.GetAccountQuery{
			Scope: scope,
			Name:  &renamedName,
		},
	)
	require.NoError(t, err)
	require.Equal(t, renamedName, info.AccountName)
}

// kvdbDeriveFnFixture returns an AccountDerivationFunc that derives an
// account-level extended key from the test wallet's known seed. The
// resulting DerivedAccountData mirrors the production wallet's deriveFn:
// plaintext PublicKey + encrypted private key (encrypted with the test
// manager's cryptoKeyPriv) + fixed MasterKeyFingerprint.
func kvdbDeriveFnFixture(t *testing.T,
	mgr *waddrmgr.Manager) db.AccountDerivationFunc {

	t.Helper()

	seed := bytes.Repeat([]byte{0x5A}, hdkeychain.RecommendedSeedLen)
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.SimNetParams)
	require.NoError(t, err)

	return func(_ context.Context, scope db.KeyScope, accountNumber uint32,
		_ bool) (*db.DerivedAccountData, error) {

		purposeKey, err := masterKey.DeriveNonStandard(
			scope.Purpose + hdkeychain.HardenedKeyStart,
		)
		if err != nil {
			return nil, err
		}

		coinKey, err := purposeKey.DeriveNonStandard(
			scope.Coin + hdkeychain.HardenedKeyStart,
		)
		if err != nil {
			return nil, err
		}

		acctPriv, err := coinKey.DeriveNonStandard(
			accountNumber + hdkeychain.HardenedKeyStart,
		)
		if err != nil {
			return nil, err
		}

		acctPub, err := acctPriv.Neuter()
		if err != nil {
			return nil, err
		}

		encPriv, err := mgr.Encrypt(
			waddrmgr.CKTPrivate, []byte(acctPriv.String()),
		)
		if err != nil {
			return nil, err
		}

		return &db.DerivedAccountData{
			PublicKey:            []byte(acctPub.String()),
			EncryptedPrivateKey:  encPriv,
			MasterKeyFingerprint: 0xC0DEC0DE,
		}, nil
	}
}

// TestCreateDerivedAccount verifies that CreateDerivedAccount persists
// the wallet-derived account material and that a subsequent GetAccount
// returns the same row.
func TestCreateDerivedAccount(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	deriveFn := kvdbDeriveFnFixture(t, mgr)

	info, err := store.CreateDerivedAccount(t.Context(),
		db.CreateDerivedAccountParams{
			Scope: db.KeyScope{
				Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
				Coin:    waddrmgr.KeyScopeBIP0084.Coin,
			},
			Name: savingsAccountName,
		}, deriveFn,
	)
	require.NoError(t, err)
	require.NotNil(t, info)
	require.Equal(t, savingsAccountName, info.AccountName)
	require.False(t, info.IsImported)
	require.NotEmpty(t, info.PublicKey)
	require.NotNil(t, info.MasterKeyFingerprint)
	require.NotZero(t, *info.MasterKeyFingerprint)
	require.NotNil(t, info.MasterKeyFingerprint)
	require.Equal(t, uint32(0xC0DEC0DE), *info.MasterKeyFingerprint)

	// A subsequent GetAccount must observe the new row.
	name := savingsAccountName
	read, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		Scope: db.KeyScope{
			Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
			Coin:    waddrmgr.KeyScopeBIP0084.Coin,
		},
		Name: &name,
	})
	require.NoError(t, err)
	require.NotNil(t, read)
	require.Equal(t, info.AccountNumber, read.AccountNumber)
	require.Equal(t, savingsAccountName, read.AccountName)
}

// TestCreateDerivedAccountExact verifies sparse creation derives the requested
// key path and advances the existing native account cursor to that slot.
func TestCreateDerivedAccountExact(t *testing.T) {
	t.Parallel()

	// Arrange: the real store already has account zero; requesting seven
	// must derive that actual path without creating intervening accounts.
	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	derive := kvdbDeriveFnFixture(t, mgr)
	scope := db.KeyScopeBIP0084
	number := uint32(7)
	params := db.CreateDerivedAccountParams{
		Scope:         scope,
		Name:          savingsAccountName,
		AccountNumber: &number,
	}

	// Act: create the sparse account through the real shared transaction.
	info, err := store.CreateDerivedAccount(t.Context(), params, derive)

	// Assert: both the key and cursor identify seven rather than a relabeled
	// sequential allocation. Existing hole/reopen cases cover later requests.
	require.NoError(t, err)
	require.Equal(t, number, *info.AccountNumber)

	want, err := derive(t.Context(), scope, number, false)
	require.NoError(t, err)
	require.Equal(
		t, db.AccountXPubPayload(want.PublicKey),
		db.AccountXPubPayload(info.PublicKey),
	)

	scoped, err := mgr.FetchScopedKeyManager(waddrmgr.KeyScope(scope))
	require.NoError(t, err)
	err = walletdb.View(store.db, func(tx walletdb.ReadTx) error {
		last, err := scoped.LastAccount(tx.ReadBucket(waddrmgr.NamespaceKey))
		require.NoError(t, err)
		require.Equal(t, number, last)

		return nil
	})
	require.NoError(t, err)
}

// TestCreateDerivedAccountExactOccupied verifies refusal preserves an occupied
// account's keys and children, including the native default and a sparse slot.
func TestCreateDerivedAccountExactOccupied(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		number uint32
	}{
		{
			name:   "native default",
			number: 0,
		},
		{
			name:   "sparse account",
			number: 7,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: both slots exist before the subject call. Retain a
			// child on the selected owner so replacement would expose lost
			// counters or metadata as well as an overwritten account key.
			store, mgr, cleanup := newAccountStoreFixture(t)
			t.Cleanup(cleanup)

			derive := kvdbDeriveFnFixture(t, mgr)
			scope := db.KeyScopeBIP0084
			seven := uint32(7)
			_, err := store.CreateDerivedAccount(
				t.Context(), db.CreateDerivedAccountParams{
					Scope:         scope,
					Name:          savingsAccountName,
					AccountNumber: &seven,
				}, derive,
			)
			require.NoError(t, err)

			_, err = store.NewDerivedAddress(
				t.Context(), db.NewDerivedAddressParams{
					Scope:         scope,
					AccountNumber: &tc.number,
				},
			)
			require.NoError(t, err)

			query := db.GetAccountQuery{
				Scope:         scope,
				AccountNumber: &tc.number,
				SkipBalance:   true,
			}
			before, err := store.GetAccount(t.Context(), query)
			require.NoError(t, err)

			// Act: request an occupied slot using a different free name.
			info, err := store.CreateDerivedAccount(
				t.Context(), db.CreateDerivedAccountParams{
					Scope:         scope,
					Name:          "replacement",
					AccountNumber: &tc.number,
				}, derive,
			)

			// Assert: refusal returns no account, preserves the complete owner
			// snapshot, and leaves the highest allocated native slot at seven.
			require.ErrorIs(t, err, db.ErrAccountNumberConflict)
			require.Nil(t, info)

			after, err := store.GetAccount(t.Context(), query)
			require.NoError(t, err)
			require.Equal(t, before, after)

			scoped, err := mgr.FetchScopedKeyManager(waddrmgr.KeyScope(scope))
			require.NoError(t, err)
			err = walletdb.View(store.db, func(tx walletdb.ReadTx) error {
				last, err := scoped.LastAccount(
					tx.ReadBucket(waddrmgr.NamespaceKey),
				)
				require.NoError(t, err)
				require.Equal(t, seven, last)

				return nil
			})
			require.NoError(t, err)
		})
	}
}

// TestCreateDerivedAccountNoChainSync verifies exact KVDB creation ignores
// SQL-only exclusion and reports the same false policy on an independent read.
func TestCreateDerivedAccountNoChainSync(t *testing.T) {
	t.Parallel()

	// Arrange: use a real Store and seed-derived keys for an exact request
	// with SQL-only exclusion set, exposing the former exact-only exception.
	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	scope := db.KeyScopeBIP0084
	number := uint32(7)
	params := db.CreateDerivedAccountParams{
		Scope:         scope,
		Name:          savingsAccountName,
		AccountNumber: &number,
		NoChainSync:   true,
	}

	// Act: create the exact account through the real shared transaction.
	created, err := store.CreateDerivedAccount(
		t.Context(), params, kvdbDeriveFnFixture(t, mgr),
	)

	// Assert: creation and a separate persisted read both keep the KVDB
	// policy false, rather than echoing the requested SQL-only exclusion.
	require.NoError(t, err)
	require.False(t, created.NoChainSync)

	read, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		Scope:         scope,
		AccountNumber: &number,
		SkipBalance:   true,
	})
	require.NoError(t, err)
	require.False(t, read.NoChainSync)
}

// TestCreateDerivedAccountRollsBackOnDeriveError verifies that when the
// derivation callback fails after the account number has been allocated,
// the underlying walletdb transaction rolls back so the lastAccount counter
// is restored.
func TestCreateDerivedAccountRollsBackOnDeriveError(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	failDerive := func(_ context.Context, _ db.KeyScope, _ uint32,
		_ bool) (*db.DerivedAccountData, error) {

		return nil, errTestBoom
	}

	_, err := store.CreateDerivedAccount(t.Context(),
		db.CreateDerivedAccountParams{
			Scope: db.KeyScope{
				Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
				Coin:    waddrmgr.KeyScopeBIP0084.Coin,
			},
			Name: "doomed",
		}, failDerive,
	)
	require.ErrorIs(t, err, errTestBoom)

	// Now a successful CreateDerivedAccount must reuse the rolled-back
	// account number rather than skipping it; we verify by creating two
	// accounts and observing contiguous account numbers.
	deriveFn := kvdbDeriveFnFixture(t, mgr)

	info1, err := store.CreateDerivedAccount(t.Context(),
		db.CreateDerivedAccountParams{
			Scope: db.KeyScope{
				Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
				Coin:    waddrmgr.KeyScopeBIP0084.Coin,
			},
			Name: "first",
		}, deriveFn,
	)
	require.NoError(t, err)

	info2, err := store.CreateDerivedAccount(t.Context(),
		db.CreateDerivedAccountParams{
			Scope: db.KeyScope{
				Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
				Coin:    waddrmgr.KeyScopeBIP0084.Coin,
			},
			Name: "second",
		}, deriveFn,
	)
	require.NoError(t, err)

	require.NotNil(t, info1.AccountNumber)
	require.NotNil(t, info2.AccountNumber)
	require.Equal(t, *info1.AccountNumber+1, *info2.AccountNumber,
		"account numbers should be contiguous after rollback")
}

// TestCreateDerivedAccountFallsBackToScopedKey verifies that kvdb can create
// derived accounts after the master root private key has been neutered.
func TestCreateDerivedAccountFallsBackToScopedKey(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	err := walletdb.Update(store.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)
		return mgr.NeuterRootKey(ns)
	})
	require.NoError(t, err)

	_, err = store.GetEncryptedHDSeed(t.Context(), 0)
	require.ErrorIs(t, err, db.ErrSecretNotFound)

	missingRootDerive := func(_ context.Context, _ db.KeyScope, _ uint32,
		_ bool) (*db.DerivedAccountData, error) {

		return nil, db.ErrSecretNotFound
	}

	info, err := store.CreateDerivedAccount(t.Context(),
		db.CreateDerivedAccountParams{
			Scope: db.KeyScope{
				Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
				Coin:    waddrmgr.KeyScopeBIP0084.Coin,
			},
			Name: savingsAccountName,
		}, missingRootDerive,
	)
	require.NoError(t, err)
	require.Equal(t, savingsAccountName, info.AccountName)
	require.False(t, info.IsImported)
	require.NotEmpty(t, info.PublicKey)

	parsed, err := hdkeychain.NewKeyFromString(string(info.PublicKey))
	require.NoError(t, err)
	require.False(t, parsed.IsPrivate())

	name := savingsAccountName
	read, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		Scope: db.KeyScope{
			Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
			Coin:    waddrmgr.KeyScopeBIP0084.Coin,
		},
		Name: &name,
	})
	require.NoError(t, err)
	require.Equal(t, info.AccountNumber, read.AccountNumber)
	require.Equal(t, info.MasterKeyFingerprint, read.MasterKeyFingerprint)
}

var errTestBoom = errors.New("kvdb test boom")

// TestCreateImportedAccount verifies the watch-only-imported account
// path: kvdb persists the row, GetAccount returns IsImported=true, and the
// AccountInfo.MasterKeyFingerprint round-trips.
func TestCreateImportedAccount(t *testing.T) {
	t.Parallel()

	// Retain supplied metadata through the optional Store input.
	fingerprint := uint32(0xDEADBEEF)

	store, _, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	// Build a deterministic account-level pub key for the import.
	seed := bytes.Repeat([]byte{0xBB}, hdkeychain.RecommendedSeedLen)
	master, err := hdkeychain.NewMaster(seed, &chaincfg.SimNetParams)
	require.NoError(t, err)
	masterPub, err := master.Neuter()
	require.NoError(t, err)

	info, err := store.CreateImportedAccount(t.Context(),
		db.CreateImportedAccountParams{
			Scope: db.KeyScope{
				Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
				Coin:    waddrmgr.KeyScopeBIP0084.Coin,
			},
			Name:              "imported-xpub",
			MasterFingerprint: &fingerprint,
			PublicKey:         []byte(masterPub.String()),
		},
	)
	require.NoError(t, err)
	require.NotNil(t, info)
	require.Equal(t, "imported-xpub", info.AccountName)
	require.True(t, info.IsImported)
	require.True(t, info.IsWatchOnly)
	require.NotNil(t, info.MasterKeyFingerprint)
	require.Equal(t, uint32(0xDEADBEEF), *info.MasterKeyFingerprint)

	// The imported xpub has no BIP44 number, but kvdb still populates the
	// durable store AccountID from its internal waddrmgr account number, which
	// is distinct from the default derived account at number 0.
	require.Nil(t, info.AccountNumber)
	require.NotNil(t, info.AccountID)
	require.NotEqual(t, uint32(waddrmgr.DefaultAccountNum), *info.AccountID)
}

// TestCreateImportedAccountRejectsPrivateKey verifies that the kvdb
// adapter refuses imported accounts with private key material on
// spendable wallets, since waddrmgr's accountWatchOnly row has no
// private-key column.
func TestCreateImportedAccountRejectsPrivateKey(t *testing.T) {
	t.Parallel()

	// Retain supplied metadata through the optional Store input.
	fingerprint := uint32(0xDEADBEEF)

	store, _, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	seed := bytes.Repeat([]byte{0xBB}, hdkeychain.RecommendedSeedLen)
	master, err := hdkeychain.NewMaster(seed, &chaincfg.SimNetParams)
	require.NoError(t, err)
	masterPub, err := master.Neuter()
	require.NoError(t, err)

	_, err = store.CreateImportedAccount(t.Context(),
		db.CreateImportedAccountParams{
			Scope: db.KeyScope{
				Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
				Coin:    waddrmgr.KeyScopeBIP0084.Coin,
			},
			Name:                "imported-spendable",
			MasterFingerprint:   &fingerprint,
			PublicKey:           []byte(masterPub.String()),
			EncryptedPrivateKey: []byte{0xAA, 0xBB},
		},
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not supported")
}

// TestCreateImportedAccountDryRunRollsBack verifies that DryRun validates the
// import and derives sample addresses without persisting the imported row.
func TestCreateImportedAccountDryRunRollsBack(t *testing.T) {
	t.Parallel()

	// Retain supplied metadata through the optional Store input.
	fingerprint := uint32(0xDEADBEEF)

	store, _, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	seed := bytes.Repeat([]byte{0xBC}, hdkeychain.RecommendedSeedLen)
	master, err := hdkeychain.NewMaster(seed, &chaincfg.SimNetParams)
	require.NoError(t, err)
	masterPub, err := master.Neuter()
	require.NoError(t, err)

	scope := db.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0084.Coin,
	}
	name := "imported-dry-run"

	info, err := store.CreateImportedAccount(t.Context(),
		db.CreateImportedAccountParams{
			Scope:             scope,
			Name:              name,
			MasterFingerprint: &fingerprint,
			PublicKey:         []byte(masterPub.String()),
			DryRun:            true,
		},
	)
	require.NoError(t, err)
	require.Equal(t, name, info.AccountName)

	_, err = store.GetAccount(t.Context(), db.GetAccountQuery{
		Scope: scope,
		Name:  &name,
	})
	require.ErrorIs(t, err, db.ErrAccountNotFound)
}

// TestCreateImportedAccountDryRunMissingScopeDoesNotRegisterScope verifies a
// missing purpose-1017 scope can be previewed without retaining scope state.
func TestCreateImportedAccountDryRunMissingScopeDoesNotRegisterScope(
	t *testing.T) {

	t.Parallel()

	// Retain supplied metadata through the optional Store input.
	fingerprint := uint32(0xDEADBEEF)

	number := uint32(7)

	cases := []struct {
		name   string
		number *uint32
	}{
		{
			name: "numberless",
		},
		{
			name:   "numbered",
			number: &number,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: derive an account key without creating the absent
			// scope, and retain the public state a preview must preserve.
			// Both inputs differ only in whether their number is declared.
			store, mgr, cleanup := newAccountStoreFixture(t)
			t.Cleanup(cleanup)

			scope := db.KeyScope{Purpose: 1017, Coin: 0}
			schema := db.ScopeAddrMap[db.KeyScopeBIP0084]
			derive := kvdbDeriveFnFixture(t, mgr)
			key, err := derive(t.Context(), scope, number, false)
			require.NoError(t, err)

			query := db.ListAccountsQuery{SkipBalance: true}
			before, err := store.ListAccounts(t.Context(), query)
			require.NoError(t, err)

			external := append([]waddrmgr.KeyScope(nil),
				mgr.ScopesForExternalAddrType(waddrmgr.WitnessPubKey)...)
			internal := append([]waddrmgr.KeyScope(nil),
				mgr.ScopesForInternalAddrTypes(waddrmgr.WitnessPubKey)...)
			params := db.CreateImportedAccountParams{
				Scope:             scope,
				Name:              "missing scope preview",
				AccountNumber:     tc.number,
				PublicKey:         key.PublicKey,
				MasterFingerprint: &fingerprint,
				AddrSchema:        &schema,
				DryRun:            true,
			}

			// Act: preview, capture the public state before any commit,
			// then commit identical input as the positive control that
			// rolled-back scope rows cannot block the real import.
			preview, previewErr := store.CreateImportedAccount(
				t.Context(), params,
			)
			after, listErr := store.ListAccounts(t.Context(), query)
			_, scopeErr := mgr.FetchScopedKeyManager(waddrmgr.KeyScope(scope))
			afterExternal := append([]waddrmgr.KeyScope(nil),
				mgr.ScopesForExternalAddrType(waddrmgr.WitnessPubKey)...)
			afterInternal := append([]waddrmgr.KeyScope(nil),
				mgr.ScopesForInternalAddrTypes(waddrmgr.WitnessPubKey)...)
			params.DryRun = false
			committed, commitErr := store.CreateImportedAccount(
				t.Context(), params,
			)

			// Assert: preview returns the requested identity without
			// publishing any scope/index or changing the account listing.
			// The committed result agrees on the same portable identity.
			require.NoError(t, previewErr)
			require.NotNil(t, preview)
			require.Equal(t, scope, preview.KeyScope)
			require.Equal(t, tc.number, preview.AccountNumber)
			require.Equal(t, key.PublicKey, preview.PublicKey)
			require.Equal(t, schema, preview.AddrSchema)
			require.NotNil(t, preview.MasterKeyFingerprint)
			require.Equal(
				t, params.MasterFingerprint,
				preview.MasterKeyFingerprint,
			)
			require.NoError(t, listErr)
			require.ElementsMatch(t, before, after)
			require.True(t, waddrmgr.IsError(
				scopeErr, waddrmgr.ErrScopeNotFound,
			))
			require.Equal(t, external, afterExternal)
			require.Equal(t, internal, afterInternal)
			require.NoError(t, commitErr)
			require.NotNil(t, committed)
			require.Equal(t, preview.KeyScope, committed.KeyScope)
			require.Equal(t, preview.AccountNumber, committed.AccountNumber)
			require.Equal(t, preview.PublicKey, committed.PublicKey)
			require.Equal(t, preview.AddrSchema, committed.AddrSchema)
			require.Equal(
				t, preview.MasterKeyFingerprint,
				committed.MasterKeyFingerprint,
			)

			_, err = mgr.FetchScopedKeyManager(waddrmgr.KeyScope(scope))
			require.NoError(t, err)
		})
	}
}

// TestCreateImportedAccountUsesAddrSchema verifies that kvdb forwards the
// per-account address schema override to waddrmgr.
func TestCreateImportedAccountUsesAddrSchema(t *testing.T) {
	t.Parallel()

	// Retain supplied metadata through the optional Store input.
	fingerprint := uint32(0xDEADBEEF)

	store, _, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	seed := bytes.Repeat([]byte{0xBD}, hdkeychain.RecommendedSeedLen)
	master, err := hdkeychain.NewMaster(seed, &chaincfg.SimNetParams)
	require.NoError(t, err)
	masterPub, err := master.Neuter()
	require.NoError(t, err)

	scope := db.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0049Plus.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0049Plus.Coin,
	}
	addrSchema := db.ScopeAddrSchema{
		ExternalAddrType: db.NestedWitnessPubKey,
		InternalAddrType: db.NestedWitnessPubKey,
	}

	name := "imported-schema"
	info, err := store.CreateImportedAccount(t.Context(),
		db.CreateImportedAccountParams{
			Scope:             scope,
			Name:              name,
			MasterFingerprint: &fingerprint,
			PublicKey:         []byte(masterPub.String()),
			AddrSchema:        &addrSchema,
		},
	)
	require.NoError(t, err)
	require.Equal(t, addrSchema, info.AddrSchema)

	info, err = store.GetAccount(
		t.Context(), db.GetAccountQuery{
			Scope: scope,
			Name:  &name,
		},
	)
	require.NoError(t, err)
	require.Equal(t, addrSchema, info.AddrSchema)

	scopedMgr, err := store.addrStore.FetchScopedKeyManager(
		waddrmgr.KeyScope(scope),
	)
	require.NoError(t, err)

	err = walletdb.View(store.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)

		accountNumber, err := scopedMgr.LookupAccount(ns, name)
		if err != nil {
			return err
		}

		props, err := scopedMgr.AccountProperties(
			ns, accountNumber,
		)
		if err != nil {
			return err
		}

		require.NotNil(t, props.AddrSchema)
		require.Equal(t, waddrmgr.KeyScopeBIP0049AddrSchema,
			*props.AddrSchema)

		return nil
	})
	require.NoError(t, err)

	// BIP44 uses db.PubKeyHash=1 while waddrmgr.PubKeyHash=0. This case
	// guards against the old raw cast by asserting the persisted legacy
	// schema for both the external and internal branches.
	bip44Scope := db.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0044.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0044.Coin,
	}
	bip44Schema := db.ScopeAddrSchema{
		ExternalAddrType: db.PubKeyHash,
		InternalAddrType: db.PubKeyHash,
	}
	bip44Name := "imported-bip44-schema"

	info, err = store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			Scope:             bip44Scope,
			Name:              bip44Name,
			MasterFingerprint: &fingerprint,
			PublicKey:         []byte(masterPub.String()),
			AddrSchema:        &bip44Schema,
		},
	)
	require.NoError(t, err)
	require.Equal(t, bip44Schema, info.AddrSchema)

	info, err = store.GetAccount(
		t.Context(), db.GetAccountQuery{
			Scope: bip44Scope,
			Name:  &bip44Name,
		},
	)
	require.NoError(t, err)
	require.Equal(t, bip44Schema, info.AddrSchema)

	bip44ScopedMgr, err := store.addrStore.FetchScopedKeyManager(
		waddrmgr.KeyScope(bip44Scope),
	)
	require.NoError(t, err)

	err = walletdb.View(store.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)

		accountNumber, err := bip44ScopedMgr.LookupAccount(
			ns, bip44Name,
		)
		if err != nil {
			return err
		}

		props, err := bip44ScopedMgr.AccountProperties(
			ns, accountNumber,
		)
		if err != nil {
			return err
		}

		require.NotNil(t, props.AddrSchema)
		require.Equal(
			t, waddrmgr.ScopeAddrSchema{
				ExternalAddrType: waddrmgr.PubKeyHash,
				InternalAddrType: waddrmgr.PubKeyHash,
			}, *props.AddrSchema,
		)

		return nil
	})
	require.NoError(t, err)
}

// newCreditedFixture builds an account store backed by a spendable wallet
// with a wired-up wtxmgr txStore and returns a helper that credits a
// confirmed UTXO at the next external address of a derived account.
func newCreditedFixture(t *testing.T) (
	*Store, *waddrmgr.Manager, *wtxmgr.Store, func()) {

	t.Helper()

	dbConn, cleanup := newTestDB(t)
	mgr := newSpendableAddrMgr(t, dbConn)
	txStore := newTxStore(t, dbConn)

	err := walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)
		return mgr.Unlock(ns, []byte("priv"))
	})
	require.NoError(t, err)

	cleanupAll := func() {
		_ = mgr.Lock()
		mgr.Close()
		cleanup()
	}

	return NewStore(dbConn, txStore, mgr), mgr, txStore, cleanupAll
}

// creditNextAccountAddress derives the next external address for the
// given (scope, account) and inserts a confirmed wtxmgr credit paying
// the requested amount to that address at the given height. The test
// pre-advances the wallet's synced height past `confirmedAtHeight` so
// the credit counts as confirmed.
func creditNextAccountAddress(t *testing.T, dbConn walletdb.DB,
	mgr *waddrmgr.Manager, txStore *wtxmgr.Store,
	scope waddrmgr.KeyScope, account uint32,
	amount btcutil.Amount) {

	t.Helper()

	// All callers credit at the same confirmation height — hard-code
	// here so the test signature stays terse.
	const confirmedAtHeight int32 = 100

	scopedMgr, err := mgr.FetchScopedKeyManager(scope)
	require.NoError(t, err)

	var pkScript []byte

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)

		addrs, err := scopedMgr.NextExternalAddresses(ns, account, 1)
		if err != nil {
			return err
		}

		require.Len(t, addrs, 1)

		pkScript, err = txscript.PayToAddrScript(addrs[0].Address())

		return err
	})
	require.NoError(t, err)

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash: chainhash.Hash{0x01},
	}})
	txMsg.AddTxOut(&wire.TxOut{
		Value:    int64(amount),
		PkScript: pkScript,
	})

	rec, err := wtxmgr.NewTxRecordFromMsgTx(txMsg, time.Now())
	require.NoError(t, err)

	blockHash := chainhash.Hash{byte(confirmedAtHeight)}
	block := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Hash: blockHash, Height: confirmedAtHeight},
		Time:  time.Now(),
	}

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)

		err := txStore.InsertTx(ns, rec, block)
		if err != nil {
			return err
		}

		return txStore.AddCredit(ns, rec, block, 0, false)
	})
	require.NoError(t, err)

	// Advance the wallet's synced height so the credit is confirmed.
	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)

		return mgr.SetSyncedTo(ns, &waddrmgr.BlockStamp{
			Hash:   blockHash,
			Height: confirmedAtHeight,
		})
	})
	require.NoError(t, err)
}

// TestGetAccountPopulatesBalance verifies that GetAccount returns
// non-zero ConfirmedBalance when the wallet owns a confirmed unspent
// output for the requested account.
func TestGetAccountPopulatesBalance(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	account := createDerivedAccount(
		t, store.db, mgr, waddrmgr.KeyScopeBIP0084, savingsAccountName,
	)

	const utxoAmount = btcutil.Amount(50_000)
	creditNextAccountAddress(
		t, store.db, mgr, txStore,
		waddrmgr.KeyScopeBIP0084, account, utxoAmount,
	)

	name := savingsAccountName
	info, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		Scope: db.KeyScope{
			Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
			Coin:    waddrmgr.KeyScopeBIP0084.Coin,
		},
		Name: &name,
	})
	require.NoError(t, err)
	require.Equal(t, utxoAmount, info.ConfirmedBalance)
	require.Zero(t, info.UnconfirmedBalance)
}

// TestGetAccountSkipBalanceZeros verifies that GetAccount with
// SkipBalance=true returns a zero ConfirmedBalance even when the
// account owns an unspent output.
func TestGetAccountSkipBalanceZeros(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	account := createDerivedAccount(
		t, store.db, mgr, waddrmgr.KeyScopeBIP0084, savingsAccountName,
	)

	creditNextAccountAddress(
		t, store.db, mgr, txStore,
		waddrmgr.KeyScopeBIP0084, account, 50_000,
	)

	name := savingsAccountName
	info, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		Scope: db.KeyScope{
			Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
			Coin:    waddrmgr.KeyScopeBIP0084.Coin,
		},
		Name:        &name,
		SkipBalance: true,
	})
	require.NoError(t, err)
	require.Zero(t, info.ConfirmedBalance)
	require.Zero(t, info.UnconfirmedBalance)
}

// TestGetAccountImportedPopulatesBalance verifies that GetAccount attaches
// the correct balance for imported accounts, even though their public
// AccountNumber is nil.
func TestGetAccountImportedPopulatesBalance(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	// Create an imported account via the kvdb adapter.
	scope := db.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0084.Coin,
	}

	xpub, err := hdkeychain.NewKeyFromString(
		"xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6o" +
			"DMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
	)
	require.NoError(t, err)

	importedInfo, err := store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			Scope:      scope,
			Name:       "test-imported",
			PublicKey:  []byte(xpub.String()),
			AddrSchema: nil,
			DryRun:     false,
		},
	)
	require.NoError(t, err)
	require.True(t, importedInfo.IsImported)
	require.Nil(t, importedInfo.AccountNumber,
		"imported account public number must be nil")

	// Resolve the internal waddrmgr account number by name so we can
	// credit it with a UTXO.
	var internalAccountNumber uint32

	err = walletdb.View(store.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)

		scopedMgr, err := mgr.FetchScopedKeyManager(
			waddrmgr.KeyScope{
				Purpose: scope.Purpose,
				Coin:    scope.Coin,
			},
		)
		if err != nil {
			return err
		}

		internalAccountNumber, err = scopedMgr.LookupAccount(
			ns, "test-imported",
		)

		return err
	})
	require.NoError(t, err)
	require.NotEqual(
		t, uint32(0), internalAccountNumber,
		"internal account number must not be 0",
	)

	// Credit the imported account with a UTXO at its next external address.
	const utxoAmount = btcutil.Amount(75_000)
	creditNextAccountAddress(
		t, store.db, mgr, txStore,
		waddrmgr.KeyScope{
			Purpose: scope.Purpose,
			Coin:    scope.Coin,
		},
		internalAccountNumber,
		utxoAmount,
	)

	// GetAccount by name should now return the balance.
	name := "test-imported"
	info, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		Scope:       scope,
		Name:        &name,
		SkipBalance: false,
	})
	require.NoError(t, err)
	require.True(t, info.IsImported)
	require.Nil(t, info.AccountNumber)
	require.Equal(t, utxoAmount, info.ConfirmedBalance)
	require.Zero(t, info.UnconfirmedBalance)
}

// TestListAccountsScopeFilter verifies that ListAccounts narrows to the
// requested scope.
func TestListAccountsScopeFilter(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	createDerivedAccount(
		t, store.db, mgr, waddrmgr.KeyScopeBIP0084, savingsAccountName,
	)
	createDerivedAccount(
		t, store.db, mgr, waddrmgr.KeyScopeBIP0086, "stash",
	)

	scope := db.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0084.Coin,
	}
	accounts, err := store.ListAccounts(t.Context(), db.ListAccountsQuery{
		Scope: &scope,
	})
	require.NoError(t, err)

	// The default account ("default") plus savingsAccountName.
	require.GreaterOrEqual(t, len(accounts), 2)

	names := make(map[string]bool, len(accounts))
	for _, a := range accounts {
		names[a.AccountName] = true
		require.Equal(t, scope, a.KeyScope)
	}

	require.True(t, names[savingsAccountName])
	require.False(t, names["stash"], "stash should be filtered out")
}

// TestListAccountsNameFilter verifies that ListAccounts narrows by name.
func TestListAccountsNameFilter(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	createDerivedAccount(
		t, store.db, mgr, waddrmgr.KeyScopeBIP0084, savingsAccountName,
	)

	name := savingsAccountName
	accounts, err := store.ListAccounts(t.Context(), db.ListAccountsQuery{
		Name: &name,
	})
	require.NoError(t, err)
	require.Len(t, accounts, 1)
	require.Equal(t, savingsAccountName, accounts[0].AccountName)
}

// TestListAccountsSortedByAccountNumber verifies ListAccounts returns account
// snapshots in numeric order, not little-endian bucket-key order.
func TestListAccountsSortedByAccountNumber(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	// Account 256 sorts before account 1 if the raw little-endian bucket
	// keys are returned directly.
	for i := uint32(1); i <= 256; i++ {
		createDerivedAccount(
			t, store.db, mgr, waddrmgr.KeyScopeBIP0084,
			fmt.Sprintf("account-%03d", i),
		)
	}

	scope := db.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0084.Coin,
	}
	accounts, err := store.ListAccounts(t.Context(), db.ListAccountsQuery{
		Scope:       &scope,
		SkipBalance: true,
	})
	require.NoError(t, err)
	require.Len(t, accounts, 257)

	for i, account := range accounts {
		require.NotNil(t, account.AccountNumber)
		require.Equal(t, uint32(i), *account.AccountNumber)
	}
}

// TestListAccountsPopulatesBalance verifies that ListAccounts
// attaches confirmed balances to each account from the same scope.
func TestListAccountsPopulatesBalance(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	account := createDerivedAccount(
		t, store.db, mgr, waddrmgr.KeyScopeBIP0084, savingsAccountName,
	)

	const utxoAmount = btcutil.Amount(70_000)
	creditNextAccountAddress(
		t, store.db, mgr, txStore,
		waddrmgr.KeyScopeBIP0084, account, utxoAmount,
	)

	scope := db.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0084.Coin,
	}
	accounts, err := store.ListAccounts(t.Context(), db.ListAccountsQuery{
		Scope: &scope,
	})
	require.NoError(t, err)

	var found bool
	for _, a := range accounts {
		if a.AccountNumber == nil || *a.AccountNumber != account {
			continue
		}

		found = true

		require.Equal(t, utxoAmount, a.ConfirmedBalance)
		require.Zero(t, a.UnconfirmedBalance)
	}

	require.True(t, found, "savings account missing from list")
}

// TestListAccountsSkipBalanceZeros verifies that SkipBalance=true
// on ListAccounts leaves every account's balance fields at zero even
// when unspent outputs exist.
func TestListAccountsSkipBalanceZeros(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	account := createDerivedAccount(
		t, store.db, mgr, waddrmgr.KeyScopeBIP0084, savingsAccountName,
	)

	creditNextAccountAddress(
		t, store.db, mgr, txStore,
		waddrmgr.KeyScopeBIP0084, account, 70_000,
	)

	scope := db.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0084.Coin,
	}
	accounts, err := store.ListAccounts(t.Context(), db.ListAccountsQuery{
		Scope:       &scope,
		SkipBalance: true,
	})
	require.NoError(t, err)

	for _, a := range accounts {
		require.Zerof(
			t, a.ConfirmedBalance,
			"account %q should have zero confirmed balance",
			a.AccountName,
		)
		require.Zerof(
			t, a.UnconfirmedBalance,
			"account %q should have zero unconfirmed balance",
			a.AccountName,
		)
	}
}

// TestListAccountsMissingScopeReturnsEmpty verifies that a ListAccounts query
// for a scope with no registered scoped key manager returns an empty result
// with a nil error, preserving parity with the SQL backend rather than
// surfacing ErrScopeNotFound/ErrAccountNotFound.
func TestListAccountsMissingScopeReturnsEmpty(t *testing.T) {
	t.Parallel()

	store, _, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	scope := db.KeyScope{Purpose: 1234, Coin: 0}
	accounts, err := store.ListAccounts(t.Context(), db.ListAccountsQuery{
		Scope:       &scope,
		SkipBalance: true,
	})
	require.NoError(t, err)
	require.Empty(t, accounts)
}

// TestCreateImportedAccountAllowsMultipleInScope verifies kvdb retains the
// legacy watch-only account behavior: imported accounts share the normal
// per-scope account counter, so multiple imported accounts can exist in the
// same scope under different names.
func TestCreateImportedAccountAllowsMultipleInScope(t *testing.T) {
	t.Parallel()

	// Retain supplied metadata through the optional Store input.
	fingerprint := uint32(0xDEADBEEF)
	otherFingerprint := uint32(0xFEEDFACE)

	// Arrange: distinct XPub payloads share the legacy allocation cursor.
	store, _, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	seed := bytes.Repeat([]byte{0xCC}, hdkeychain.RecommendedSeedLen)
	master, err := hdkeychain.NewMaster(seed, &chaincfg.SimNetParams)
	require.NoError(t, err)
	masterPub, err := master.Neuter()
	require.NoError(t, err)

	secondPub, err := masterPub.Derive(1)
	require.NoError(t, err)

	scope := db.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0084.Coin,
	}

	// Act: persist two independent identities under different names.
	first, err := store.CreateImportedAccount(t.Context(),
		db.CreateImportedAccountParams{
			Scope:             scope,
			Name:              "alice-import",
			MasterFingerprint: &fingerprint,
			PublicKey:         []byte(masterPub.String()),
		},
	)
	require.NoError(t, err)
	require.NotNil(t, first)
	require.Equal(t, "alice-import", first.AccountName)

	second, err := store.CreateImportedAccount(t.Context(),
		db.CreateImportedAccountParams{
			Scope:             scope,
			Name:              "bob-import",
			MasterFingerprint: &otherFingerprint,
			PublicKey:         []byte(secondPub.String()),
		},
	)
	require.NoError(t, err)
	require.NotNil(t, second)
	require.Equal(t, "bob-import", second.AccountName)

	// Assert: the second account follows the first without a cursor gap.
	mgrScope := waddrmgr.KeyScope(scope)
	scopedMgr, err := store.addrStore.FetchScopedKeyManager(mgrScope)
	require.NoError(t, err)

	var firstNumber, secondNumber uint32

	err = walletdb.View(store.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)

		var err error

		firstNumber, err = scopedMgr.LookupAccount(
			ns, first.AccountName,
		)
		if err != nil {
			return err
		}

		secondNumber, err = scopedMgr.LookupAccount(
			ns, second.AccountName,
		)
		if err != nil {
			return err
		}

		return nil
	})
	require.NoError(t, err)
	require.Equal(t, firstNumber+1, secondNumber)

	got, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		Scope: scope,
		Name:  &second.AccountName,
	})
	require.NoError(t, err)
	require.Equal(t, "bob-import", got.AccountName)
	require.NotNil(t, got.MasterKeyFingerprint)
	require.Equal(t, uint32(0xFEEDFACE), *got.MasterKeyFingerprint)
}

// TestCreateImportedAccountIdentity checks admission before children exist,
// including serialization metadata and per-account branch schema overrides.
func TestCreateImportedAccountIdentity(t *testing.T) {
	t.Parallel()

	// Arrange: keep the derivation payload fixed while varying origin and
	// version metadata, so only the effective branch schemas decide overlap.
	master, err := hdkeychain.NewMaster(
		bytes.Repeat([]byte{0xCC}, 32), &chaincfg.SimNetParams,
	)
	require.NoError(t, err)
	key, err := master.Neuter()
	require.NoError(t, err)
	pub, err := key.ECPubKey()
	require.NoError(t, err)

	alias := hdkeychain.NewExtendedKey(
		chaincfg.MainNetParams.HDPublicKeyID[:], pub.SerializeCompressed(),
		key.ChainCode(), []byte{1, 2, 3, 4}, 3, 42, false,
	)
	strict, err := db.ScopeAddrSchemaFromWaddrmgr(
		waddrmgr.KeyScopeBIP0049AddrSchema,
	)
	require.NoError(t, err)

	tests := []struct {
		name   string
		scope  db.KeyScope
		schema *db.ScopeAddrSchema
		dryRun bool
		want   error
	}{
		{
			name:  "same scope",
			scope: db.KeyScopeBIP0084,
			want:  db.ErrAccountIdentityCollision,
		},
		{
			name:  "internal overlap across scopes",
			scope: db.KeyScopeBIP0049Plus,
			want:  db.ErrAccountIdentityCollision,
		},
		{
			name:   "strict nested disjoint",
			scope:  db.KeyScopeBIP0049Plus,
			schema: &strict,
		},
		{
			name:   "preview collision",
			scope:  db.KeyScopeBIP0084,
			dryRun: true,
			want:   db.ErrAccountIdentityCollision,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: one childless imported account owns this payload;
			// the snapshot includes all pre-existing derived accounts.
			store, _, cleanup := newAccountStoreFixture(t)
			t.Cleanup(cleanup)

			params := db.CreateImportedAccountParams{
				Scope:     db.KeyScopeBIP0084,
				Name:      "owner",
				PublicKey: []byte(key.String()),
			}
			_, err := store.CreateImportedAccount(t.Context(), params)
			require.NoError(t, err)

			query := db.ListAccountsQuery{SkipBalance: true}
			before, err := store.ListAccounts(t.Context(), query)
			require.NoError(t, err)

			params.Scope, params.AddrSchema = tc.scope, tc.schema
			params.Name, params.DryRun = "candidate", tc.dryRun
			params.PublicKey = []byte(alias.String())

			// Vary supplied metadata without changing script ownership.
			fingerprint := uint32(123)
			params.MasterFingerprint = &fingerprint

			// Act: admit the same payload through the ordinary Store path.
			info, err := store.CreateImportedAccount(t.Context(), params)

			// Assert: disjoint schemas remain usable; collisions leave the
			// complete childless inventory unchanged and return no account.
			require.ErrorIs(t, err, tc.want)
			after, err := store.ListAccounts(t.Context(), query)
			require.NoError(t, err)

			if tc.want != nil {
				require.Nil(t, info)
				require.ElementsMatch(t, before, after)
			} else {
				require.NotNil(t, info)
				require.Len(t, after, len(before)+1)
			}
		})
	}
}

// TestCreateImportedAccountIdentityNamePrecedence verifies that an occupied
// name retains its own error even when the requested XPub also collides.
func TestCreateImportedAccountIdentityNamePrecedence(t *testing.T) {
	t.Parallel()

	// Arrange: persist one imported owner and reuse its name and public key
	// so each retry would also collide by script identity.
	store, _, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	master, err := hdkeychain.NewMaster(
		bytes.Repeat([]byte{0xCE}, 32), &chaincfg.SimNetParams,
	)
	require.NoError(t, err)
	key, err := master.Neuter()
	require.NoError(t, err)

	params := db.CreateImportedAccountParams{
		Scope:     db.KeyScopeBIP0084,
		Name:      "owner",
		PublicKey: []byte(key.String()),
	}
	_, err = store.CreateImportedAccount(t.Context(), params)
	require.NoError(t, err)

	query := db.ListAccountsQuery{SkipBalance: true}
	before, err := store.ListAccounts(t.Context(), query)
	require.NoError(t, err)

	// Act: retry the occupied request to exercise stable name precedence.
	for range 2 {
		info, err := store.CreateImportedAccount(t.Context(), params)

		// Assert: each retry reports the name conflict and commits no row.
		require.ErrorIs(t, err, db.ErrAccountNameConflict)
		require.Nil(t, info)
	}

	// Assert: neither retry changes the visible account inventory.
	after, err := store.ListAccounts(t.Context(), query)
	require.NoError(t, err)
	require.ElementsMatch(t, before, after)
}

// TestCreateImportedAccountIdentityConcurrent checks account admission waits
// for scope registration without admitting duplicate owners or consuming IDs.
func TestCreateImportedAccountIdentityConcurrent(t *testing.T) {
	t.Parallel()

	missing := db.KeyScope{Purpose: 1017, Coin: 0}
	otherMissing := db.KeyScope{Purpose: 1018, Coin: 0}
	schema := db.ScopeAddrMap[db.KeyScopeBIP0084]

	tests := []struct {
		name       string
		firstScope db.KeyScope
		scope      db.KeyScope
		other      string
		want       error
		wantSlot   uint32
	}{
		{
			name:       "same scope",
			firstScope: db.KeyScopeBIP0084,
			scope:      db.KeyScopeBIP0084,
			other:      "second",
			want:       db.ErrAccountIdentityCollision,
			wantSlot:   1,
		},
		{
			name:       "cross scope",
			firstScope: db.KeyScopeBIP0084,
			scope:      db.KeyScopeBIP0049Plus,
			other:      "second",
			want:       db.ErrAccountIdentityCollision,
			wantSlot:   1,
		},
		{
			name:       "occupied name",
			firstScope: db.KeyScopeBIP0084,
			scope:      db.KeyScopeBIP0084,
			other:      "first",
			want:       db.ErrAccountNameConflict,
			wantSlot:   1,
		},
		{
			name:       "missing same scope",
			firstScope: missing,
			scope:      missing,
			other:      "second",
			want:       db.ErrAccountIdentityCollision,
			wantSlot:   0,
		},
		{
			name:       "missing cross scope",
			firstScope: missing,
			scope:      otherMissing,
			other:      "second",
			want:       db.ErrAccountIdentityCollision,
			wantSlot:   0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: both workers wait at a shared start barrier; buffered
			// outcomes let every worker finish even if an assertion fails.
			// Missing scopes exercise the commit/registration interval;
			// their legacy numberless allocator starts at slot zero.
			store, _, cleanup := newAccountStoreFixture(t)
			t.Cleanup(cleanup)

			key, err := hdkeychain.NewMaster(
				bytes.Repeat([]byte{0xCD}, 32), &chaincfg.SimNetParams,
			)
			require.NoError(t, err)
			pub, err := key.Neuter()
			require.NoError(t, err)

			start := make(chan struct{})
			results := make(chan error, 2)

			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			for _, params := range []db.CreateImportedAccountParams{
				{
					Scope:      tc.firstScope,
					Name:       "first",
					PublicKey:  []byte(pub.String()),
					AddrSchema: &schema,
				},
				{
					Scope:      tc.scope,
					Name:       tc.other,
					PublicKey:  []byte(pub.String()),
					AddrSchema: &schema,
				},
			} {
				go func() {
					<-start

					_, err := store.CreateImportedAccount(ctx, params)
					results <- err
				}()
			}

			// Act: release both requests before waiting for either outcome.
			close(start)

			firstErr, secondErr := <-results, <-results

			// Assert: exactly one request wins and the other is classified.
			if firstErr != nil {
				firstErr, secondErr = secondErr, firstErr
			}

			require.NoError(t, firstErr)
			require.ErrorIs(t, secondErr, tc.want)

			accounts, err := store.ListAccounts(ctx, db.ListAccountsQuery{
				SkipBalance: true,
			})
			require.NoError(t, err)

			var imported int
			for _, account := range accounts {
				if account.IsImported {
					imported++

					require.Equal(t, tc.wantSlot, *account.AccountID)
				}
			}

			require.Equal(t, 1, imported)

			// The sum of scope cursors exposes allocation by either loser.
			var allocated uint32

			err = walletdb.View(store.db, func(tx walletdb.ReadTx) error {
				managers := store.addrStore.ActiveScopedKeyManagers()
				for _, scoped := range managers {
					last, err := scoped.LastAccount(
						tx.ReadBucket(waddrmgr.NamespaceKey),
					)
					if err != nil {
						return err
					}

					allocated += last
				}

				return nil
			})
			require.NoError(t, err)
			require.Equal(t, tc.wantSlot, allocated)
		})
	}
}

// TestCreateDerivedAccountIdentityRollback verifies a collision cannot persist
// keys or consume the account number allocated before the derivation callback.
func TestCreateDerivedAccountIdentityRollback(t *testing.T) {
	t.Parallel()

	// Arrange: return the existing default account's XPub with otherwise valid
	// private material, forcing refusal after the sequential allocation.
	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	query := db.ListAccountsQuery{SkipBalance: true}
	before, err := store.ListAccounts(t.Context(), query)
	require.NoError(t, err)

	zero := uint32(0)
	owner, err := store.GetAccount(t.Context(), db.GetAccountQuery{
		Scope:         db.KeyScopeBIP0084,
		AccountNumber: &zero,
		SkipBalance:   true,
	})
	require.NoError(t, err)
	derive := kvdbDeriveFnFixture(t, mgr)
	collision := func(ctx context.Context, scope db.KeyScope, number uint32,
		watchOnly bool) (*db.DerivedAccountData, error) {

		data, err := derive(ctx, scope, number, watchOnly)
		if err == nil {
			data.PublicKey = owner.PublicKey
		}

		return data, err
	}
	params := db.CreateDerivedAccountParams{
		Scope: db.KeyScopeBIP0084,
		Name:  "candidate",
	}

	// Act: force identity refusal after allocation and private-key preparation.
	info, err := store.CreateDerivedAccount(t.Context(), params, collision)

	// Assert: no account or child state survives, and a successful retry uses
	// the same name and first available number without a stale cache entry.
	require.ErrorIs(t, err, db.ErrAccountIdentityCollision)
	require.Nil(t, info)
	after, err := store.ListAccounts(t.Context(), query)
	require.NoError(t, err)
	require.ElementsMatch(t, before, after)
	next, err := store.CreateDerivedAccount(t.Context(), params, derive)
	require.NoError(t, err)
	require.Equal(t, uint32(1), *next.AccountNumber)
}

// TestCreateImportedAccountNumberedCursor verifies exact imports and lower
// holes share the native cursor without numbering later inferred imports.
func TestCreateImportedAccountNumberedCursor(t *testing.T) {
	t.Parallel()

	// Arrange: use kvdbDeriveFnFixture to derive keys from the fixture seed
	// without creating rows, so only the subject imports advance allocation.
	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	scoped, err := mgr.FetchScopedKeyManager(scope)
	require.NoError(t, err)

	derive := kvdbDeriveFnFixture(t, mgr)

	number, hole := uint32(7), uint32(2)
	cases := []struct {
		name   string
		number *uint32
		child  uint32
	}{
		{
			name:   "exact import",
			number: &number,
			child:  number,
		},
		{
			name:   "lower hole",
			number: &hole,
			child:  hole,
		},
		{
			name:  "inferred next",
			child: number + 1,
		},
	}

	params := make([]db.CreateImportedAccountParams, len(cases))
	for i, tc := range cases {
		data, err := derive(t.Context(), db.KeyScope(scope), tc.child, false)
		require.NoError(t, err)

		params[i] = db.CreateImportedAccountParams{
			Scope:         db.KeyScope(scope),
			Name:          tc.name,
			AccountNumber: tc.number,
			PublicKey:     data.PublicKey,
		}
	}

	// Act: import the high slot, then its lower hole, then an inferred account.
	infos := make([]*db.AccountInfo, len(params))
	for i, input := range params {
		infos[i], err = store.CreateImportedAccount(t.Context(), input)
		require.NoError(t, err)
	}

	// Assert: exact paths remain known while the inferred key stays numberless,
	// even though its key child and assigned slot coincide. The native public
	// cursor must continue beyond the high slot without rewinding to the hole.
	for i, tc := range cases {
		require.Equal(t, tc.number, infos[i].AccountNumber)
	}

	var last uint32

	err = walletdb.View(store.db, func(tx walletdb.ReadTx) error {
		var err error

		last, err = scoped.LastAccount(tx.ReadBucket(waddrmgr.NamespaceKey))

		return err
	})
	require.NoError(t, err)
	require.Equal(t, number+1, last)
}

// TestCreateImportedAccountNumberedConflict verifies every occupied native slot
// is protected, including numberless imports, before key-identity checks run.
func TestCreateImportedAccountNumberedConflict(t *testing.T) {
	t.Parallel()

	number := uint32(7)
	cases := []struct {
		name        string
		ownerNumber *uint32
		ownerChild  uint32
	}{
		{
			name:        "numbered same key",
			ownerNumber: &number,
			ownerChild:  number,
		},
		{
			name:       "numberless different key",
			ownerChild: 2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: derive fixture keys without creating accounts, then
			// import the owner and resolve its native slot with LookupAccount.
			// The contender at that slot reuses the numbered owner's key but
			// differs from the numberless owner's, isolating slot admission.
			store, mgr, cleanup := newAccountStoreFixture(t)
			t.Cleanup(cleanup)

			scope := waddrmgr.KeyScopeBIP0084
			scoped, err := mgr.FetchScopedKeyManager(scope)
			require.NoError(t, err)

			derive := kvdbDeriveFnFixture(t, mgr)
			ownerData, err := derive(
				t.Context(), db.KeyScope(scope), tc.ownerChild, false,
			)
			require.NoError(t, err)

			params := db.CreateImportedAccountParams{
				Scope:         db.KeyScope(scope),
				Name:          "slot owner",
				AccountNumber: tc.ownerNumber,
				PublicKey:     ownerData.PublicKey,
			}
			owner, err := store.CreateImportedAccount(t.Context(), params)
			require.NoError(t, err)

			var slot uint32

			err = walletdb.View(store.db, func(tx walletdb.ReadTx) error {
				ns := tx.ReadBucket(waddrmgr.NamespaceKey)

				var err error

				slot, err = scoped.LookupAccount(ns, params.Name)

				return err
			})
			require.NoError(t, err)
			contender, err := derive(
				t.Context(), db.KeyScope(scope), slot, false,
			)
			require.NoError(t, err)

			params.Name = "slot contender"
			params.AccountNumber = &slot
			params.PublicKey = contender.PublicKey

			// Act: declare the occupied number under a different name
			// through Store, which must refuse before replacing any key.
			info, err := store.CreateImportedAccount(t.Context(), params)

			// Assert: slot refusal wins over key collision, no result
			// escapes, and the complete owner remains unchanged by name,
			// including its numberless status when no path was declared.
			require.ErrorIs(t, err, db.ErrAccountNumberConflict)
			require.Nil(t, info)
			stored, err := store.GetAccount(t.Context(), db.GetAccountQuery{
				Scope:       db.KeyScope(scope),
				Name:        &owner.AccountName,
				SkipBalance: true,
			})
			require.NoError(t, err)
			require.Equal(t, tc.ownerNumber, stored.AccountNumber)
			require.Equal(t, owner, stored)
		})
	}
}

// TestCreateImportedAccountNumberedPreview verifies preview retains the known
// number without occupying its slot or consuming committed child indexes.
func TestCreateImportedAccountNumberedPreview(t *testing.T) {
	t.Parallel()

	// Arrange: derive a fixture key without creating a row and use an existing
	// scope, isolating preview rollback from legacy scope registration.
	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	derive := kvdbDeriveFnFixture(t, mgr)

	number := uint32(7)

	data, err := derive(t.Context(), db.KeyScope(scope), number, false)
	require.NoError(t, err)

	params := db.CreateImportedAccountParams{
		Scope:         db.KeyScope(scope),
		Name:          "numbered preview",
		AccountNumber: &number,
		PublicKey:     data.PublicKey,
		DryRun:        true,
	}

	// Act: preview the numbered write with transaction rollback enabled.
	preview, err := store.CreateImportedAccount(t.Context(), params)

	// Assert: preview reports the known path but no persisted account resolves.
	// Committing the identical request proves rollback left the slot reusable
	// and both address branches start at their unconsumed index zero.
	require.NoError(t, err)
	require.Equal(t, &number, preview.AccountNumber)
	_, err = store.GetAccount(t.Context(), db.GetAccountQuery{
		Scope:         db.KeyScope(scope),
		AccountNumber: &number,
		SkipBalance:   true,
	})
	require.ErrorIs(t, err, db.ErrAccountNotFound)

	params.DryRun = false
	created, err := store.CreateImportedAccount(t.Context(), params)
	require.NoError(t, err)
	require.Equal(t, &number, created.AccountNumber)
	require.Zero(t, created.ExternalKeyCount)
	require.Zero(t, created.InternalKeyCount)
}

// TestCreateImportedAccountNumberedExhaustion verifies a cursor jump to the
// maximum cannot let the next inferred import overwrite the raw-import bucket.
func TestCreateImportedAccountNumberedExhaustion(t *testing.T) {
	t.Parallel()

	// Arrange: derive keys with the existing fixture without allocating rows,
	// import the maximum, and retain the raw pseudo-account before exhaustion.
	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	scoped, err := mgr.FetchScopedKeyManager(scope)
	require.NoError(t, err)

	derive := kvdbDeriveFnFixture(t, mgr)

	number := db.MaxAccountNumber

	data, err := derive(t.Context(), db.KeyScope(scope), number, false)
	require.NoError(t, err)
	next, err := derive(t.Context(), db.KeyScope(scope), 1, false)
	require.NoError(t, err)
	_, err = store.CreateImportedAccount(t.Context(),
		db.CreateImportedAccountParams{
			Scope:         db.KeyScope(scope),
			Name:          "last slot",
			AccountNumber: &number,
			PublicKey:     data.PublicKey,
		},
	)
	require.NoError(t, err)

	importedName := waddrmgr.ImportedAddrAccountName
	query := db.GetAccountQuery{
		Scope:       db.KeyScope(scope),
		Name:        &importedName,
		SkipBalance: true,
	}
	before, err := store.GetAccount(t.Context(), query)
	require.NoError(t, err)

	// Act: import an ordinary account after exhausting the shared sequence.
	info, err := store.CreateImportedAccount(t.Context(),
		db.CreateImportedAccountParams{
			Scope:     db.KeyScope(scope),
			Name:      "after limit",
			PublicKey: next.PublicKey,
		},
	)

	// Assert: the existing capacity identity replaces the reserved-slot write;
	// the pseudo-account and public native cursor remain exactly as committed.
	require.ErrorIs(t, err, db.ErrMaxAccountNumberReached)
	require.Nil(t, info)
	after, err := store.GetAccount(t.Context(), query)
	require.NoError(t, err)
	require.Equal(t, before, after)

	var last uint32

	err = walletdb.View(store.db, func(tx walletdb.ReadTx) error {
		var err error

		last, err = scoped.LastAccount(tx.ReadBucket(waddrmgr.NamespaceKey))

		return err
	})
	require.NoError(t, err)
	require.Equal(t, number, last)
}

// TestCreateImportedAccountNumberedDefaultConflict verifies collisions with a
// new spendable scope's seeded default are refused before scope registration.
func TestCreateImportedAccountNumberedDefaultConflict(t *testing.T) {
	t.Parallel()

	// Number, name and key collisions share the same fixture and refusal
	// assertions; keyChild varies the key independently of the supplied slot.
	cases := []struct {
		name        string
		number      uint32
		keyChild    uint32
		accountName string
		wantErr     error
	}{
		{
			name:        "default number",
			number:      waddrmgr.DefaultAccountNum,
			keyChild:    waddrmgr.DefaultAccountNum,
			accountName: "default contender",
			wantErr:     db.ErrAccountNumberConflict,
		},
		{
			name:        "default name at nonzero number",
			number:      7,
			keyChild:    7,
			accountName: waddrmgr.DefaultAccountName,
			wantErr:     db.ErrAccountNameConflict,
		},
		{
			name:        "default key at nonzero number",
			number:      7,
			keyChild:    waddrmgr.DefaultAccountNum,
			accountName: "default key contender",
			wantErr:     db.ErrAccountIdentityCollision,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: derive a valid XPub for an absent spendable scope
			// without creating a row, and retain the public account list.
			// Registration would seed default at zero before the import.
			store, mgr, cleanup := newAccountStoreFixture(t)
			t.Cleanup(cleanup)

			scope := db.KeyScope{
				Purpose: 1017,
				Coin:    0,
			}
			schema := db.ScopeAddrSchema{
				ExternalAddrType: db.WitnessPubKey,
				InternalAddrType: db.WitnessPubKey,
			}
			derive := kvdbDeriveFnFixture(t, mgr)
			data, err := derive(t.Context(), scope, tc.keyChild, false)
			require.NoError(t, err)

			query := db.ListAccountsQuery{
				SkipBalance: true,
			}
			before, err := store.ListAccounts(t.Context(), query)
			require.NoError(t, err)

			// Act: import an account whose supplied number, name or key
			// collides with the default that registration would create.
			info, err := store.CreateImportedAccount(t.Context(),
				db.CreateImportedAccountParams{
					Scope:         scope,
					Name:          tc.accountName,
					AccountNumber: &tc.number,
					PublicKey:     data.PublicKey,
					AddrSchema:    &schema,
				},
			)

			// Assert: admission returns the conflict without an account
			// or registered scope. Listing remains usable and unchanged,
			// proving rollback cannot leave a manager for missing data.
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, info)
			after, err := store.ListAccounts(t.Context(), query)
			require.NoError(t, err)
			require.ElementsMatch(t, before, after)

			_, err = mgr.FetchScopedKeyManager(waddrmgr.KeyScope(scope))
			require.True(t, waddrmgr.IsError(err, waddrmgr.ErrScopeNotFound))
		})
	}
}

// TestCreateImportedAccountDefaultIdentity checks that scope creation admits
// its additional default account before assigning a second owner of its keys.
func TestCreateImportedAccountDefaultIdentity(t *testing.T) {
	t.Parallel()

	// Both rows create a stored owner; only its key differs from the native
	// default. The request-only collision is in the default-conflict table.
	cases := []struct {
		name       string
		ownerChild uint32
		wantErr    error
	}{
		{
			name:       "existing owner matches default",
			ownerChild: 0,
			wantErr:    db.ErrAccountIdentityCollision,
		},
		{
			name:       "different existing owner",
			ownerChild: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange: derive keys for an absent spendable scope, whose
			// registration also creates account zero. Always import its
			// zero or one key under BIP84 so the same subject distinguishes
			// a duplicate default from an unrelated existing owner.
			store, mgr, cleanup := newAccountStoreFixture(t)
			t.Cleanup(cleanup)

			scope := db.KeyScope{
				Purpose: 1017,
				Coin:    0,
			}
			schema := db.ScopeAddrSchema{
				ExternalAddrType: db.WitnessPubKey,
				InternalAddrType: db.WitnessPubKey,
			}
			derive := kvdbDeriveFnFixture(t, mgr)
			data, err := derive(t.Context(), scope, 7, false)
			require.NoError(t, err)

			key, err := derive(t.Context(), scope, tc.ownerChild, false)
			require.NoError(t, err)
			owner, err := store.CreateImportedAccount(t.Context(),
				db.CreateImportedAccountParams{
					Scope:      db.KeyScopeBIP0084,
					Name:       "existing imported owner",
					PublicKey:  key.PublicKey,
					AddrSchema: &schema,
				},
			)
			require.NoError(t, err)

			query := db.ListAccountsQuery{
				SkipBalance: true,
			}
			before, err := store.ListAccounts(t.Context(), query)
			require.NoError(t, err)

			number := uint32(7)

			// Act: request the nonzero slot through Store, which accepts
			// key and number fields independently. Both the requested key
			// and the additional default must pass ownership admission.
			info, err := store.CreateImportedAccount(t.Context(),
				db.CreateImportedAccountParams{
					Scope:         scope,
					Name:          "declared import",
					AccountNumber: &number,
					PublicKey:     data.PublicKey,
					AddrSchema:    &schema,
				},
			)

			// Assert: either duplicate refuses the entire operation with
			// usable, unchanged listing and no registered scope. An
			// unrelated owner permits the import and remains unchanged.
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, info)
				after, err := store.ListAccounts(t.Context(), query)
				require.NoError(t, err)
				require.ElementsMatch(t, before, after)

				_, err = mgr.FetchScopedKeyManager(waddrmgr.KeyScope(scope))
				require.True(t, waddrmgr.IsError(
					err, waddrmgr.ErrScopeNotFound,
				))

				return
			}

			require.NoError(t, err)
			require.NotNil(t, info)

			stored, err := store.GetAccount(t.Context(), db.GetAccountQuery{
				Scope:       db.KeyScopeBIP0084,
				Name:        &owner.AccountName,
				SkipBalance: true,
			})
			require.NoError(t, err)
			require.Equal(t, owner, stored)
		})
	}
}

// TestRenameAccountNumberedImported checks the numeric rename selector accepts
// an imported account whose declared BIP44 number is retained by the store.
func TestRenameAccountNumberedImported(t *testing.T) {
	t.Parallel()

	// Arrange: import a valid fixture key at a declared number, keeping the
	// existing numberless/raw refusal tests as independent negative controls.
	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	scope := db.KeyScopeBIP0084
	number := uint32(7)
	derive := kvdbDeriveFnFixture(t, mgr)
	data, err := derive(t.Context(), scope, number, false)
	require.NoError(t, err)
	_, err = store.CreateImportedAccount(t.Context(),
		db.CreateImportedAccountParams{
			Scope:         scope,
			Name:          "numbered rename",
			AccountNumber: &number,
			PublicKey:     data.PublicKey,
		},
	)
	require.NoError(t, err)

	name := "renamed import"

	// Act: rename through the public number rather than the mutable name.
	err = store.RenameAccount(t.Context(), db.RenameAccountParams{
		Scope:         scope,
		AccountNumber: &number,
		NewName:       name,
	})

	// Assert: both public selectors read the new name and unchanged declared
	// number, proving numeric rename does not discard the import's known path.
	require.NoError(t, err)

	for _, query := range []db.GetAccountQuery{
		{
			Scope:         scope,
			AccountNumber: &number,
			SkipBalance:   true,
		},
		{
			Scope:       scope,
			Name:        &name,
			SkipBalance: true,
		},
	} {
		info, err := store.GetAccount(t.Context(), query)
		require.NoError(t, err)
		require.Equal(t, name, info.AccountName)
		require.Equal(t, &number, info.AccountNumber)
	}
}
