//go:build itest

package itest

import (
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/stretchr/testify/require"
)

// TestGetAccount verifies that GetAccount correctly retrieves accounts
// by name or account number.
func TestGetAccount(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)

	walletID := newWallet(t, store, "wallet-get-account")

	createAllAccounts(t, store, walletID)

	for _, tc := range AllAccountCases {
		accNumber := uint32(0)

		t.Run(
			"by name-"+tc.Name, func(t *testing.T) {
				query := getAccountQueryByName(walletID, tc.Scope, tc.Name)
				info, err := store.GetAccount(t.Context(), query)
				require.NoError(t, err)
				require.NotNil(t, info)
				requireAccountMatches(t, info, tc)

				if info.AccountNumber != nil {
					accNumber = *info.AccountNumber
				}
			},
		)

		if tc.IsImported {
			continue
		}

		t.Run(fmt.Sprintf("by number-%d-%s", accNumber, tc.Name),
			func(t *testing.T) {
				query := getAccountQueryByNumber(walletID, tc.Scope, accNumber)
				info, err := store.GetAccount(t.Context(), query)
				require.NoError(t, err)
				require.NotNil(t, info)
				requireAccountMatches(t, info, tc)
			},
		)
	}
}

// TestGetAccountWatchOnlyMapping verifies that GetAccount preserves
// representative watch-only flags on read.
func TestGetAccountWatchOnlyMapping(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-get-watch")
	scope := db.KeyScopeBIP0084

	createDerivedAccount(t, store, walletID, scope, "derived")

	_, err := store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			WalletID:            walletID,
			Name:                "imported-xpub",
			Scope:               scope,
			PublicKey:           RandomBytes(32),
			EncryptedPrivateKey: RandomBytes(32),
		},
	)
	require.NoError(t, err)

	derived, err := store.GetAccount(
		t.Context(), getAccountQueryByName(walletID, scope, "derived"),
	)
	require.NoError(t, err)
	require.False(t, derived.IsWatchOnly)

	imported, err := store.GetAccount(
		t.Context(), getAccountQueryByName(
			walletID, scope, "imported-xpub",
		),
	)
	require.NoError(t, err)
	// ADR 0012: imported accounts on a spendable wallet carry private-
	// key material, so they inherit the wallet's spendable state.
	require.False(t, imported.IsWatchOnly)
}

// TestGetAccountReturnsPublicKeyAndFingerprint verifies that derived and
// imported accounts re-read through GetAccount carry the public key and
// master fingerprint that were persisted at creation. Regression test
// for the pre-fix gap where AccountRowToInfo passed `nil, 0` for both
// fields on the lightweight read path.
func TestGetAccountReturnsPublicKeyAndFingerprint(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-pubkey-roundtrip")
	scope := db.KeyScopeBIP0084

	derived, err := store.CreateDerivedAccount(
		t.Context(), db.CreateDerivedAccountParams{
			WalletID: walletID,
			Scope:    scope,
			Name:     "derived",
		}, SpendableDeriveFn(),
	)
	require.NoError(t, err)
	require.NotEmpty(t, derived.PublicKey)
	require.NotZero(t, derived.MasterKeyFingerprint)

	derivedRead, err := store.GetAccount(
		t.Context(), getAccountQueryByName(walletID, scope, "derived"),
	)
	require.NoError(t, err)
	require.Equal(t, derived.PublicKey, derivedRead.PublicKey)
	require.Equal(t,
		derived.MasterKeyFingerprint, derivedRead.MasterKeyFingerprint,
	)

	importedPubKey := RandomBytes(32)
	_, err = store.CreateImportedAccount(
		t.Context(), db.CreateImportedAccountParams{
			WalletID:            walletID,
			Name:                "imported-xpub",
			Scope:               scope,
			PublicKey:           importedPubKey,
			EncryptedPrivateKey: RandomBytes(32),
		},
	)
	require.NoError(t, err)

	importedRead, err := store.GetAccount(
		t.Context(), getAccountQueryByName(walletID, scope, "imported-xpub"),
	)
	require.NoError(t, err)
	require.Equal(t, importedPubKey, importedRead.PublicKey)
}

// TestGetAccountPopulatesBalance verifies that GetAccount returns the
// confirmed and unconfirmed UTXO totals on the AccountInfo, sourced from
// the dedicated AccountBalance query that the adapter dispatches
// alongside the account row fetch.
func TestGetAccountPopulatesBalance(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-get-balance")
	scope := db.KeyScopeBIP0084

	queries := store.Queries()
	syncBlock := CreateBlockFixture(t, queries, 200)
	confirmedBlock := CreateBlockFixture(t, queries, 100)

	err := store.UpdateWallet(
		t.Context(), db.UpdateWalletParams{
			WalletID: walletID,
			SyncedTo: &syncBlock,
		},
	)
	require.NoError(t, err)

	createDerivedAccount(t, store, walletID, scope, "funded")
	createDerivedAccount(t, store, walletID, scope, "empty")

	addr := newDerivedAddress(t, store, walletID, scope, "funded", false)

	confirmedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 24000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(
		t.Context(), db.CreateTxParams{
			WalletID: walletID,
			Tx:       confirmedTx,
			Received: time.Unix(1710000000, 0),
			Block:    &confirmedBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	unconfirmedTx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 26000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(
		t.Context(), db.CreateTxParams{
			WalletID: walletID,
			Tx:       unconfirmedTx,
			Received: time.Unix(1710000100, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	funded, err := store.GetAccount(
		t.Context(), getAccountQueryByName(walletID, scope, "funded"),
	)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(24000), funded.ConfirmedBalance)
	require.Equal(t, btcutil.Amount(26000), funded.UnconfirmedBalance)

	byNumber, err := store.GetAccount(
		t.Context(),
		getAccountQueryByNumber(
			walletID, scope,
			accountNumberNotNil(t, funded.AccountNumber),
		),
	)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(24000), byNumber.ConfirmedBalance)
	require.Equal(t, btcutil.Amount(26000), byNumber.UnconfirmedBalance)

	empty, err := store.GetAccount(
		t.Context(), getAccountQueryByName(walletID, scope, "empty"),
	)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(0), empty.ConfirmedBalance)
	require.Equal(t, btcutil.Amount(0), empty.UnconfirmedBalance)
}

// TestAccountBalancesExcludeCorruptRawAddressChild verifies that account-level
// balance reads do not count raw imported addresses that have corrupt derived
// address child rows pointing at an account.
func TestAccountBalancesExcludeCorruptRawAddressChild(t *testing.T) {
	// The sqlite corruption helper temporarily drops a trigger, so this test
	// must not run in parallel with other database integration tests.
	store := NewTestStore(t)
	queries := store.Queries()
	walletID := newWatchOnlyWallet(t, store, "account-balance-corrupt-raw")
	scope := db.KeyScopeBIP0084
	accountName := fundedAccountName

	createDerivedAccount(t, store, walletID, scope, accountName)

	scopeID := GetKeyScopeID(t, queries, walletID, scope)
	accountID := GetAccountID(t, queries, scopeID, accountName)
	badScript := RandomBytes(22)
	imported, err := store.NewImportedAddress(
		t.Context(), db.NewImportedAddressParams{
			WalletID:     walletID,
			AddressType:  db.WitnessPubKey,
			PubKey:       RandomBytes(33),
			ScriptPubKey: badScript,
		},
	)
	require.NoError(t, err)

	err = insertCorruptDerivedAddressChildRaw(
		t, store.DB(), walletID, scopeID, accountID, int64(imported.ID),
		0, 0,
	)
	require.NoError(t, err)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 33000, PkScript: badScript}},
	)
	err = store.CreateTx(
		t.Context(), db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000400, 0),
			Status:   db.TxStatusPending,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	account, err := store.GetAccount(
		t.Context(), getAccountQueryByName(walletID, scope, accountName),
	)
	require.NoError(t, err)
	require.Zero(t, account.ConfirmedBalance)
	require.Zero(t, account.UnconfirmedBalance)

	accounts, err := store.ListAccounts(
		t.Context(), db.ListAccountsQuery{
			WalletID: walletID,
			Scope:    &scope,
		},
	)
	require.NoError(t, err)

	listed := findAccountInList(t, accounts, AccountTestCase{
		Name:  accountName,
		Scope: scope,
	})
	require.Zero(t, listed.ConfirmedBalance)
	require.Zero(t, listed.UnconfirmedBalance)
}

// TestGetAccountSkipBalanceZerosFields verifies that GetAccount with
// SkipBalance=true skips the dedicated AccountBalance dispatch on both
// the by-name and by-number selectors and leaves the balance fields at
// zero even when UTXOs exist on the account.
func TestGetAccountSkipBalanceZerosFields(t *testing.T) {
	t.Parallel()

	store := NewTestStore(t)
	walletID := newWallet(t, store, "wallet-get-balance-skip")
	scope := db.KeyScopeBIP0084

	queries := store.Queries()
	syncBlock := CreateBlockFixture(t, queries, 200)
	confirmedBlock := CreateBlockFixture(t, queries, 100)

	err := store.UpdateWallet(
		t.Context(), db.UpdateWalletParams{
			WalletID: walletID,
			SyncedTo: &syncBlock,
		},
	)
	require.NoError(t, err)

	createDerivedAccount(t, store, walletID, scope, "funded")

	addr := newDerivedAddress(t, store, walletID, scope, "funded", false)

	tx := newRegularTx(
		[]wire.OutPoint{randomOutPoint()},
		[]*wire.TxOut{{Value: 24000, PkScript: addr.ScriptPubKey}},
	)
	err = store.CreateTx(
		t.Context(), db.CreateTxParams{
			WalletID: walletID,
			Tx:       tx,
			Received: time.Unix(1710000200, 0),
			Block:    &confirmedBlock,
			Status:   db.TxStatusPublished,
			Credits:  map[uint32]address.Address{0: nil},
		},
	)
	require.NoError(t, err)

	byNameQuery := getAccountQueryByName(walletID, scope, "funded")
	byNameQuery.SkipBalance = true

	infoByName, err := store.GetAccount(t.Context(), byNameQuery)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(0), infoByName.ConfirmedBalance)
	require.Equal(t, btcutil.Amount(0), infoByName.UnconfirmedBalance)

	byNumberQuery := getAccountQueryByNumber(
		walletID, scope, accountNumberNotNil(t, infoByName.AccountNumber),
	)
	byNumberQuery.SkipBalance = true

	infoByNumber, err := store.GetAccount(t.Context(), byNumberQuery)
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(0), infoByNumber.ConfirmedBalance)
	require.Equal(t, btcutil.Amount(0), infoByNumber.UnconfirmedBalance)
}

// TestGetAccountNotFound verifies that GetAccount returns ErrAccountNotFound
// when querying a non-existent account.
func TestGetAccountNotFound(t *testing.T) {
	t.Parallel()

	scope := db.KeyScopeBIP0084

	t.Run("by name", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)
		walletID := newWallet(t, store, "wallet-get-account-not-found-name")
		createAllAccounts(t, store, walletID)

		query := getAccountQueryByName(walletID, scope, "non-existent")
		info, err := store.GetAccount(t.Context(), query)
		require.ErrorIs(t, err, db.ErrAccountNotFound)
		require.Nil(t, info)
	})

	t.Run("by number", func(t *testing.T) {
		t.Parallel()

		store := NewTestStore(t)
		walletID := newWallet(t, store, "wallet-get-account-not-found-number")
		createAllAccounts(t, store, walletID)

		query := getAccountQueryByNumber(walletID, scope, 99999)
		info, err := store.GetAccount(t.Context(), query)
		require.ErrorIs(t, err, db.ErrAccountNotFound)
		require.Nil(t, info)
	})
}
