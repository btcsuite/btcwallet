package kvdb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
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
		Name: &accountName,
	})
	require.NoError(t, err)
	require.NotNil(t, info)
	require.Equal(t, accountName, info.AccountName)
	require.Equal(t, accountNumber, info.AccountNumber)
	require.Equal(t, db.DerivedAccount, info.Origin)
	require.False(t, info.IsWatchOnly)

	// The plaintext account-level public key must be parseable.
	require.NotEmpty(t, info.PublicKey)
	parsed, err := hdkeychain.NewKeyFromString(string(info.PublicKey))
	require.NoError(t, err)
	require.False(t, parsed.IsPrivate())
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
	require.Equal(t, db.ImportedAccount, info.Origin)
	require.Equal(t, uint32(0), info.AccountNumber)
}

// TestListAccountsByNameIncludesImportedPseudoAccount verifies the
// name-filtered list path also returns the legacy imported address
// pseudo-account.
func TestListAccountsByNameIncludesImportedPseudoAccount(t *testing.T) {
	t.Parallel()

	store, _, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	name := waddrmgr.ImportedAddrAccountName
	infos, err := store.ListAccounts(t.Context(), db.ListAccountsQuery{
		Name: &name,
	})
	require.NoError(t, err)
	require.Len(t, infos, 1)
	require.Equal(t, waddrmgr.ImportedAddrAccountName, infos[0].AccountName)
	require.Equal(t, db.ImportedAccount, infos[0].Origin)
	require.Equal(t, uint32(0), infos[0].AccountNumber)
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
	require.Equal(t, accountNumber, info.AccountNumber)
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
	require.Equal(t, db.DerivedAccount, info.Origin)
	require.NotEmpty(t, info.PublicKey)
	require.Equal(t, uint32(0xC0DEC0DE), info.MasterKeyFingerprint)

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

	require.Equal(t, info1.AccountNumber+1, info2.AccountNumber,
		"account numbers should be contiguous after rollback")
}

var errTestBoom = errors.New("kvdb test boom")

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
		require.Equal(t, uint32(i), account.AccountNumber)
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
		if a.AccountNumber != account {
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
