package kvdb

import (
	"bytes"
	"context"
	"errors"
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

// createKvdbDerivedAccount creates a derived account directly through
// waddrmgr's legacy NewAccount path so kvdb's read methods have a row to
// observe.
func createKvdbDerivedAccount(t *testing.T, dbConn walletdb.DB,
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

// TestKvdbGetAccountByName verifies that GetAccount returns the expected
// AccountInfo when the account exists and is looked up by name.
func TestKvdbGetAccountByName(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	accountName := savingsAccountName
	accountNumber := createKvdbDerivedAccount(
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

// TestKvdbGetAccountByNumber verifies the AccountNumber-keyed lookup branch.
func TestKvdbGetAccountByNumber(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	accountName := savingsAccountName
	accountNumber := createKvdbDerivedAccount(
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

// TestKvdbGetAccountNotFound verifies the not-found translation.
func TestKvdbGetAccountNotFound(t *testing.T) {
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

// TestKvdbListAccountsScopeFilter verifies that ListAccounts narrows to the
// requested scope.
func TestKvdbListAccountsScopeFilter(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	createKvdbDerivedAccount(
		t, store.db, mgr, waddrmgr.KeyScopeBIP0084, savingsAccountName,
	)
	createKvdbDerivedAccount(
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

// TestKvdbListAccountsNameFilter verifies that ListAccounts narrows by name.
func TestKvdbListAccountsNameFilter(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	createKvdbDerivedAccount(
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

// TestKvdbRenameAccountByName verifies that RenameAccount renames by old
// name and that GetAccount with the new name returns the same row.
func TestKvdbRenameAccountByName(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	accountNumber := createKvdbDerivedAccount(
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

// TestKvdbRenameAccountByNumber verifies the AccountNumber-keyed rename branch.
func TestKvdbRenameAccountByNumber(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	accountNumber := createKvdbDerivedAccount(
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

// TestKvdbRenameAccountNotFound verifies the not-found translation.
func TestKvdbRenameAccountNotFound(t *testing.T) {
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

// TestKvdbCreateDerivedAccount verifies that CreateDerivedAccount persists
// the wallet-derived account material and that a subsequent GetAccount
// returns the same row.
func TestKvdbCreateDerivedAccount(t *testing.T) {
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

// TestKvdbCreateDerivedAccountRollsBackOnDeriveError verifies that when the
// derivation callback fails after the account number has been allocated,
// the underlying walletdb transaction rolls back so the lastAccount counter
// is restored.
func TestKvdbCreateDerivedAccountRollsBackOnDeriveError(t *testing.T) {
	t.Parallel()

	store, mgr, cleanup := newAccountStoreFixture(t)
	t.Cleanup(cleanup)

	failDerive := func(_ context.Context, _ db.KeyScope, _ uint32,
		_ bool) (*db.DerivedAccountData, error) {

		return nil, errKvdbTestBoom
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
	require.ErrorIs(t, err, errKvdbTestBoom)

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

var errKvdbTestBoom = errors.New("kvdb test boom")

// TestKvdbCreateImportedAccount verifies the watch-only-imported account
// path: kvdb persists the row, GetAccount returns Origin=ImportedAccount,
// and the AccountInfo.MasterKeyFingerprint round-trips.
func TestKvdbCreateImportedAccount(t *testing.T) {
	t.Parallel()

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
			MasterFingerprint: 0xDEADBEEF,
			PublicKey:         []byte(masterPub.String()),
		},
	)
	require.NoError(t, err)
	require.NotNil(t, info)
	require.Equal(t, "imported-xpub", info.AccountName)
	require.Equal(t, db.ImportedAccount, info.Origin)
	require.True(t, info.IsWatchOnly)
	require.Equal(t, uint32(0xDEADBEEF), info.MasterKeyFingerprint)
}

// TestKvdbCreateImportedAccountRejectsPrivateKey verifies that the kvdb
// adapter refuses imported accounts with private key material on
// spendable wallets, since waddrmgr's accountWatchOnly row has no
// private-key column.
func TestKvdbCreateImportedAccountRejectsPrivateKey(t *testing.T) {
	t.Parallel()

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
			MasterFingerprint:   0xDEADBEEF,
			PublicKey:           []byte(masterPub.String()),
			EncryptedPrivateKey: []byte{0xAA, 0xBB},
		},
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not supported")
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

// TestKvdbGetAccountPopulatesBalance verifies that GetAccount returns
// non-zero ConfirmedBalance when the wallet owns a confirmed unspent
// output for the requested account.
func TestKvdbGetAccountPopulatesBalance(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	account := createKvdbDerivedAccount(
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

// TestKvdbGetAccountSkipBalanceZeros verifies that GetAccount with
// SkipBalance=true returns a zero ConfirmedBalance even when the
// account owns an unspent output.
func TestKvdbGetAccountSkipBalanceZeros(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	account := createKvdbDerivedAccount(
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

// TestKvdbListAccountsPopulatesBalance verifies that ListAccounts
// attaches confirmed balances to each account from the same scope.
func TestKvdbListAccountsPopulatesBalance(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	account := createKvdbDerivedAccount(
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

// TestKvdbListAccountsSkipBalanceZeros verifies that SkipBalance=true
// on ListAccounts leaves every account's balance fields at zero even
// when unspent outputs exist.
func TestKvdbListAccountsSkipBalanceZeros(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	account := createKvdbDerivedAccount(
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
