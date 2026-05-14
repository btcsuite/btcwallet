package kvdb

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
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
