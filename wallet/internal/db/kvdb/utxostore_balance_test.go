package kvdb

import (
	"bytes"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
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

const balanceTestTipHeight int32 = 100

// TestBalanceScopeFilter verifies the Scope filter narrows the sum to
// UTXOs belonging to that scope's accounts. Wallets with accounts under
// two scopes get a per-scope balance via BalanceParams.Scope.
func TestBalanceScopeFilter(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	creditNextAccountAddress(
		t, store.db, mgr, txStore,
		waddrmgr.KeyScopeBIP0084, 0, btcutil.Amount(100),
	)
	creditNextAccountAddress(
		t, store.db, mgr, txStore,
		waddrmgr.KeyScopeBIP0049Plus, 0, btcutil.Amount(200),
	)

	bip84 := db.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0084.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0084.Coin,
	}
	bip49 := db.KeyScope{
		Purpose: waddrmgr.KeyScopeBIP0049Plus.Purpose,
		Coin:    waddrmgr.KeyScopeBIP0049Plus.Coin,
	}

	res, err := store.Balance(t.Context(), db.BalanceParams{
		Scope: &bip84,
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(100), res.Total)

	res, err = store.Balance(t.Context(), db.BalanceParams{
		Scope: &bip49,
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(200), res.Total)

	res, err = store.Balance(t.Context(), db.BalanceParams{})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(300), res.Total)
}

// TestBalanceAccountFilter verifies the Account filter narrows the sum
// to UTXOs whose owning account number matches the supplied filter.
func TestBalanceAccountFilter(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	bip84 := db.KeyScope{
		Purpose: scope.Purpose, Coin: scope.Coin,
	}

	scopedMgr, err := mgr.FetchScopedKeyManager(scope)
	require.NoError(t, err)

	// Create a second derived account in the same scope.
	var acct1 uint32

	err = walletdb.Update(store.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)

		var inner error

		acct1, inner = scopedMgr.NewAccount(ns, "account-1")

		return inner
	})
	require.NoError(t, err)
	require.NotEqual(t, uint32(0), acct1)

	creditNextAccountAddress(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(100),
	)
	creditNextAccountAddress(
		t, store.db, mgr, txStore, scope, acct1, btcutil.Amount(200),
	)

	acct0 := uint32(0)
	res, err := store.Balance(t.Context(), db.BalanceParams{
		Scope:   &bip84,
		Account: &acct0,
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(100), res.Total)

	res, err = store.Balance(t.Context(), db.BalanceParams{
		Scope:   &bip84,
		Account: &acct1,
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(200), res.Total)
}

// TestBalanceReturnsLockedSubset verifies locked credits contribute to Total
// and are also reported through the Locked subset.
func TestBalanceReturnsLockedSubset(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(100),
		balanceTestTipHeight, false,
	)
	lockedOutPoint := creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(200),
		balanceTestTipHeight, false,
	)

	lockID := wtxmgr.LockID{1}
	err := walletdb.Update(store.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)

		_, err := txStore.LockOutput(ns, lockID, lockedOutPoint, time.Hour)

		return err
	})
	require.NoError(t, err)

	res, err := store.Balance(t.Context(), db.BalanceParams{})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(300), res.Total)
	require.Equal(t, btcutil.Amount(200), res.Locked)
}

// TestBalanceMinConfs verifies that Balance skips outputs below MinConfs.
func TestBalanceMinConfs(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(100),
		balanceTestTipHeight, false,
	)
	creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(200),
		balanceTestTipHeight-4, false,
	)

	minConfs := int32(2)
	res, err := store.Balance(t.Context(), db.BalanceParams{
		MinConfs: &minConfs,
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(200), res.Total)
}

// TestBalanceMaxConfs verifies that Balance skips outputs above MaxConfs.
func TestBalanceMaxConfs(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(100),
		balanceTestTipHeight, false,
	)
	creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(200),
		balanceTestTipHeight-4, false,
	)

	maxConfs := int32(2)
	res, err := store.Balance(t.Context(), db.BalanceParams{
		MaxConfs: &maxConfs,
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(100), res.Total)
}

// TestBalanceCoinbaseMaturity verifies that CoinbaseMaturity only gates
// coinbase outputs and leaves non-coinbase outputs unaffected.
func TestBalanceCoinbaseMaturity(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(100),
		balanceTestTipHeight, true,
	)
	creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(200),
		balanceTestTipHeight-9, true,
	)
	creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(300),
		balanceTestTipHeight, false,
	)

	maturity := int32(2)
	res, err := store.Balance(t.Context(), db.BalanceParams{
		CoinbaseMaturity: &maturity,
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(500), res.Total)
}

// TestBalanceSkipsUnownedAddress verifies that Balance ignores txstore credits
// whose script does not map back to a wallet-managed address.
func TestBalanceSkipsUnownedAddress(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(100),
		balanceTestTipHeight, false,
	)
	creditUnownedOutputAtHeight(
		t, store.db, mgr, txStore, btcutil.Amount(900),
		balanceTestTipHeight,
	)

	res, err := store.Balance(t.Context(), db.BalanceParams{})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(100), res.Total)
}

// TestBalanceNameFilter verifies that Balance can resolve a public account
// name to the backend's internal account number, including imported accounts.
func TestBalanceNameFilter(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScope{
		Purpose: scope.Purpose,
		Coin:    scope.Coin,
	}

	seed := bytes.Repeat([]byte{0xBE}, hdkeychain.RecommendedSeedLen)
	master, err := hdkeychain.NewMaster(seed, &chaincfg.SimNetParams)
	require.NoError(t, err)
	masterPub, err := master.Neuter()
	require.NoError(t, err)

	importedName := "imported-balance"
	_, err = store.CreateImportedAccount(t.Context(),
		db.CreateImportedAccountParams{
			Scope:             dbScope,
			Name:              importedName,
			MasterFingerprint: 0xDEADBEEF,
			PublicKey:         []byte(masterPub.String()),
		},
	)
	require.NoError(t, err)

	creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(100),
		balanceTestTipHeight, false,
	)
	creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, waddrmgr.MaxAccountNum,
		btcutil.Amount(300), balanceTestTipHeight, false,
	)

	res, err := store.Balance(t.Context(), db.BalanceParams{
		Scope: &dbScope,
		Name:  &importedName,
	})
	require.NoError(t, err)
	require.Equal(t, btcutil.Amount(300), res.Total)

	missing := "missing"
	res, err = store.Balance(t.Context(), db.BalanceParams{
		Scope: &dbScope,
		Name:  &missing,
	})
	require.NoError(t, err)
	require.Zero(t, res.Total)
}

// TestCalcConfs is a table-driven test of the calcConfs helper. Covers
// the documented edges: unconfirmed (height<=0), future-dated
// (height>tip), and the normal (tip - height + 1) calculation.
func TestCalcConfs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		outputHeight int32
		curHeight    int32
		want         int32
	}{
		{"unconfirmed-zero-height", 0, 100, 0},
		{"unconfirmed-negative-one", -1, 100, 0},
		{"future-dated", 110, 100, 0},
		{"single-confirmation", 10, 10, 1},
		{"normal-six-confirmations", 10, 15, 6},
		{"early-block-deep-chain", 1, 1000, 1000},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := calcConfs(tc.outputHeight, tc.curHeight)
			require.Equal(t, tc.want, got)
		})
	}
}

// creditAccountAddressAtHeight derives the next external address for account,
// inserts a credit paying to it at height, and returns the credited outpoint.
func creditAccountAddressAtHeight(t *testing.T, dbConn walletdb.DB,
	mgr *waddrmgr.Manager, txStore *wtxmgr.Store,
	scope waddrmgr.KeyScope, account uint32, amount btcutil.Amount,
	height int32, coinbase bool) wire.OutPoint {

	t.Helper()

	scopedMgr, err := mgr.FetchScopedKeyManager(scope)
	require.NoError(t, err)

	var pkScript []byte

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)

		addrs, err := scopedMgr.NextExternalAddresses(ns, account, 1)
		if err != nil {
			return err
		}

		pkScript, err = txscript.PayToAddrScript(addrs[0].Address())

		return err
	})
	require.NoError(t, err)

	return insertBalanceCredit(
		t, dbConn, mgr, txStore, pkScript, amount, height, coinbase,
	)
}

// creditUnownedOutputAtHeight inserts a txstore credit whose script belongs to
// an address that is not managed by the wallet.
func creditUnownedOutputAtHeight(t *testing.T, dbConn walletdb.DB,
	mgr *waddrmgr.Manager, txStore *wtxmgr.Store, amount btcutil.Amount,
	height int32) {

	t.Helper()

	addr, err := address.NewAddressPubKeyHash(
		bytes.Repeat([]byte{0x01}, 20), &chaincfg.SimNetParams,
	)
	require.NoError(t, err)

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	_ = insertBalanceCredit(
		t, dbConn, mgr, txStore, pkScript, amount, height, false,
	)
}

// insertBalanceCredit records a txstore credit and advances the wallet sync
// height to the balance-test tip. It returns the credited outpoint.
func insertBalanceCredit(t *testing.T, dbConn walletdb.DB,
	mgr *waddrmgr.Manager, txStore *wtxmgr.Store, pkScript []byte,
	amount btcutil.Amount, height int32, coinbase bool) wire.OutPoint {

	t.Helper()

	txHash := chainhash.Hash{
		byte(height), byte(amount), byte(amount >> 8), byte(len(pkScript)),
	}
	if coinbase {
		txHash[31] = 1
	}

	txMsg := &wire.MsgTx{Version: 1}
	if coinbase {
		txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
			Index: ^uint32(0),
		}})
	} else {
		txMsg.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
			Hash: txHash,
		}})
	}

	txMsg.AddTxOut(&wire.TxOut{
		Value:    int64(amount),
		PkScript: pkScript,
	})

	rec, err := wtxmgr.NewTxRecordFromMsgTx(txMsg, time.Now())
	require.NoError(t, err)

	blockHash := chainhash.Hash{byte(height), byte(amount >> 16)}
	block := &wtxmgr.BlockMeta{
		Block: wtxmgr.Block{Hash: blockHash, Height: height},
		Time:  time.Now(),
	}

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)

		err := txStore.InsertTx(ns, rec, block)
		if err != nil {
			return err
		}

		return txStore.AddCredit(ns, rec, block, 0, coinbase)
	})
	require.NoError(t, err)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgr.NamespaceKey)

		return mgr.SetSyncedTo(ns, &waddrmgr.BlockStamp{
			Hash:   blockHash,
			Height: balanceTestTipHeight,
		})
	})
	require.NoError(t, err)

	return wire.OutPoint{Hash: rec.Hash, Index: 0}
}
