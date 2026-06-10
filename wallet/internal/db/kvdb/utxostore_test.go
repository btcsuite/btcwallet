package kvdb

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

// TestReleaseOutputSuccess verifies that kvdb.Store.ReleaseOutput removes an
// existing output lease from the underlying wtxmgr store.
func TestReleaseOutputSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	lockID := wtxmgr.LockID{1}
	op := wire.OutPoint{Hash: [32]byte{1}, Index: 0}

	// Arrange: Create a lease so there is something to release.
	err := walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		// Create a mock transaction to satisfy the "known output" check in
		// wtxmgr.
		txMsg := &wire.MsgTx{
			Version: 1,
			TxOut: []*wire.TxOut{{
				Value:    1000,
				PkScript: []byte{0x00}, // OP_0
			}},
		}

		rec, err := wtxmgr.NewTxRecordFromMsgTx(txMsg, time.Now())
		if err != nil {
			return fmt.Errorf("create tx record: %w", err)
		}

		// Insert the transaction as mined.
		block := &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Height: 1},
			Time:  time.Now(),
		}

		err = txStore.InsertTx(ns, rec, block)
		if err != nil {
			return fmt.Errorf("insert tx: %w", err)
		}

		// Add the output as a credit so wtxmgr knows about it.
		err = txStore.AddCredit(ns, rec, block, 0, false)
		if err != nil {
			return fmt.Errorf("add credit: %w", err)
		}

		// Use the inserted transaction's hash for the outpoint.
		op.Hash = rec.Hash

		_, err = txStore.LockOutput(ns, lockID, op, time.Hour)

		return err
	})
	require.NoError(t, err)

	// Act: Release the lease through the kvdb store implementation.
	err = store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: 1,
		ID:       [32]byte(lockID),
		OutPoint: op,
	})
	require.NoError(t, err)

	// Assert: The lock set is now empty.
	err = walletdb.View(dbConn, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		require.NotNil(t, ns)

		locked, err := txStore.ListLockedOutputs(ns)
		require.NoError(t, err)
		require.Empty(t, locked)

		return nil
	})
	require.NoError(t, err)
}

// TestReleaseOutputMissingNamespace verifies a helpful error is returned when
// the `wtxmgr` namespace bucket is not present.
func TestReleaseOutputMissingNamespace(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	store := NewStore(dbConn, nil, nil)

	err := store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: 0,
		ID:       [32]byte{1},
		OutPoint: wire.OutPoint{Hash: [32]byte{1}, Index: 0},
	})
	require.Error(t, err)
	require.ErrorIs(t, err, walletdb.ErrBucketNotFound)
}

// TestGetUtxoSuccess verifies that kvdb.Store adapts one wallet-owned legacy
// credit into the db-native UTXO shape.
func TestGetUtxoSuccess(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	outPoint := creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(1500), 1,
		false,
	)

	utxo, err := store.GetUtxo(
		t.Context(), db.GetUtxoQuery{
			WalletID: 0,
			OutPoint: outPoint,
		},
	)
	require.NoError(t, err)
	require.Equal(t, outPoint, utxo.OutPoint)
	require.Equal(t, btcutil.Amount(1500), utxo.Amount)
	require.NotEmpty(t, utxo.PkScript)
	require.Equal(t, uint32(1), utxo.Height)
	require.Equal(t, waddrmgr.DefaultAccountName, utxo.AccountName)
	require.Equal(t, db.DerivedAccount, utxo.Origin)
	require.Equal(t, db.WitnessPubKey, utxo.AddrType)
	require.False(t, utxo.HasScript)
	require.Equal(t, db.KeyScopeBIP0084, utxo.KeyScope)
}

// TestGetUtxoNotFound verifies that kvdb.Store maps the legacy missing-UTXO
// error onto db.ErrUtxoNotFound.
func TestGetUtxoNotFound(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	_, err := store.GetUtxo(
		t.Context(), db.GetUtxoQuery{
			WalletID: 0,
			OutPoint: wire.OutPoint{Hash: [32]byte{9}, Index: 0},
		},
	)
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestGetUtxoRejectsSpentByUnminedTx verifies GetUtxo only returns outputs
// that remain current after unmined wallet spends are considered.
func TestGetUtxoRejectsSpentByUnminedTx(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	outPoint := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 1500, 1,
	)
	insertUnminedSpend(t, dbConn, txStore, outPoint)

	_, err := store.GetUtxo(
		t.Context(), db.GetUtxoQuery{
			WalletID: 0,
			OutPoint: outPoint,
		},
	)
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestCalcConfsGenesisHeight verifies the shared kvdb confirmation helper
// treats height zero as unconfirmed.
func TestCalcConfsGenesisHeight(t *testing.T) {
	t.Parallel()

	require.Equal(t, int32(0), calcConfs(0, 100))
}

// TestLeaseOutputSuccess verifies that kvdb.Store adapts one legacy lease write
// into the db-native leased-output view.
func TestLeaseOutputSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	outPoint := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 2500, 2,
	)

	lease, err := store.LeaseOutput(
		t.Context(), db.LeaseOutputParams{
			WalletID: 0,
			ID:       db.LockID{1},
			OutPoint: outPoint,
			Duration: time.Hour,
		},
	)
	require.NoError(t, err)
	require.Equal(t, outPoint, lease.OutPoint)
	require.Equal(t, db.LockID{1}, lease.LockID)
	require.True(t, lease.Expiration.After(time.Now().UTC()))
}

// TestLeaseOutputRejectsSpentByUnminedTx verifies leases cannot be acquired for
// outputs already spent by an unmined wallet transaction.
func TestLeaseOutputRejectsSpentByUnminedTx(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)
	outPoint := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 2500, 2,
	)
	insertUnminedSpend(t, dbConn, txStore, outPoint)

	_, err := store.LeaseOutput(
		t.Context(), db.LeaseOutputParams{
			WalletID: 0,
			ID:       db.LockID{1},
			OutPoint: outPoint,
			Duration: time.Hour,
		},
	)
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestListUTXOsIncludesLockedOutputs verifies kvdb returns current UTXOs even
// when they are actively leased.
func TestListUTXOsIncludesLockedOutputs(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	// Credit two wallet-owned outputs so they resolve to an account and
	// surface through the enriched listing path (unowned scripts are
	// dropped, matching the SQL backends).
	scope := waddrmgr.KeyScopeBIP0084
	lockedPoint := creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(3000),
		balanceTestTipHeight, false,
	)
	unlockedPoint := creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(4000),
		balanceTestTipHeight, false,
	)

	_, err := store.LeaseOutput(
		t.Context(), db.LeaseOutputParams{
			WalletID: 0,
			ID:       db.LockID{3},
			OutPoint: lockedPoint,
			Duration: time.Hour,
		},
	)
	require.NoError(t, err)

	utxos, err := store.ListUTXOs(
		t.Context(), db.ListUtxosQuery{
			WalletID: 0,
		},
	)
	require.NoError(t, err)
	require.Len(t, utxos, 2)
	require.ElementsMatch(t, []wire.OutPoint{
		lockedPoint, unlockedPoint,
	}, []wire.OutPoint{
		utxos[0].OutPoint, utxos[1].OutPoint,
	})

	// The leased output reports IsLocked; the other does not. This is the
	// original intent of the test: a leased UTXO still appears in the
	// listing, now distinguished by the enriched IsLocked flag.
	byOutPoint := make(map[wire.OutPoint]db.UtxoInfo, len(utxos))
	for _, u := range utxos {
		byOutPoint[u.OutPoint] = u
	}

	require.True(t, byOutPoint[lockedPoint].IsLocked)
	require.False(t, byOutPoint[unlockedPoint].IsLocked)
}

func TestUTXOEnrichmentFields(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	wantScope := db.KeyScopeBIP0084

	lockedPoint := creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(20000),
		balanceTestTipHeight, false,
	)
	unlockedPoint := creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(30000),
		balanceTestTipHeight, false,
	)

	// Lease only one output so IsLocked separates the two rows.
	_, err := store.LeaseOutput(
		t.Context(), db.LeaseOutputParams{
			WalletID: 0,
			OutPoint: lockedPoint,
			ID:       db.LockID{1},
			Duration: 30 * time.Minute,
		},
	)
	require.NoError(t, err)

	// ListUTXOs returns both rows with the derived-account enrichment.
	utxos, err := store.ListUTXOs(
		t.Context(), db.ListUtxosQuery{
			WalletID: 0,
		},
	)
	require.NoError(t, err)
	require.Len(t, utxos, 2)

	byOutPoint := make(map[wire.OutPoint]db.UtxoInfo, len(utxos))
	for _, u := range utxos {
		byOutPoint[u.OutPoint] = u
	}

	locked, ok := byOutPoint[lockedPoint]
	require.True(t, ok, "locked UTXO missing from ListUTXOs")
	require.Equal(t, waddrmgr.DefaultAccountName, locked.AccountName)
	require.Equal(t, db.DerivedAccount, locked.Origin)
	require.Equal(t, db.WitnessPubKey, locked.AddrType)
	require.False(t, locked.HasScript)
	require.True(t, locked.IsLocked)
	require.Equal(t, wantScope, locked.KeyScope)

	unlocked, ok := byOutPoint[unlockedPoint]
	require.True(t, ok, "unlocked UTXO missing from ListUTXOs")
	require.Equal(t, waddrmgr.DefaultAccountName, unlocked.AccountName)
	require.Equal(t, db.DerivedAccount, unlocked.Origin)
	require.Equal(t, db.WitnessPubKey, unlocked.AddrType)
	require.False(t, unlocked.HasScript)
	require.False(t, unlocked.IsLocked)
	require.Equal(t, wantScope, unlocked.KeyScope)

	// GetUtxo surfaces the same enriched view as ListUTXOs, including the
	// active-lease IsLocked flag and the owning account's KeyScope.
	got, err := store.GetUtxo(
		t.Context(), db.GetUtxoQuery{
			WalletID: 0,
			OutPoint: lockedPoint,
		},
	)
	require.NoError(t, err)
	require.Equal(t, waddrmgr.DefaultAccountName, got.AccountName)
	require.Equal(t, db.DerivedAccount, got.Origin)
	require.Equal(t, db.WitnessPubKey, got.AddrType)
	require.False(t, got.HasScript)
	require.True(t, got.IsLocked)
	require.Equal(t, wantScope, got.KeyScope)
}

// TestListUTXOsFiltersByConfirms verifies that kvdb.Store applies the
// confirmation filters before returning db-native UTXO rows. The
// account / scope / name filters are exercised end-to-end by the
// cross-backend itests under wallet/internal/db/itest, where real
// addrmgr fixtures populate the enrichment fields and the filter
// semantics can be asserted across pg, sqlite, and kvdb together.
func TestListUTXOsFiltersByConfirms(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(4000), 4,
		false,
	)
	creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(5000), 5,
		false,
	)
	creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(6000), 0,
		false,
	)

	minConfs := int32(1)

	utxos, err := store.ListUTXOs(
		t.Context(), db.ListUtxosQuery{
			WalletID: 0,
			MinConfs: &minConfs,
		},
	)
	require.NoError(t, err)
	require.Len(t, utxos, 2)
}

// insertKnownCredit inserts one test credit and returns its outpoint.
func insertKnownCredit(t *testing.T, dbConn walletdb.DB, txStore *wtxmgr.Store,
	pkScript []byte, value int64, height int32) wire.OutPoint {

	t.Helper()

	txMsg := &wire.MsgTx{Version: 1}
	txMsg.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: [32]byte{1}},
	})
	txMsg.AddTxOut(&wire.TxOut{Value: value, PkScript: pkScript})

	received := time.Now().UTC()
	rec, err := wtxmgr.NewTxRecordFromMsgTx(txMsg, received)
	require.NoError(t, err)

	var block *wtxmgr.BlockMeta
	if height >= 0 {
		block = &wtxmgr.BlockMeta{
			Block: wtxmgr.Block{Height: height},
			Time:  received,
		}
	}

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return walletdb.ErrBucketNotFound
		}

		err := txStore.InsertTx(ns, rec, block)
		if err != nil {
			return fmt.Errorf("insert tx: %w", err)
		}

		err = txStore.AddCredit(ns, rec, block, 0, false)
		if err != nil {
			return fmt.Errorf("add credit: %w", err)
		}

		return nil
	})
	require.NoError(t, err)

	return wire.OutPoint{Hash: rec.Hash, Index: 0}
}

// insertUnminedSpend records an unmined wallet transaction that spends the
// given outpoint.
func insertUnminedSpend(t *testing.T, dbConn walletdb.DB,
	txStore *wtxmgr.Store, outPoint wire.OutPoint) {

	t.Helper()

	spendTx := &wire.MsgTx{Version: 1}
	spendTx.AddTxIn(&wire.TxIn{PreviousOutPoint: outPoint})
	spendTx.AddTxOut(&wire.TxOut{Value: 1, PkScript: []byte{0x51}})
	spendRec, err := wtxmgr.NewTxRecordFromMsgTx(spendTx, time.Now())
	require.NoError(t, err)

	err = walletdb.Update(dbConn, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return walletdb.ErrBucketNotFound
		}

		return txStore.InsertTx(ns, spendRec, nil)
	})
	require.NoError(t, err)
}

// TestBalanceRejectsAccountWithoutScope verifies that Balance enforces
// the BalanceParams contract: an Account filter requires a Scope filter to
// avoid cross-scope account-number collisions.
func TestBalanceRejectsAccountWithoutScope(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	store := NewStore(dbConn, nil, nil)

	acct := uint32(0)
	_, err := store.Balance(t.Context(), db.BalanceParams{
		Account: &acct,
	})
	require.ErrorIs(t, err, db.ErrBalanceParamsAccountWithoutScope)
}

// TestBalanceEmptyWallet verifies that Balance returns zero on a wallet
// with no UTXOs and a nil tx store.
func TestBalanceEmptyWallet(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	store := NewStore(dbConn, nil, nil)

	result, err := store.Balance(t.Context(), db.BalanceParams{})
	require.NoError(t, err)
	require.Zero(t, result.Total)
}

// TestListUTXOsExcludesImportedFromNumericAccountFilter verifies that kvdb
// matches SQL semantics for the db.ListUtxosQuery.Account filter: a numeric
// Account filter never selects imported UTXOs (those carry the legacy
// ImportedAddrAccount pseudo-account number, which has no numeric counterpart
// on SQL backends), while derived accounts remain selectable by number.
// Imported UTXOs stay reachable through (Scope, AccountName).
func TestListUTXOsExcludesImportedFromNumericAccountFilter(t *testing.T) {
	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScopeBIP0084

	// Arrange: one derived-account (account 0) UTXO and one imported-key
	// UTXO under the legacy ImportedAddrAccount pseudo-account.
	derivedPoint := creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(1000),
		balanceTestTipHeight, false,
	)
	importedPoint := creditImportedKeyAtHeight(
		t, store.db, mgr, txStore, scope, btcutil.Amount(2000),
		balanceTestTipHeight,
	)

	// A numeric Account filter set to the imported pseudo-account number
	// must select nothing: imported rows are not numerically addressable,
	// matching SQL's NULL account_number.
	importedAcct := uint32(waddrmgr.ImportedAddrAccount)
	utxos, err := store.ListUTXOs(
		t.Context(), db.ListUtxosQuery{
			WalletID: 0,
			Scope:    &dbScope,
			Account:  &importedAcct,
		},
	)
	require.NoError(t, err)
	require.Empty(t, utxos)

	// A numeric Account filter for the derived account returns only the
	// derived UTXO; the imported UTXO is excluded.
	derivedAcct := uint32(0)
	utxos, err = store.ListUTXOs(
		t.Context(), db.ListUtxosQuery{
			WalletID: 0,
			Scope:    &dbScope,
			Account:  &derivedAcct,
		},
	)
	require.NoError(t, err)
	require.Len(t, utxos, 1)
	require.Equal(t, derivedPoint, utxos[0].OutPoint)
	require.Equal(t, db.DerivedAccount, utxos[0].Origin)

	// The imported UTXO remains selectable via (Scope, AccountName).
	importedName := waddrmgr.ImportedAddrAccountName
	utxos, err = store.ListUTXOs(
		t.Context(), db.ListUtxosQuery{
			WalletID:    0,
			Scope:       &dbScope,
			AccountName: &importedName,
		},
	)
	require.NoError(t, err)
	require.Len(t, utxos, 1)
	require.Equal(t, importedPoint, utxos[0].OutPoint)
	require.Equal(t, db.ImportedAccount, utxos[0].Origin)
}

// TestListUTXOsExcludesWatchOnlyAccountFromNumericAccountFilter verifies that
// kvdb excludes an imported xpub (watch-only) account from the numeric
// db.ListUtxosQuery.Account filter even though the account carries an ordinary
// kvdb account number. SQL backends store NULL account_number for imported
// accounts, so they are never selectable by number; kvdb must match that. The
// imported UTXO stays reachable through (Scope, AccountName).
func TestListUTXOsExcludesWatchOnlyAccountFromNumericAccountFilter(
	t *testing.T) {

	t.Parallel()

	store, mgr, txStore, cleanup := newCreditedFixture(t)
	t.Cleanup(cleanup)

	scope := waddrmgr.KeyScopeBIP0084
	dbScope := db.KeyScopeBIP0084

	// Arrange: a derived account-0 UTXO and an imported xpub-account UTXO
	// whose account carries an ordinary (non-pseudo) account number.
	importedName := "imported-xpub-list"
	importedAcct := createImportedXpubAccount(
		t, store, scope, importedName, 0xBE,
	)

	derivedPoint := creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, 0, btcutil.Amount(1000),
		balanceTestTipHeight, false,
	)
	importedPoint := creditAccountAddressAtHeight(
		t, store.db, mgr, txStore, scope, importedAcct,
		btcutil.Amount(2000), balanceTestTipHeight, false,
	)

	// A numeric Account filter on the imported account's ordinary number
	// must select nothing: imported rows are not numerically addressable.
	utxos, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: 0,
		Scope:    &dbScope,
		Account:  &importedAcct,
	})
	require.NoError(t, err)
	require.Empty(t, utxos)

	// The derived account is still selectable by number, with no leakage
	// from the imported account.
	derivedAcct := uint32(0)
	utxos, err = store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: 0,
		Scope:    &dbScope,
		Account:  &derivedAcct,
	})
	require.NoError(t, err)
	require.Len(t, utxos, 1)
	require.Equal(t, derivedPoint, utxos[0].OutPoint)
	require.Equal(t, db.DerivedAccount, utxos[0].Origin)

	// The imported account remains selectable through (Scope, AccountName).
	utxos, err = store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID:    0,
		Scope:       &dbScope,
		AccountName: &importedName,
	})
	require.NoError(t, err)
	require.Len(t, utxos, 1)
	require.Equal(t, importedPoint, utxos[0].OutPoint)
	require.Equal(t, db.ImportedAccount, utxos[0].Origin)
}

// createImportedXpubAccount creates an imported (watch-only) xpub account via
// CreateImportedAccount, which allocates an ordinary kvdb account number
// (NewAccountWatchingOnly) rather than the legacy ImportedAddrAccount
// pseudo-account. It returns that account number so callers can confirm a
// numeric Account filter still excludes the account despite the ordinary
// number. The xpub-derived seed byte keeps successive accounts distinct.
func createImportedXpubAccount(t *testing.T, store *Store,
	scope waddrmgr.KeyScope, name string, seedByte byte) uint32 {

	t.Helper()

	seed := bytes.Repeat([]byte{seedByte}, hdkeychain.RecommendedSeedLen)
	master, err := hdkeychain.NewMaster(seed, &chaincfg.SimNetParams)
	require.NoError(t, err)

	masterPub, err := master.Neuter()
	require.NoError(t, err)

	dbScope := db.KeyScope{Purpose: scope.Purpose, Coin: scope.Coin}

	_, err = store.CreateImportedAccount(t.Context(),
		db.CreateImportedAccountParams{
			Scope:             dbScope,
			Name:              name,
			MasterFingerprint: 0xDEADBEEF,
			PublicKey:         []byte(masterPub.String()),
		},
	)
	require.NoError(t, err)

	scopedMgr, err := store.addrStore.FetchScopedKeyManager(scope)
	require.NoError(t, err)

	var account uint32

	err = walletdb.View(store.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgr.NamespaceKey)

		var inner error

		account, inner = scopedMgr.LookupAccount(ns, name)

		return inner
	})
	require.NoError(t, err)

	// The imported account must receive an ordinary account number, not the
	// legacy pseudo-account: that is the exact case the numeric filter has to
	// guard against.
	require.NotEqual(t, uint32(waddrmgr.ImportedAddrAccount), account)

	return account
}
