package kvdb

import (
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
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
