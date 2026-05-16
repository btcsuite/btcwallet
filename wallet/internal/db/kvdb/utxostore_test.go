package kvdb

import (
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
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

// TestGetUtxoSuccess verifies that kvdb.Store adapts one legacy credit into the
// db-native UTXO shape.
func TestGetUtxoSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	pkScript := []byte{0x51}
	outPoint, received := insertKnownCredit(
		t, dbConn, txStore, pkScript, 1500, 1,
	)

	utxo, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: 0,
		OutPoint: outPoint,
	})
	require.NoError(t, err)
	require.Equal(t, outPoint, utxo.OutPoint)
	require.Equal(t, btcutil.Amount(1500), utxo.Amount)
	require.Equal(t, pkScript, utxo.PkScript)
	require.Equal(t, received.UTC().Unix(), utxo.Received.Unix())
	require.Equal(t, uint32(1), utxo.Height)
}

// TestGetUtxoNotFound verifies that kvdb.Store maps the legacy missing-UTXO
// error onto db.ErrUtxoNotFound.
func TestGetUtxoNotFound(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	_, err := store.GetUtxo(t.Context(), db.GetUtxoQuery{
		WalletID: 0,
		OutPoint: wire.OutPoint{Hash: [32]byte{9}, Index: 0},
	})
	require.ErrorIs(t, err, db.ErrUtxoNotFound)
}

// TestLeaseOutputSuccess verifies that kvdb.Store adapts one legacy lease write
// into the db-native leased-output view.
func TestLeaseOutputSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	outPoint, _ := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 2500, 2,
	)

	lease, err := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: 0,
		ID:       db.LockID{1},
		OutPoint: outPoint,
		Duration: time.Hour,
	})
	require.NoError(t, err)
	require.Equal(t, outPoint, lease.OutPoint)
	require.Equal(t, db.LockID{1}, lease.LockID)
	require.True(t, lease.Expiration.After(time.Now().UTC()))
}

// TestListLeasedOutputsSuccess verifies that kvdb.Store exposes the active
// legacy lease set through the db-native shape.
func TestListLeasedOutputsSuccess(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	txStore := newTxStore(t, dbConn)
	store := NewStore(dbConn, txStore, nil)

	outPoint, _ := insertKnownCredit(
		t, dbConn, txStore, []byte{0x51}, 3000, 3,
	)

	_, err := store.LeaseOutput(t.Context(), db.LeaseOutputParams{
		WalletID: 0,
		ID:       db.LockID{2},
		OutPoint: outPoint,
		Duration: time.Hour,
	})
	require.NoError(t, err)

	leases, err := store.ListLeasedOutputs(t.Context(), 0)
	require.NoError(t, err)
	require.Len(t, leases, 1)
	require.Equal(t, outPoint, leases[0].OutPoint)
	require.Equal(t, db.LockID{2}, leases[0].LockID)
}

// TestListUTXOsFiltersByAccountAndConfirms verifies that kvdb.Store applies the
// legacy address/account and confirmation filters before returning db-native
// UTXO rows.
func TestListUTXOsFiltersByAccountAndConfirms(t *testing.T) {
	t.Parallel()

	dbConn, cleanup := newTestDB(t)
	t.Cleanup(cleanup)

	newAddrmgrNamespace(t, dbConn)
	txStore := newTxStore(t, dbConn)

	defaultAddr, defaultScript := newTestAddressScript(t)
	testAddr, testScript := newTestAddressScript(t)

	addrStore := &testLegacyAddrStore{
		chainParams:   &chaincfg.RegressionNetParams,
		currentHeight: 5,
		accountByAddr: map[string]uint32{
			defaultAddr.String(): 0,
			testAddr.String():    1,
		},
	}

	store := NewStore(dbConn, txStore, addrStore)

	_, _ = insertKnownCredit(t, dbConn, txStore, defaultScript, 4000, 4)
	_, _ = insertKnownCredit(t, dbConn, txStore, testScript, 5000, 5)
	_, _ = insertKnownCredit(t, dbConn, txStore, testScript, 6000, -1)

	account := uint32(1)
	minConfs := int32(1)

	utxos, err := store.ListUTXOs(t.Context(), db.ListUtxosQuery{
		WalletID: 0,
		Account:  &account,
		MinConfs: &minConfs,
	})
	require.NoError(t, err)
	require.Len(t, utxos, 1)
	require.Equal(t, btcutil.Amount(5000), utxos[0].Amount)
	require.Equal(t, testScript, utxos[0].PkScript)
}

func insertKnownCredit(t *testing.T, dbConn walletdb.DB, txStore *wtxmgr.Store,
	pkScript []byte, value int64, height int32) (wire.OutPoint, time.Time) {

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
		require.NotNil(t, ns)

		err := txStore.InsertTx(ns, rec, block)
		require.NoError(t, err)

		err = txStore.AddCredit(ns, rec, block, 0, false)
		require.NoError(t, err)

		return nil
	})
	require.NoError(t, err)

	return wire.OutPoint{Hash: rec.Hash, Index: 0}, received
}
