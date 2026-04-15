package kvdb

import (
	"fmt"
	"testing"
	"time"

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
	store := NewStore(dbConn, txStore)

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

	store := NewStore(dbConn, nil)

	err := store.ReleaseOutput(t.Context(), db.ReleaseOutputParams{
		WalletID: 0,
		ID:       [32]byte{1},
		OutPoint: wire.OutPoint{Hash: [32]byte{1}, Index: 0},
	})
	require.Error(t, err)
	require.ErrorIs(t, err, errMissingTxmgrNamespace)
}
