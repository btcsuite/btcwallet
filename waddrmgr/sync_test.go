package waddrmgr

import (
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// TestSetSyncedToRollback checks that the in-memory sync tip only moves once
// the transaction that set it commits, so a rolled back write leaves SyncedTo
// matching the database.
func TestSetSyncedToRollback(t *testing.T) {
	t.Parallel()

	teardown, db, mgr := setupManager(t)
	defer teardown()

	before := mgr.SyncedTo()
	next := BlockStamp{
		Height:    before.Height + 1,
		Hash:      chainhash.Hash{1},
		Timestamp: time.Unix(1234, 0),
	}

	errAbort := errors.New("abort")
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		require.NoError(t, mgr.SetSyncedTo(ns, &next))

		return errAbort
	})
	require.ErrorIs(t, err, errAbort)

	// The write was rolled back, so neither memory nor the database
	// moved.
	require.Equal(t, before, mgr.SyncedTo())
	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		stored, err := fetchSyncedTo(ns)
		require.NoError(t, err)
		require.Equal(t, before.Height, stored.Height)

		return nil
	})
	require.NoError(t, err)

	// Once a transaction commits, memory follows.
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		return mgr.SetSyncedTo(ns, &next)
	})
	require.NoError(t, err)
	require.Equal(t, next, mgr.SyncedTo())
}
