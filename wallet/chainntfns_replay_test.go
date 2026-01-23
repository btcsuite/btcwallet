package wallet

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

func reorgSpend(t *testing.T, parent *wtxmgr.TxRecord,
	amount int64) *wtxmgr.TxRecord {

	t.Helper()

	msg := wire.NewMsgTx(2)
	msg.AddTxIn(wire.NewTxIn(&wire.OutPoint{Hash: parent.Hash}, nil, nil))
	msg.AddTxOut(wire.NewTxOut(amount, []byte{0x51}))
	rec, err := wtxmgr.NewTxRecordFromMsgTx(msg, time.Unix(1, 0))
	require.NoError(t, err)

	return rec
}

func reorgCoinbase(t *testing.T, tag byte) *wtxmgr.TxRecord {
	t.Helper()

	msg := wire.NewMsgTx(2)
	msg.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: ^uint32(0)},
		[]byte{tag}, nil))
	msg.AddTxOut(wire.NewTxOut(1000, []byte{0x51}))
	rec, err := wtxmgr.NewTxRecordFromMsgTx(msg, time.Unix(1, 0))
	require.NoError(t, err)

	return rec
}

// TestDisconnectCoinbaseSpends covers canonical coinbases, same-block debit
// order, unmined descendants, orphaned coinbase cleanup, labels and leases.
func TestDisconnectCoinbaseSpends(t *testing.T) {
	t.Parallel()

	w := testWalletWatchingOnly(t)
	t.Cleanup(func() {
		w.StopDeprecated()
		w.WaitForShutdown()
		require.NoError(t, w.db.Close())
	})

	w.chainClient = &reorgChainClient{
		mockChainClient: &mockChainClient{
			getBestBlockHeight: 200,
			getBlockHeader:     &wire.BlockHeader{Timestamp: time.Unix(1, 0)},
		},
		blockHashes: map[int64]chainhash.Hash{
			1: {9}, 2: {2}, 3: {9}, 102: {102},
		},
	}
	old := reorgRecord(t, 60)
	coinbaseMsg := reorgCoinbase(t, 61).MsgTx
	// Output 0 stays spent, output 1 becomes unspent when the mixed
	// descendant is removed, and output 2 stays unspent throughout.
	coinbaseMsg.AddTxOut(wire.NewTxOut(1000, []byte{0x51}))
	coinbaseMsg.AddTxOut(wire.NewTxOut(1000, []byte{0x51}))
	coinbase, err := wtxmgr.NewTxRecordFromMsgTx(&coinbaseMsg, time.Unix(1, 0))
	require.NoError(t, err)

	parent := reorgSpend(t, coinbase, 900)
	child := reorgSpend(t, parent, 800)
	pending := reorgSpend(t, child, 700)
	pendingChild := reorgSpend(t, pending, 600)
	orphanCoinbase := reorgCoinbase(t, 62)
	orphanPending := reorgSpend(t, orphanCoinbase, 900)
	orphanPendingChild := reorgSpend(t, orphanPending, 800)
	// A transaction with both valid and orphaned coinbase ancestry must
	// not be resurrected when the valid ancestry is restored.
	mixedMsg := wire.NewMsgTx(2)
	for _, rec := range []*wtxmgr.TxRecord{pendingChild, orphanPendingChild} {
		mixedMsg.AddTxIn(wire.NewTxIn(
			&wire.OutPoint{Hash: rec.Hash}, nil, nil,
		))
	}

	mixedMsg.AddTxIn(wire.NewTxIn(
		&wire.OutPoint{Hash: coinbase.Hash, Index: 1}, nil, nil,
	))
	mixedMsg.AddTxOut(wire.NewTxOut(2300, []byte{0x51}))
	mixed, err := wtxmgr.NewTxRecordFromMsgTx(mixedMsg, time.Unix(1, 0))
	require.NoError(t, err)

	oldBlock, coinbaseBlock := reorgBlock(1), reorgBlock(2)
	orphanBlock, spendBlock := reorgBlock(3), reorgBlock(102)
	leaseID := wtxmgr.LockID{1}
	// This branch uses duration leases. Lock an unspent canonical output
	// to verify replay retains its lock without confirmation-lease APIs.
	outpoint := wire.OutPoint{Hash: coinbase.Hash, Index: 1}

	updateErr := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		addReorgCredit(t, w, tx, old, &oldBlock, false)
		addReorgCredit(t, w, tx, coinbase, &coinbaseBlock, false)

		for _, index := range []uint32{1, 2} {
			require.NoError(t, w.txStore.AddCredit(
				ns, coinbase, &coinbaseBlock, index, false,
			))
		}

		_, err := w.txStore.LockOutput(ns, leaseID, outpoint, time.Hour)
		require.NoError(t, err)
		addReorgCredit(t, w, tx, parent, &spendBlock, true)
		addReorgCredit(t, w, tx, child, &spendBlock, false)
		addReorgCredit(t, w, tx, pending, nil, true)
		addReorgCredit(t, w, tx, pendingChild, nil, false)
		addReorgCredit(t, w, tx, orphanCoinbase, &orphanBlock, false)
		addReorgCredit(t, w, tx, orphanPending, nil, false)
		addReorgCredit(t, w, tx, orphanPendingChild, nil, false)
		addReorgCredit(t, w, tx, mixed, nil, false)
		require.NoError(t, w.txStore.PutTxLabel(ns, parent.Hash, "retained"))

		return w.connectBlock(tx, oldBlock)
	})
	require.NoError(t, updateErr)

	// Record the callback that forwards unspent events to public clients.
	var unspent []wire.OutPoint

	store, ok := w.txStore.(*wtxmgr.Store)
	require.True(t, ok)

	notify := store.NotifyUnspent
	store.NotifyUnspent = func(hash *chainhash.Hash, index uint32) {
		unspent = append(unspent, wire.OutPoint{Hash: *hash, Index: index})
		notify(hash, index)
	}

	// An error after successful replay must discard queued notifications
	// along with the database changes. Retry against the same history.
	abortErr := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		require.NoError(t, w.rollbackBlockHistory(ns, oldBlock.Height))
		require.Empty(t, unspent)

		return errReorgWrite
	})
	require.ErrorIs(t, abortErr, errReorgWrite)
	require.Empty(t, unspent)
	require.NoError(t, walletdb.Update(w.db,
		func(tx walletdb.ReadWriteTx) error {
			err := w.disconnectBlock(tx, oldBlock)

			require.Empty(t, unspent)

			return err
		}))
	// Only removing the mixed-ancestry spend changes spentness. Unchanged
	// spent and unspent credits must not produce replay notifications.
	require.ElementsMatch(t, []wire.OutPoint{
		{Hash: pendingChild.Hash}, {Hash: coinbase.Hash, Index: 1},
	}, unspent)
	require.NoError(t, walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		for _, test := range []struct {
			rec           *wtxmgr.TxRecord
			height        int32
			spent, change bool
			debit         int64
		}{
			{old, -1, false, false, 0},
			{parent, 102, true, true, 1000},
			{child, 102, true, false, 900},
			{pending, -1, true, true, 800},
			{pendingChild, -1, false, false, 700},
		} {
			detail, err := w.txStore.TxDetails(ns, &test.rec.Hash)
			require.NoError(t, err)
			require.NotNil(t, detail)
			require.Equal(t, test.height, detail.Block.Height)
			require.Equal(t, test.rec.Received, detail.Received)
			require.Len(t, detail.Credits, 1)
			require.Equal(t, test.spent, detail.Credits[0].Spent)
			require.Equal(t, test.change, detail.Credits[0].Change)

			if test.debit > 0 {
				require.Len(t, detail.Debits, 1)
				require.EqualValues(t, test.debit, detail.Debits[0].Amount)
			}
		}

		for _, rec := range []*wtxmgr.TxRecord{
			orphanCoinbase, orphanPending, orphanPendingChild, mixed,
		} {
			detail, err := w.txStore.TxDetails(ns, &rec.Hash)
			require.NoError(t, err)
			require.Nil(t, detail)
		}

		cbDetail, err := w.txStore.TxDetails(ns, &coinbase.Hash)
		require.NoError(t, err)
		require.NotNil(t, cbDetail)
		require.Equal(t, coinbaseBlock, cbDetail.Block)
		require.Equal(t, coinbase.Received, cbDetail.Received)
		require.Equal(t, []wtxmgr.CreditRecord{
			{Amount: 1000, Index: 0, Spent: true},
			{Amount: 1000, Index: 1, Locked: true},
			{Amount: 1000, Index: 2},
		}, cbDetail.Credits)

		label, err := w.txStore.FetchTxLabel(ns, parent.Hash)
		require.NoError(t, err)
		require.Equal(t, "retained", label)

		locks, err := w.txStore.ListLockedOutputs(ns)
		require.NoError(t, err)
		require.Len(t, locks, 1)
		require.Equal(t, leaseID, locks[0].LockID)
		require.Equal(t, outpoint, locks[0].Outpoint)

		confirmed, err := w.txStore.Balance(ns, 1, 200)
		require.NoError(t, err)
		require.EqualValues(t, 1000, confirmed)

		total, err := w.txStore.Balance(ns, 0, 200)
		require.NoError(t, err)
		require.EqualValues(t, 2600, total)

		return nil
	}))
}

// TestDisconnectConflictingSpends verifies replay removes orphaned double
// spends and their unmined children while rebuilding the canonical debit.
func TestDisconnectConflictingSpends(t *testing.T) {
	t.Parallel()

	w := testWalletWatchingOnly(t)
	t.Cleanup(func() {
		w.StopDeprecated()
		w.WaitForShutdown()
		require.NoError(t, w.db.Close())
	})

	w.chainClient = &reorgChainClient{
		mockChainClient: &mockChainClient{
			getBestBlockHeight: 2,
			getBlockHeader:     &wire.BlockHeader{Timestamp: time.Unix(1, 0)},
		},
		blockHashes: map[int64]chainhash.Hash{1: {9}, 2: {2}},
	}
	funding := reorgRecord(t, 70)
	orphan := reorgSpend(t, funding, 900)
	orphanChild := reorgSpend(t, orphan, 800)
	canonical := reorgSpend(t, funding, 700)
	fundingBlock := reorgBlock(0)
	oldBlock, newBlock := reorgBlock(1), reorgBlock(2)
	require.NoError(t, walletdb.Update(w.db,
		func(tx walletdb.ReadWriteTx) error {
			addReorgCredit(t, w, tx, funding, &fundingBlock, false)
			addReorgCredit(t, w, tx, orphan, &oldBlock, false)
			addReorgCredit(t, w, tx, orphanChild, nil, false)
			addReorgCredit(t, w, tx, canonical, &newBlock, true)

			return w.connectBlock(tx, oldBlock)
		}))
	require.NoError(t, walletdb.Update(w.db,
		func(tx walletdb.ReadWriteTx) error {
			return w.disconnectBlock(tx, oldBlock)
		}))
	require.NoError(t, walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		for _, rec := range []*wtxmgr.TxRecord{orphan, orphanChild} {
			detail, err := w.txStore.TxDetails(ns, &rec.Hash)
			require.NoError(t, err)
			require.Nil(t, detail)
		}

		detail, err := w.txStore.TxDetails(ns, &canonical.Hash)
		require.NoError(t, err)
		require.EqualValues(t, 2, detail.Block.Height)
		require.Len(t, detail.Debits, 1)
		require.EqualValues(t, 1000, detail.Debits[0].Amount)

		for _, minConf := range []int32{0, 1} {
			balance, err := w.txStore.Balance(ns, minConf, 2)
			require.NoError(t, err)
			require.EqualValues(t, 700, balance)
		}

		return nil
	}))
}

var errReorgWrite = errors.New("reorg replay write failed")

// failingReorgBucket rejects writes of one saved block hash. This forces an
// error during replay, after the original records have been rolled back.
type failingReorgBucket struct {
	walletdb.ReadWriteBucket

	failHash chainhash.Hash
}

//nolint:ireturn // Implements the walletdb bucket interface.
func (b failingReorgBucket) NestedReadWriteBucket(
	key []byte) walletdb.ReadWriteBucket {

	bucket := b.ReadWriteBucket.NestedReadWriteBucket(key)
	if bucket == nil {
		return nil
	}

	return failingReorgBucket{ReadWriteBucket: bucket, failHash: b.failHash}
}

func (b failingReorgBucket) Put(key, value []byte) error {
	// A block record starts with its hash. Rollback writes no block records.
	if len(key) == 4 && len(value) >= 32 &&
		bytes.Equal(value[:32], b.failHash[:]) {

		return fmt.Errorf("restore block: %w", errReorgWrite)
	}

	return b.ReadWriteBucket.Put(key, value)
}

func TestDisconnectReplayFailure(t *testing.T) {
	t.Parallel()

	w := testWalletWatchingOnly(t)
	t.Cleanup(func() {
		w.StopDeprecated()
		w.WaitForShutdown()
		require.NoError(t, w.db.Close())
	})

	w.chainClient = &reorgChainClient{
		mockChainClient: &mockChainClient{getBestBlockHeight: 3},
		blockHashes:     map[int64]chainhash.Hash{1: {9}, 2: {2}, 3: {3}},
	}
	records := []*wtxmgr.TxRecord{
		reorgRecord(t, 80), reorgRecord(t, 81), reorgRecord(t, 82),
	}
	heights := []int32{1, 2, 3}
	require.NoError(t, walletdb.Update(w.db,
		func(tx walletdb.ReadWriteTx) error {
			for i, rec := range records {
				block := reorgBlock(heights[i])
				addReorgCredit(t, w, tx, rec, &block, i%2 != 0)
			}

			return nil
		}))
	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := failingReorgBucket{
			ReadWriteBucket: tx.ReadWriteBucket(wtxmgrNamespaceKey),
			failHash:        chainhash.Hash{3},
		}

		return w.rollbackBlockHistory(ns, 1)
	})
	require.ErrorIs(t, err, errReorgWrite)
	assertReorgHistory(t, w, records, heights)
}

// TestDisconnectOrphanCoinbaseSpend checks that a normal transaction detached
// from an orphan block survives as unmined when its coinbase ancestor is valid.
func TestDisconnectOrphanCoinbaseSpend(t *testing.T) {
	t.Parallel()

	w := testWalletWatchingOnly(t)
	t.Cleanup(func() {
		w.StopDeprecated()
		w.WaitForShutdown()
		require.NoError(t, w.db.Close())
	})

	w.chainClient = &reorgChainClient{
		mockChainClient: &mockChainClient{
			getBestBlockHeight: 102,
			getBlockHeader:     &wire.BlockHeader{Timestamp: time.Unix(1, 0)},
		},
		blockHashes: map[int64]chainhash.Hash{1: {9}, 2: {2}, 102: {9}},
	}
	old := reorgRecord(t, 90)
	coinbase := reorgCoinbase(t, 91)
	spend := reorgSpend(t, coinbase, 900)
	child := reorgSpend(t, spend, 800)
	oldBlock, cbBlock := reorgBlock(1), reorgBlock(2)
	spendBlock := reorgBlock(102)
	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addReorgCredit(t, w, tx, old, &oldBlock, false)
		addReorgCredit(t, w, tx, coinbase, &cbBlock, false)
		addReorgCredit(t, w, tx, spend, &spendBlock, true)
		addReorgCredit(t, w, tx, child, nil, false)

		return w.connectBlock(tx, oldBlock)
	})
	require.NoError(t, err)
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		return w.disconnectBlock(tx, oldBlock)
	})
	require.NoError(t, err)
	require.NoError(t, walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		for _, rec := range []*wtxmgr.TxRecord{spend, child} {
			detail, err := w.txStore.TxDetails(ns, &rec.Hash)
			require.NoError(t, err)
			require.NotNil(t, detail)
			require.EqualValues(t, -1, detail.Block.Height)
			require.Len(t, detail.Credits, 1)
		}

		detail, err := w.txStore.TxDetails(ns, &coinbase.Hash)
		require.NoError(t, err)
		require.EqualValues(t, 2, detail.Block.Height)
		require.True(t, detail.Credits[0].Spent)

		balance, err := w.txStore.Balance(ns, 0, 102)
		require.NoError(t, err)
		require.EqualValues(t, 1800, balance)

		return nil
	}))
}
