// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package kvdb

import (
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
	"github.com/stretchr/testify/require"
)

var (
	blockHashKey      = []byte("block-hash")
	syncedToHeightKey = []byte("synced-to-height")
	rollbackHeightKey = []byte("rollback-height")
)

type testAddrStore struct{}

// BlockHash returns the fixture's block hash at the requested height.
func (testAddrStore) BlockHash(ns walletdb.ReadBucket,
	_ int32) (*chainhash.Hash, error) {

	value := ns.Get(blockHashKey)
	if value == nil {
		return nil, errors.New("block hash not found")
	}

	var hash chainhash.Hash
	copy(hash[:], value)

	return &hash, nil
}

// SetSyncedTo records the fixture's synced-to block stamp.
func (testAddrStore) SetSyncedTo(ns walletdb.ReadWriteBucket,
	block *waddrmgr.BlockStamp) error {

	return ns.Put(syncedToHeightKey, encodeHeight(block.Height))
}

type testTxStore struct {
	legacyTxStore
}

// Rollback rewinds mined transaction incidences at and above the given height.
func (testTxStore) Rollback(ns walletdb.ReadWriteBucket, height int32) error {
	return ns.Put(rollbackHeightKey, encodeHeight(height))
}

// replayingDB records use of the replay-capable DB.Update method.
type replayingDB struct {
	// DB delegates database operations other than Update.
	walletdb.DB

	updateCalls int
}

// Update records an unexpected call to the replay-capable transaction API.
func (d *replayingDB) Update(func(walletdb.ReadWriteTx) error,
	func()) error {

	d.updateCalls++
	return errors.New("replaying update called")
}

// commitErrorDB replaces transaction commit with a deterministic failure.
type commitErrorDB struct {
	// DB delegates database operations not involved in commit injection.
	walletdb.DB

	commitErr error
}

// BeginReadWriteTx wraps a real transaction with the configured commit error.
//
//nolint:ireturn // The wrapper must implement the walletdb transaction API.
func (d *commitErrorDB) BeginReadWriteTx() (walletdb.ReadWriteTx, error) {
	tx, err := d.DB.BeginReadWriteTx()
	if err != nil {
		return nil, err
	}

	return &commitErrorTx{
		ReadWriteTx: tx,
		commitErr:   d.commitErr,
	}, nil
}

// commitErrorTx fails commit after rolling back its underlying transaction.
type commitErrorTx struct {
	// ReadWriteTx delegates transaction operations other than Commit.
	walletdb.ReadWriteTx

	commitErr error
}

// Commit rolls back the fixture transaction and returns its configured error.
func (t *commitErrorTx) Commit() error {
	_ = t.ReadWriteTx.Rollback()
	return t.commitErr
}

// TestStoreUpdateSharesTransaction verifies that both manager adapters share
// one writable walletdb transaction.
func TestStoreUpdateSharesTransaction(t *testing.T) {
	t.Parallel()

	testErr := errors.New("rollback transaction")
	tests := []struct {
		name    string
		bodyErr error
	}{
		{
			name: "commit",
		},
		{
			name:    "rollback",
			bodyErr: testErr,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			db := testDB(t)
			store := newStore(db, testAddrStore{}, testTxStore{})
			shouldCommit := test.bodyErr == nil

			var resetCount int

			err := store.Update(
				context.Background(), func(tx walletstore.ReadWriteTx) error {
					err := tx.Addr().SetSyncedTo(&waddrmgr.BlockStamp{
						Height: 101,
					})
					if err != nil {
						return err
					}

					err = tx.Tx().Rollback(102)
					if err != nil {
						return err
					}

					return test.bodyErr
				}, func() {
					resetCount++
				},
			)
			if shouldCommit {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, test.bodyErr)
			}

			require.Equal(t, 1, resetCount)

			assertHeight := func(bucketKey, valueKey []byte,
				expected int32) {

				t.Helper()

				err := walletdb.View(db, func(tx walletdb.ReadTx) error {
					value := tx.ReadBucket(bucketKey).Get(valueKey)
					if !shouldCommit {
						require.Nil(t, value)

						return nil
					}

					require.Equal(
						t, expected, decodeHeight(value),
					)

					return nil
				})
				require.NoError(t, err)
			}

			assertHeight(addrmgrNamespaceKey, syncedToHeightKey, 101)
			assertHeight(txmgrNamespaceKey, rollbackHeightKey, 102)
		})
	}
}

// TestStoreView verifies that both manager adapters share one read-only
// walletdb transaction.
func TestStoreView(t *testing.T) {
	t.Parallel()

	db := testDB(t)
	wantHash := chainhash.Hash{1, 2, 3}
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return tx.ReadWriteBucket(addrmgrNamespaceKey).Put(
			blockHashKey, wantHash[:],
		)
	})
	require.NoError(t, err)

	store := newStore(db, testAddrStore{}, testTxStore{})

	var resetCount int

	err = store.View(
		context.Background(), func(tx walletstore.ReadTx) error {
			gotHash, err := tx.Addr().BlockHash(100)
			require.NoError(t, err)
			require.Equal(t, wantHash, *gotHash)

			return nil
		}, func() {
			resetCount++
		},
	)
	require.NoError(t, err)
	require.Equal(t, 1, resetCount)
}

// TestTransactionStoreCompatibility verifies that the KV adapter preserves new
// credit reporting and unmined debit reconstruction used by wallet APIs.
func TestTransactionStoreCompatibility(t *testing.T) {
	t.Parallel()

	database := testDB(t)
	err := walletdb.Update(database, func(tx walletdb.ReadWriteTx) error {
		return wtxmgr.Create(tx.ReadWriteBucket(txmgrNamespaceKey))
	})
	require.NoError(t, err)

	var txManager *wtxmgr.Store
	err = walletdb.View(database, func(tx walletdb.ReadTx) error {
		var err error
		txManager, err = wtxmgr.Open(
			tx.ReadBucket(txmgrNamespaceKey), &chaincfg.TestNet3Params,
		)

		return err
	})
	require.NoError(t, err)

	store := newStore(database, testAddrStore{}, txManager)
	fundingTx := wire.NewMsgTx(2)
	fundingTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash:  chainhash.Hash{1},
		Index: 1,
	}})
	fundingTx.AddTxOut(&wire.TxOut{Value: 50_000, PkScript: []byte{0x51}})
	funding, err := wtxmgr.NewTxRecordFromMsgTx(
		fundingTx, time.Unix(1_000, 0),
	)
	require.NoError(t, err)

	err = store.Update(t.Context(), func(tx walletstore.ReadWriteTx) error {
		err := tx.Tx().InsertTx(funding, nil)
		if err != nil {
			return err
		}

		isNew, err := tx.Tx().AddCredit(funding, nil, 0, false)
		require.NoError(t, err)
		require.True(t, isNew)

		isNew, err = tx.Tx().AddCredit(funding, nil, 0, false)
		require.NoError(t, err)
		require.False(t, isNew)

		return nil
	}, nil)
	require.NoError(t, err)

	spenderTx := wire.NewMsgTx(2)
	spenderTx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{
		Hash:  funding.Hash,
		Index: 0,
	}})
	spenderTx.AddTxOut(&wire.TxOut{Value: 49_000, PkScript: []byte{0x51}})
	spender, err := wtxmgr.NewTxRecordFromMsgTx(
		spenderTx, time.Unix(1_001, 0),
	)
	require.NoError(t, err)
	err = store.Update(t.Context(), func(tx walletstore.ReadWriteTx) error {
		return tx.Tx().InsertTx(spender, nil)
	}, nil)
	require.NoError(t, err)

	err = store.View(t.Context(), func(tx walletstore.ReadTx) error {
		details, err := tx.Tx().TxDetails(&spender.Hash)
		require.NoError(t, err)
		require.Equal(t, []wtxmgr.DebitRecord{{
			Amount: 50_000,
			Index:  0,
		}}, details.Debits)

		return nil
	}, nil)
	require.NoError(t, err)
}

// TestStoreAcceptsNilReset verifies optional reset callbacks are normalized for
// both replay-capable KV transaction methods.
func TestStoreAcceptsNilReset(t *testing.T) {
	t.Parallel()

	store := newStore(testDB(t), testAddrStore{}, testTxStore{})
	require.NoError(t, store.View(
		t.Context(), func(walletstore.ReadTx) error {
			return nil
		}, nil,
	))
	require.NoError(t, store.Update(
		t.Context(), func(walletstore.ReadWriteTx) error {
			return nil
		}, nil,
	))
}

// TestStoreRejectsCanceledContext verifies that a canceled context prevents a
// walletdb transaction from starting.
func TestStoreRejectsCanceledContext(t *testing.T) {
	t.Parallel()

	db := testDB(t)
	store := newStore(db, testAddrStore{}, testTxStore{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var (
		bodyCalled  bool
		resetCalled bool
	)

	err := store.Update(
		ctx, func(walletstore.ReadWriteTx) error {
			bodyCalled = true

			return nil
		}, func() {
			resetCalled = true
		},
	)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, bodyCalled)
	require.False(t, resetCalled)
}

// TestUpdateOnceBypassesReplay verifies that the KV adapter invokes body once
// without using a backend's replay-capable Update method.
func TestUpdateOnceBypassesReplay(t *testing.T) {
	t.Parallel()

	database := &replayingDB{DB: testDB(t)}
	store := newStore(database, testAddrStore{}, testTxStore{})
	var bodyCalls, resetCalls, hookCalls int

	err := store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			bodyCalls++
			tx.Addr().OnCommit(func() {
				hookCalls++
			})
			return nil
		}, func() {
			resetCalls++
		},
	)
	require.NoError(t, err)
	require.Zero(t, database.updateCalls)
	require.Equal(t, 1, bodyCalls)
	require.Equal(t, 1, resetCalls)
	require.Equal(t, 1, hookCalls)
}

// TestUpdateOnceReturnsRetryableBodyError verifies that a definitely
// uncommitted retryable body error is preserved without replay.
func TestUpdateOnceReturnsRetryableBodyError(t *testing.T) {
	t.Parallel()

	store := newStore(testDB(t), testAddrStore{}, testTxStore{})
	wantErr := &walletstore.RetryableTransactionError{
		Err: errors.New("retry transaction"),
	}
	var bodyCalls int
	err := store.UpdateOnce(
		t.Context(), func(walletstore.ReadWriteTx) error {
			bodyCalls++
			return wantErr
		}, nil,
	)

	var retryable *walletstore.RetryableTransactionError
	require.ErrorAs(t, err, &retryable)
	require.Same(t, wantErr, retryable)
	require.Equal(t, 1, bodyCalls)
}

// TestUpdateOnceReturnsAmbiguousCommit verifies that a KV commit failure is
// conservatively reported as ambiguous and retains repairable commit hooks.
func TestUpdateOnceReturnsAmbiguousCommit(t *testing.T) {
	t.Parallel()

	database := &commitErrorDB{
		DB:        testDB(t),
		commitErr: errors.New("commit failed"),
	}
	store := newStore(database, testAddrStore{}, testTxStore{})
	var bodyCalls, hookCalls int
	err := store.UpdateOnce(
		t.Context(), func(tx walletstore.ReadWriteTx) error {
			bodyCalls++
			tx.Addr().OnCommit(func() {
				hookCalls++
			})
			return nil
		}, nil,
	)

	var ambiguous *walletstore.AmbiguousCommitError
	require.ErrorAs(t, err, &ambiguous)
	var retryable *walletstore.RetryableTransactionError
	require.NotErrorAs(t, err, &retryable)
	require.Equal(t, 1, bodyCalls)
	require.Zero(t, hookCalls)
	ambiguous.ApplyCommitHooks()
	ambiguous.ApplyCommitHooks()
	require.Equal(t, 1, hookCalls)
}

// testDB creates a walletdb fixture with initialized manager namespaces.
//
//nolint:ireturn // The test helper returns the walletdb driver interface.
func testDB(t *testing.T) walletdb.DB {
	t.Helper()

	db, err := walletdb.Create(
		"bdb", filepath.Join(t.TempDir(), "wallet.db"), true,
		10*time.Second, false,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		_, err := tx.CreateTopLevelBucket(addrmgrNamespaceKey)
		if err != nil {
			return err
		}

		_, err = tx.CreateTopLevelBucket(txmgrNamespaceKey)
		if err != nil {
			return err
		}

		return nil
	})
	require.NoError(t, err)

	return db
}

// encodeHeight encodes a test height using the adapter fixture format.
func encodeHeight(height int32) []byte {
	var value [4]byte
	binary.BigEndian.PutUint32(value[:], uint32(height))

	return value[:]
}

// decodeHeight decodes a test height from the adapter fixture format.
func decodeHeight(value []byte) int32 {
	return int32(binary.BigEndian.Uint32(value))
}
