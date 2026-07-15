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

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	walletstore "github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
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
