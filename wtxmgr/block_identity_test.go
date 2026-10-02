package wtxmgr

import (
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/stretchr/testify/require"
)

// blockIdentityRecord creates a synthetic non-coinbase transaction.
func blockIdentityRecord(t *testing.T, n byte) *TxRecord {
	t.Helper()

	msg := wire.NewMsgTx(2)
	msg.AddTxIn(wire.NewTxIn(
		&wire.OutPoint{Hash: chainhash.Hash{n}}, nil, nil,
	))
	msg.AddTxOut(wire.NewTxOut(1000, []byte{0x51}))

	rec, err := NewTxRecordFromMsgTx(msg, time.Unix(1, 0))
	require.NoError(t, err)

	return rec
}

// TestInsertTxBlockIdentity verifies that a conflicting block cannot corrupt
// confirmed history or consume a previously unmined transaction and its credit.
func TestInsertTxBlockIdentity(t *testing.T) {
	t.Parallel()

	s, db, err := testStore(t)
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, db.Close()) })

	a, b := blockIdentityRecord(t, 1), blockIdentityRecord(t, 2)
	block := &BlockMeta{
		Block: Block{Height: 100, Hash: chainhash.Hash{3}},
		Time:  time.Unix(1, 0),
	}
	replacement := *block
	replacement.Hash = chainhash.Hash{4}

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(namespaceKey)
		require.NoError(t, s.InsertTx(ns, a, block))
		require.NoError(t, s.InsertTx(ns, b, nil))

		return s.AddCredit(ns, b, nil, 0, false)
	})
	require.NoError(t, err)

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return s.InsertTx(
			tx.ReadWriteBucket(namespaceKey), b, &replacement,
		)
	})

	var inputErr Error
	require.ErrorAs(t, err, &inputErr)
	require.Equal(t, ErrInput, inputErr.Code)

	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(namespaceKey)
		details, err := s.TxDetails(ns, &b.Hash)
		require.NoError(t, err)
		require.NotNil(t, details)
		require.EqualValues(t, -1, details.Block.Height)
		assertBalance(t, s, ns, false, 100, 1000)
		assertBalance(t, s, ns, true, 100, 0)

		var count int

		err = s.RangeTransactions(ns, 0, -1,
			func(txs []TxDetails) (bool, error) {
				count += len(txs)
				return false, nil
			})
		require.NoError(t, err)
		require.Equal(t, 2, count)

		// Same-block insertion and replay remain valid.
		require.NoError(t, s.InsertTx(ns, b, block))
		require.NoError(t, s.InsertTx(ns, b, block))
		assertBalance(t, s, ns, true, 100, 1000)

		return s.RangeTransactions(ns, 100, 100,
			func(txs []TxDetails) (bool, error) {
				require.Len(t, txs, 2)
				return false, nil
			})
	})
	require.NoError(t, err)
}

// TestStoreBlockHash verifies that recorded block identities survive reopening
// and that heights with no wallet transactions have no stored block identity.
func TestStoreBlockHash(t *testing.T) {
	t.Parallel()

	s, db, err := testStore(t)
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, db.Close()) })

	block := &BlockMeta{
		Block: Block{Height: 100, Hash: chainhash.Hash{3}},
		Time:  time.Unix(1, 0),
	}
	rec := blockIdentityRecord(t, 1)
	err = walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		return s.InsertTx(tx.ReadWriteBucket(namespaceKey), rec, block)
	})
	require.NoError(t, err)

	err = walletdb.View(db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(namespaceKey)
		s, err = Open(ns, &chaincfg.TestNet3Params)
		require.NoError(t, err)

		hash, err := s.BlockHash(ns, block.Height)
		require.NoError(t, err)
		require.Equal(t, &block.Hash, hash)

		hash, err = s.BlockHash(ns, block.Height-1)
		require.NoError(t, err)
		require.Nil(t, hash)

		return nil
	})
	require.NoError(t, err)
}
